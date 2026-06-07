#!/usr/bin/env bash
set -uo pipefail

API_ORIGIN="${API_ORIGIN:-http://localhost:8090}"
KEYCLOAK_URL="${KEYCLOAK_URL:-http://localhost:8080}"
REALM="${REALM:-adaptive-security-policy}"
CLIENT_ID="${CLIENT_ID:-asp-ui}"
ADMIN_USER="${ADMIN_USER:-admin}"
ADMIN_PASS="${ADMIN_PASS:-}"
DEFAULT_USER="${DEFAULT_USER:-}"
DEFAULT_PASS="${DEFAULT_PASS:-}"
ADMIN_TOKEN="${ADMIN_TOKEN:-}"
DEFAULT_TOKEN="${DEFAULT_TOKEN:-}"
TEST_IP="${TEST_IP:-203.0.113.77}"
TEST_CHAIN="${TEST_CHAIN:-ALL}"
WITH_DB="${WITH_DB:-0}"

if [ -t 1 ]; then
  GREEN=$'\033[32m'; RED=$'\033[31m'; YELLOW=$'\033[33m'; BOLD=$'\033[1m'; DIM=$'\033[2m'; RESET=$'\033[0m'
else
  GREEN=""; RED=""; YELLOW=""; BOLD=""; DIM=""; RESET=""
fi

pass=0
fail=0

need() {
  command -v "$1" >/dev/null 2>&1 || { echo "${RED}Lipseste '$1'. Instaleaza-l si reia.${RESET}" >&2; exit 1; }
}
need curl
need jq

get_token() {
  local resp tok err
  resp=$(curl -s -X POST "${KEYCLOAK_URL}/realms/${REALM}/protocol/openid-connect/token" \
    -d "client_id=${CLIENT_ID}" \
    -d "grant_type=password" \
    -d "username=$1" \
    -d "password=$2")
  tok=$(printf '%s' "$resp" | jq -r '.access_token // empty')
  if [ -z "$tok" ]; then
    err=$(printf '%s' "$resp" | jq -r '.error_description // .error // "raspuns necunoscut"')
    echo "  ${YELLOW}token pentru '$1' a esuat: ${err}${RESET}" >&2
  fi
  printf '%s' "$tok"
}

decode_payload() {
  local p
  p=$(printf '%s' "$1" | cut -d. -f2 | tr '_-' '/+')
  while [ $(( ${#p} % 4 )) -ne 0 ]; do p="${p}="; done
  printf '%s' "$p" | base64 -d 2>/dev/null
}

token_roles() {
  decode_payload "$1" | jq -rc '.realm_access.roles // []'
}

http_status() {
  local method="$1" path="$2" token="${3:-}" body="${4:-}"
  local args=(-s -o /dev/null -w "%{http_code}" -X "$method" "${API_ORIGIN}${path}")
  [ -n "$token" ] && args+=(-H "Authorization: Bearer ${token}")
  [ -n "$body" ] && args+=(-H "Content-Type: application/json" -d "$body")
  curl "${args[@]}"
}

check() {
  local desc="$1" expected="$2" actual="$3"
  if [ "$actual" = "$expected" ]; then
    printf "  ${GREEN}PASS${RESET}  %-46s ${DIM}astept %s, primit %s${RESET}\n" "$desc" "$expected" "$actual"
    pass=$((pass+1))
  else
    printf "  ${RED}FAIL${RESET}  %-46s ${BOLD}astept %s, primit %s${RESET}\n" "$desc" "$expected" "$actual"
    fail=$((fail+1))
  fi
}

echo "${BOLD}Adaptive Security Policy - test backend${RESET}"
echo "  API:       ${API_ORIGIN}"
echo "  Keycloak:  ${KEYCLOAK_URL}/realms/${REALM}  (client ${CLIENT_ID})"
echo "  Test IP:   ${TEST_IP}  chain=${TEST_CHAIN}"
echo

if [ -z "$ADMIN_TOKEN" ]; then
  [ -z "$ADMIN_PASS" ] && { echo "${RED}Seteaza ADMIN_PASS (sau ADMIN_TOKEN).${RESET}" >&2; exit 1; }
  echo "Obtin token ADMIN pentru '${ADMIN_USER}'..."
  ADMIN_TOKEN="$(get_token "$ADMIN_USER" "$ADMIN_PASS")"
fi
if [ -z "$ADMIN_TOKEN" ]; then
  echo "${RED}Nu am putut obtine token ADMIN.${RESET}" >&2
  echo "${YELLOW}Verifica in Keycloak: clientul '${CLIENT_ID}' are 'Direct access grants' activat?" >&2
  echo "Alternativ, copiaza tokenul din browser:  ADMIN_TOKEN=... DEFAULT_TOKEN=... $0${RESET}" >&2
  exit 1
fi

echo "  roluri in token ADMIN:   $(token_roles "$ADMIN_TOKEN")"

if [ -z "$DEFAULT_TOKEN" ] && [ -n "$DEFAULT_PASS" ]; then
  echo "Obtin token DEFAULT pentru '${DEFAULT_USER}'..."
  DEFAULT_TOKEN="$(get_token "$DEFAULT_USER" "$DEFAULT_PASS")"
fi
[ -n "$DEFAULT_TOKEN" ] && echo "  roluri in token DEFAULT: $(token_roles "$DEFAULT_TOKEN")"
echo

block_body="{\"ipAddress\":\"${TEST_IP}\",\"chain\":\"${TEST_CHAIN}\"}"

echo "${BOLD}1) Autentificare obligatorie (401 fara token valid)${RESET}"
check "GET /suspicious-ips fara token"    401 "$(http_status GET /api/monitoring/suspicious-ips)"
check "GET /suspicious-ips token invalid" 401 "$(http_status GET /api/monitoring/suspicious-ips 'abc.def.ghi')"
check "GET /api/events fara token"        401 "$(http_status GET /api/events)"
echo

echo "${BOLD}2) ADMIN - poate citi (200)${RESET}"
check "GET /suspicious-ips (admin)" 200 "$(http_status GET /api/monitoring/suspicious-ips "$ADMIN_TOKEN")"
check "GET /api/events (admin)"     200 "$(http_status GET /api/events "$ADMIN_TOKEN")"
echo

echo "${BOLD}3) ADMIN - poate bloca (200)${RESET}"
check "POST /firewall/block (admin)" 200 "$(http_status POST /api/firewall/block "$ADMIN_TOKEN" "$block_body")"
echo

echo "${BOLD}4) DEFAULT - citeste (200) dar NU poate bloca/debloca (403)${RESET}"
if [ -n "$DEFAULT_TOKEN" ]; then
  check "GET /suspicious-ips (default)"     200 "$(http_status GET /api/monitoring/suspicious-ips "$DEFAULT_TOKEN")"
  check "GET /api/events (default)"         200 "$(http_status GET /api/events "$DEFAULT_TOKEN")"
  check "POST /firewall/block (default)"    403 "$(http_status POST /api/firewall/block "$DEFAULT_TOKEN" "$block_body")"
  check "POST /firewall/unblock (default)"  403 "$(http_status POST /api/firewall/unblock "$DEFAULT_TOKEN" "$block_body")"
else
  echo "  ${YELLOW}SKIP - fara token DEFAULT (seteaza DEFAULT_USER/DEFAULT_PASS sau DEFAULT_TOKEN)${RESET}"
fi
echo

echo "${BOLD}5) ADMIN - poate debloca (200, curata regula de test)${RESET}"
check "POST /firewall/unblock (admin)" 200 "$(http_status POST /api/firewall/unblock "$ADMIN_TOKEN" "$block_body")"
echo

if [ "$WITH_DB" = "1" ]; then
  echo "${BOLD}6) Stare in baza de date (psql)${RESET}"
  if command -v psql >/dev/null 2>&1; then
    here="$(cd "$(dirname "$0")" && pwd)"
    [ -f "${here}/.env" ] && { set -a; . "${here}/.env"; set +a; }
    export PGPASSWORD="${DB_PASSWORD:-}"
    PSQL=(psql -h 127.0.0.1 -U "${DB_USER:-asp_user}" -d "${DB_NAME:-asp}" -P pager=off)
    "${PSQL[@]}" -c "SELECT ip_address, current_status, failed_attempts, attempt_baseline FROM tracked_ip WHERE ip_address='${TEST_IP}';"
    "${PSQL[@]}" -c "SELECT br.status, br.source, br.chain, br.blocked_at, br.unblocked_at FROM block_record br JOIN tracked_ip t ON t.id=br.ip_id WHERE t.ip_address='${TEST_IP}' ORDER BY br.blocked_at DESC;"
    "${PSQL[@]}" -c "SELECT action, user_type, username, details, created_at FROM audit_log ORDER BY created_at DESC LIMIT 6;"
  else
    echo "  ${YELLOW}SKIP - psql indisponibil${RESET}"
  fi
  echo
fi

echo "${BOLD}Rezumat:${RESET} ${GREEN}${pass} PASS${RESET}, ${RED}${fail} FAIL${RESET}"
[ "$fail" -eq 0 ]
