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
DEFAULT_TEST_IPS="203.0.113.10 203.0.113.11 203.0.113.12 198.51.100.23 198.51.100.24 192.0.2.55"
read -r -a TEST_IPS <<< "${TEST_IPS:-$DEFAULT_TEST_IPS}"
TEST_CIDR="${TEST_CIDR:-198.51.100.0/30}"
TEST_CHAIN="${TEST_CHAIN:-ALL}"
WHITELIST_IP="${WHITELIST_IP:-198.51.100.200}"
ANALYTICS_DAYS="${ANALYTICS_DAYS:-14}"
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

HTTP_CODE=""
HTTP_BODY=""
http_call() {
  local method="$1" path="$2" token="${3:-}" body="${4:-}"
  local args=(-s -w $'\n%{http_code}' -X "$method" "${API_ORIGIN}${path}")
  [ -n "$token" ] && args+=(-H "Authorization: Bearer ${token}")
  [ -n "$body" ] && args+=(-H "Content-Type: application/json" -d "$body")
  local resp
  resp=$(curl "${args[@]}")
  HTTP_CODE="${resp##*$'\n'}"
  HTTP_BODY="${resp%$'\n'*}"
}

check() {
  local desc="$1" expected="$2" actual="$3"
  if [ "$actual" = "$expected" ]; then
    printf "  ${GREEN}PASS${RESET}  %-50s ${DIM}astept %s, primit %s${RESET}\n" "$desc" "$expected" "$actual"
    pass=$((pass+1))
  else
    printf "  ${RED}FAIL${RESET}  %-50s ${BOLD}astept %s, primit %s${RESET}\n" "$desc" "$expected" "$actual"
    fail=$((fail+1))
  fi
}

expect() {
  local desc="$1" expected="$2"
  if [ "$HTTP_CODE" = "$expected" ]; then
    printf "  ${GREEN}PASS${RESET}  %-50s ${DIM}astept %s, primit %s${RESET}\n" "$desc" "$expected" "$HTTP_CODE"
    pass=$((pass+1))
  else
    printf "  ${RED}FAIL${RESET}  %-50s ${BOLD}astept %s, primit %s${RESET}\n" "$desc" "$expected" "$HTTP_CODE"
    fail=$((fail+1))
    local msg
    msg=$(jq -r '.message // .error // empty' <<<"$HTTP_BODY" 2>/dev/null)
    [ -z "$msg" ] && msg=$(printf '%s' "$HTTP_BODY" | head -c 400)
    [ -n "$msg" ] && printf "        ${DIM}-> %s${RESET}\n" "$msg"
  fi
}

is_num() { [[ "$1" =~ ^[0-9]+$ ]] && echo yes || echo no; }

echo "${BOLD}Adaptive Security Policy - test backend (end-to-end)${RESET}"
echo "  API:        ${API_ORIGIN}"
echo "  Keycloak:   ${KEYCLOAK_URL}/realms/${REALM}  (client ${CLIENT_ID})"
echo "  Test IPs:   ${TEST_IPS[*]}"
echo "  Test CIDR:  ${TEST_CIDR}   chain=${TEST_CHAIN}"
echo "  Whitelist:  ${WHITELIST_IP}"
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

primary_ip="${TEST_IPS[0]}"
block_body="{\"ipAddress\":\"${primary_ip}\",\"chain\":\"${TEST_CHAIN}\"}"
valid_policy_body='{"warningThreshold":3,"blockThreshold":5,"detectionWindowMinutes":15,"autoBlockEnabled":true}'
valid_whitelist_body="{\"ipAddress\":\"${WHITELIST_IP}\",\"note\":\"test-backend.sh\"}"

echo "${BOLD}1) Autentificare obligatorie (401 fara token valid)${RESET}"
check "GET /monitoring/suspicious-ips fara token"  401 "$(http_status GET /api/monitoring/suspicious-ips)"
check "GET /monitoring/suspicious-ips token invalid" 401 "$(http_status GET /api/monitoring/suspicious-ips 'abc.def.ghi')"
check "GET /monitoring/connections fara token"     401 "$(http_status GET /api/monitoring/connections)"
check "GET /events fara token"                     401 "$(http_status GET /api/events)"
check "GET /analytics/overview fara token"         401 "$(http_status GET /api/analytics/overview)"
check "GET /policy fara token"                     401 "$(http_status GET /api/policy)"
check "GET /whitelist fara token"                  401 "$(http_status GET /api/whitelist)"
check "POST /firewall/block fara token"            401 "$(http_status POST /api/firewall/block '' "$block_body")"
check "PUT /policy fara token"                      401 "$(http_status PUT /api/policy '' "$valid_policy_body")"
echo

echo "${BOLD}2) ADMIN - poate citi toate modulele (200)${RESET}"
check "GET /monitoring/connections (admin)"    200 "$(http_status GET /api/monitoring/connections "$ADMIN_TOKEN")"
check "GET /monitoring/firewall-rules (admin)" 200 "$(http_status GET /api/monitoring/firewall-rules "$ADMIN_TOKEN")"
check "GET /monitoring/suspicious-ips (admin)" 200 "$(http_status GET /api/monitoring/suspicious-ips "$ADMIN_TOKEN")"
check "GET /events (admin)"                    200 "$(http_status GET /api/events "$ADMIN_TOKEN")"
check "GET /events?page=0&size=5 (admin)"      200 "$(http_status GET '/api/events?page=0&size=5' "$ADMIN_TOKEN")"
check "GET /analytics/overview (admin)"        200 "$(http_status GET "/api/analytics/overview?days=${ANALYTICS_DAYS}" "$ADMIN_TOKEN")"
check "GET /policy (admin)"                    200 "$(http_status GET /api/policy "$ADMIN_TOKEN")"
check "GET /whitelist (admin)"                 200 "$(http_status GET /api/whitelist "$ADMIN_TOKEN")"
check "GET /test/ping (admin)"                 200 "$(http_status GET /api/test/ping "$ADMIN_TOKEN")"
echo

echo "${BOLD}3) DEFAULT - citeste partajat (200) dar NU scrie / nu vede audit (403)${RESET}"
if [ -n "$DEFAULT_TOKEN" ]; then
  check "GET /monitoring/suspicious-ips (default)" 200 "$(http_status GET /api/monitoring/suspicious-ips "$DEFAULT_TOKEN")"
  check "GET /monitoring/connections (default)"    200 "$(http_status GET /api/monitoring/connections "$DEFAULT_TOKEN")"
  check "GET /analytics/overview (default)"        200 "$(http_status GET "/api/analytics/overview?days=${ANALYTICS_DAYS}" "$DEFAULT_TOKEN")"
  check "GET /policy (default)"                    200 "$(http_status GET /api/policy "$DEFAULT_TOKEN")"
  check "GET /whitelist (default)"                 200 "$(http_status GET /api/whitelist "$DEFAULT_TOKEN")"
  check "GET /events (default) interzis"           403 "$(http_status GET /api/events "$DEFAULT_TOKEN")"
  check "POST /firewall/block (default) interzis"  403 "$(http_status POST /api/firewall/block "$DEFAULT_TOKEN" "$block_body")"
  check "POST /firewall/unblock (default) interzis" 403 "$(http_status POST /api/firewall/unblock "$DEFAULT_TOKEN" "$block_body")"
  check "PUT /policy (default) interzis"           403 "$(http_status PUT /api/policy "$DEFAULT_TOKEN" "$valid_policy_body")"
  check "POST /whitelist (default) interzis"       403 "$(http_status POST /api/whitelist "$DEFAULT_TOKEN" "$valid_whitelist_body")"
  check "DELETE /whitelist/999999 (default) interzis" 403 "$(http_status DELETE /api/whitelist/999999 "$DEFAULT_TOKEN")"
else
  echo "  ${YELLOW}SKIP - fara token DEFAULT (seteaza DEFAULT_USER/DEFAULT_PASS sau DEFAULT_TOKEN)${RESET}"
fi
echo

echo "${BOLD}4) ADMIN - blocheaza mai multe IP-uri + un CIDR (200)${RESET}"
for ip in "${TEST_IPS[@]}"; do
  body="{\"ipAddress\":\"${ip}\",\"chain\":\"${TEST_CHAIN}\"}"
  http_call POST /api/firewall/block "$ADMIN_TOKEN" "$body"
  expect "POST /firewall/block ${ip}" 200
done
cidr_body="{\"ipAddress\":\"${TEST_CIDR}\",\"chain\":\"${TEST_CHAIN}\"}"
http_call POST /api/firewall/block "$ADMIN_TOKEN" "$cidr_body"
expect "POST /firewall/block ${TEST_CIDR}" 200
echo

echo "${BOLD}5) Validare input (400 pe payload invalid, cu token ADMIN)${RESET}"
check "POST /firewall/block IP invalid"   400 "$(http_status POST /api/firewall/block "$ADMIN_TOKEN" '{"ipAddress":"999.1.1.1","chain":"ALL"}')"
check "POST /firewall/block chain invalid" 400 "$(http_status POST /api/firewall/block "$ADMIN_TOKEN" '{"ipAddress":"203.0.113.10","chain":"BOGUS"}')"
check "PUT /policy valoare sub minim"     400 "$(http_status PUT /api/policy "$ADMIN_TOKEN" '{"warningThreshold":0,"blockThreshold":5,"detectionWindowMinutes":15,"autoBlockEnabled":true}')"
check "POST /whitelist IP invalid"        400 "$(http_status POST /api/whitelist "$ADMIN_TOKEN" '{"ipAddress":"not-an-ip","note":"x"}')"
echo

echo "${BOLD}6) ADMIN - policy round-trip (modifica, verifica, restaureaza)${RESET}"
http_call GET /api/policy "$ADMIN_TOKEN"
wt=$(jq -r '.warningThreshold // empty' <<<"$HTTP_BODY")
bt=$(jq -r '.blockThreshold // empty' <<<"$HTTP_BODY")
dw=$(jq -r '.detectionWindowMinutes // empty' <<<"$HTTP_BODY")
ab=$(jq -r '.autoBlockEnabled' <<<"$HTTP_BODY")
if [[ "$wt" =~ ^[0-9]+$ && "$bt" =~ ^[0-9]+$ && "$dw" =~ ^[0-9]+$ && ( "$ab" = "true" || "$ab" = "false" ) ]]; then
  new_bt=$((bt+1))
  if [ "$ab" = "true" ]; then new_ab=false; else new_ab=true; fi
  put_body="{\"warningThreshold\":$wt,\"blockThreshold\":$new_bt,\"detectionWindowMinutes\":$dw,\"autoBlockEnabled\":$new_ab}"
  check "PUT /policy (modifica blockThreshold->${new_bt})" 200 "$(http_status PUT /api/policy "$ADMIN_TOKEN" "$put_body")"
  http_call GET /api/policy "$ADMIN_TOKEN"
  got_bt=$(jq -r '.blockThreshold // empty' <<<"$HTTP_BODY")
  got_ab=$(jq -r '.autoBlockEnabled' <<<"$HTTP_BODY")
  check "policy blockThreshold persistat" "$new_bt" "$got_bt"
  check "policy autoBlockEnabled comutat" "$new_ab" "$got_ab"
  restore_body="{\"warningThreshold\":$wt,\"blockThreshold\":$bt,\"detectionWindowMinutes\":$dw,\"autoBlockEnabled\":$ab}"
  check "PUT /policy (restaureaza)" 200 "$(http_status PUT /api/policy "$ADMIN_TOKEN" "$restore_body")"
else
  echo "  ${YELLOW}SKIP - nu am putut citi policy curent${RESET}"
fi
echo

echo "${BOLD}7) ADMIN - whitelist round-trip (adauga, listeaza, sterge)${RESET}"
http_call GET /api/whitelist "$ADMIN_TOKEN"
existing_id=$(jq -r --arg ip "$WHITELIST_IP" '.[] | select(.ipAddress==$ip) | .id' <<<"$HTTP_BODY" 2>/dev/null | head -n1)
[[ "$existing_id" =~ ^[0-9]+$ ]] && http_status DELETE "/api/whitelist/${existing_id}" "$ADMIN_TOKEN" >/dev/null
http_call POST /api/whitelist "$ADMIN_TOKEN" "$valid_whitelist_body"
check "POST /whitelist (adauga ${WHITELIST_IP})" 201 "$HTTP_CODE"
new_id=$(jq -r '.id // empty' <<<"$HTTP_BODY")
http_call GET /api/whitelist "$ADMIN_TOKEN"
present=$(jq -r --arg ip "$WHITELIST_IP" 'any(.[]; .ipAddress==$ip)' <<<"$HTTP_BODY" 2>/dev/null)
check "whitelist contine ${WHITELIST_IP}" true "$present"
if [[ "$new_id" =~ ^[0-9]+$ ]]; then
  check "DELETE /whitelist/${new_id}" 204 "$(http_status DELETE "/api/whitelist/${new_id}" "$ADMIN_TOKEN")"
  http_call GET /api/whitelist "$ADMIN_TOKEN"
  gone=$(jq -r --arg ip "$WHITELIST_IP" 'any(.[]; .ipAddress==$ip) | not' <<<"$HTTP_BODY" 2>/dev/null)
  check "whitelist ${WHITELIST_IP} sters" true "$gone"
else
  echo "  ${YELLOW}SKIP - fara id de la POST /whitelist${RESET}"
fi
echo

echo "${BOLD}8) Analytics - structura raspunsului${RESET}"
http_call GET "/api/analytics/overview?days=${ANALYTICS_DAYS}" "$ADMIN_TOKEN"
uniq=$(jq -r '.summary.uniqueIps // empty' <<<"$HTTP_BODY")
auto=$(jq -r '.summary.autoActions // empty' <<<"$HTTP_BODY")
manual=$(jq -r '.summary.manualActions // empty' <<<"$HTTP_BODY")
tl_type=$(jq -r 'if (.timeline|type)=="array" then "array" else "no" end' <<<"$HTTP_BODY" 2>/dev/null)
ab_type=$(jq -r 'if (.actionBreakdown|type)=="array" then "array" else "no" end' <<<"$HTTP_BODY" 2>/dev/null)
top_type=$(jq -r 'if (.topIps|type)=="array" then "array" else "no" end' <<<"$HTTP_BODY" 2>/dev/null)
check "summary.uniqueIps numeric"    yes   "$(is_num "$uniq")"
check "summary.autoActions numeric"  yes   "$(is_num "$auto")"
check "summary.manualActions numeric" yes  "$(is_num "$manual")"
check "timeline este array"          array "$tl_type"
check "actionBreakdown este array"   array "$ab_type"
check "topIps este array"            array "$top_type"
echo

echo "${BOLD}9) ADMIN - debloca IP-urile de test (200, curatare)${RESET}"
for ip in "${TEST_IPS[@]}"; do
  body="{\"ipAddress\":\"${ip}\",\"chain\":\"${TEST_CHAIN}\"}"
  http_call POST /api/firewall/unblock "$ADMIN_TOKEN" "$body"
  expect "POST /firewall/unblock ${ip}" 200
done
http_call POST /api/firewall/unblock "$ADMIN_TOKEN" "$cidr_body"
expect "POST /firewall/unblock ${TEST_CIDR}" 200
echo

if [ "$WITH_DB" = "1" ]; then
  echo "${BOLD}10) Stare in baza de date (psql)${RESET}"
  if command -v psql >/dev/null 2>&1; then
    here="$(cd "$(dirname "$0")" && pwd)"
    [ -f "${here}/.env" ] && { set -a; . "${here}/.env"; set +a; }
    export PGPASSWORD="${DB_PASSWORD:-}"
    PSQL=(psql -h 127.0.0.1 -U "${DB_USER:-asp_user}" -d "${DB_NAME:-asp}" -P pager=off)
    ips_sql=$(printf "'%s'," "${TEST_IPS[@]}"); ips_sql="${ips_sql%,}"
    "${PSQL[@]}" -c "SELECT ip_address, current_status, failed_attempts FROM tracked_ip WHERE ip_address IN (${ips_sql}) ORDER BY ip_address;"
    "${PSQL[@]}" -c "SELECT current_status, count(*) FROM tracked_ip GROUP BY current_status ORDER BY current_status;"
    "${PSQL[@]}" -c "SELECT status, source, count(*) FROM block_record GROUP BY status, source ORDER BY status, source;"
    "${PSQL[@]}" -c "SELECT action, count(*) FROM audit_log GROUP BY action ORDER BY count(*) DESC;"
    "${PSQL[@]}" -c "SELECT action, user_type, username, details, created_at FROM audit_log ORDER BY created_at DESC LIMIT 8;"
  else
    echo "  ${YELLOW}SKIP - psql indisponibil${RESET}"
  fi
  echo
fi

echo "${BOLD}Rezumat:${RESET} ${GREEN}${pass} PASS${RESET}, ${RED}${fail} FAIL${RESET}  ${DIM}(${#TEST_IPS[@]} IP-uri + 1 CIDR exersate)${RESET}"
[ "$fail" -eq 0 ]
