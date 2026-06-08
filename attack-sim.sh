#!/usr/bin/env bash
set -uo pipefail

TARGET="${TARGET:-}"
SSH_PORT="${SSH_PORT:-22}"
ATTACK_USER="${ATTACK_USER:-asp_attacker}"
WARN_AT="${WARN_AT:-10}"
BLOCK_AT="${BLOCK_AT:-20}"
ATTACK_DELAY="${ATTACK_DELAY:-0.5}"
UI_PAUSE="${UI_PAUSE:-20}"
read -r -a KNOCK_SEQ <<< "${KNOCK_SEQUENCE:-8936 6027 9417}"
KNOCK_PROTECTED_PORT="${KNOCK_PROTECTED_PORT:-22}"
DO_KNOCK="${DO_KNOCK:-1}"
DO_BRUTE="${DO_BRUTE:-1}"

if [ -t 1 ]; then
  GREEN=$'\033[32m'; RED=$'\033[31m'; YELLOW=$'\033[33m'; BOLD=$'\033[1m'; DIM=$'\033[2m'; RESET=$'\033[0m'
else
  GREEN=""; RED=""; YELLOW=""; BOLD=""; DIM=""; RESET=""
fi

if [ -z "$TARGET" ]; then
  echo "${RED}Seteaza TARGET=<IP-ul VM-ului aplicatie>, ex: TARGET=192.168.1.50 ./attack-sim.sh${RESET}" >&2
  exit 1
fi

command -v ssh >/dev/null 2>&1 || { echo "${RED}Lipseste 'ssh'.${RESET}" >&2; exit 1; }
if [ "$DO_BRUTE" = "1" ] && ! command -v sshpass >/dev/null 2>&1; then
  echo "${RED}Lipseste 'sshpass'. Ruleaza: sudo apt install -y sshpass${RESET}" >&2
  exit 1
fi

echo "${BOLD}Simulator atac -> ${TARGET}${RESET}"
echo "  SSH port:      ${SSH_PORT}   user fals: ${ATTACK_USER}"
echo "  Praguri:       warning la ${WARN_AT}, block la ${BLOCK_AT}"
echo "  Knock:         ${KNOCK_SEQ[*]} -> deschide ${KNOCK_PROTECTED_PORT}"
echo

ssh_fail() {
  sshpass -p 'wrong-asp-pass' ssh \
    -o PreferredAuthentications=password -o PubkeyAuthentication=no \
    -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -o ConnectTimeout=5 -o NumberOfPasswordPrompts=1 \
    -p "$SSH_PORT" "${ATTACK_USER}@${TARGET}" true >/dev/null 2>&1
}

knock_once() { timeout 2 bash -c ": </dev/tcp/${TARGET}/$1" 2>/dev/null; }

port_open() {
  if timeout 3 bash -c ": </dev/tcp/${TARGET}/${KNOCK_PROTECTED_PORT}" 2>/dev/null; then echo yes; else echo no; fi
}

if [ "$DO_KNOCK" = "1" ]; then
  echo "${BOLD}1) Port knocking${RESET}"
  before=$(port_open)
  echo "  portul ${KNOCK_PROTECTED_PORT} inainte de knock: ${before}"
  for p in "${KNOCK_SEQ[@]}"; do knock_once "$p"; echo "  knock -> ${p}"; sleep 0.3; done
  sleep 2
  after=$(port_open)
  echo "  portul ${KNOCK_PROTECTED_PORT} dupa knock:    ${after}"
  if [ "$after" = "yes" ] && [ "$before" = "no" ]; then
    echo "  ${GREEN}KNOCK OK - portul s-a deschis dupa secventa corecta${RESET}"
  elif [ "$after" = "yes" ]; then
    echo "  ${YELLOW}portul era deja deschis (firewall fara default-deny pe ${KNOCK_PROTECTED_PORT}) - verifica alerta in UI${RESET}"
  else
    echo "  ${RED}portul nu s-a deschis - knock-urile nu au ajuns la listener (firewall pe porturile de knock?)${RESET}"
  fi
  echo "  ${YELLOW}>> Uita-te in UI: ar trebui o alerta de PORT KNOCK pentru IP-ul acestei masini.${RESET}"
  echo
fi

if [ "$DO_BRUTE" = "1" ]; then
  echo "${BOLD}2) Brute force SSH (auto-block)${RESET}"
  echo "  faza WARNING: ${WARN_AT} incercari esuate..."
  for ((i=1; i<=WARN_AT; i++)); do ssh_fail; printf '\r    incercarea %d/%d' "$i" "$WARN_AT"; sleep "$ATTACK_DELAY"; done
  echo
  echo "  ${YELLOW}>> Uita-te in UI ACUM: alerta WARNING pentru IP-ul tau. Continui in ${UI_PAUSE}s...${RESET}"
  sleep "$UI_PAUSE"
  more=$((BLOCK_AT - WARN_AT)); [ "$more" -lt 1 ] && more=1
  echo "  faza BLOCK: inca ${more} incercari (total ${BLOCK_AT})..."
  for ((i=1; i<=more; i++)); do ssh_fail; printf '\r    incercarea %d/%d' "$i" "$more"; sleep "$ATTACK_DELAY"; done
  echo
  echo "  ${YELLOW}>> Uita-te in UI: alerta BLOCKED. Dupa block, conexiunile acestei masini spre ${TARGET} vor fi picate.${RESET}"
  echo "  ${DIM}ca sa repeti testul, deblocheaza IP-ul din UI (Firewall) inainte.${RESET}"
  echo
fi
