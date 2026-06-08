#!/usr/bin/env bash
set -uo pipefail

TARGET_IP="192.168.64.4"
KNOCK_SEQ=(8936 6027 9417)
PROTECTED_PORT=22

# Culori pentru consola
GREEN=$'\033[32m'
RED=$'\033[31m'
YELLOW=$'\033[33m'
RESET=$'\033[0m'

echo "=========================================================="
echo " 1. TESTARE PORT KNOCKING SPRE $TARGET_IP"
echo "=========================================================="

echo "a) Verificam daca portul $PROTECTED_PORT este inchis initial (ar trebui sa esueze)..."
if nc -z -w 2 $TARGET_IP $PROTECTED_PORT 2>/dev/null || nc -z -G 2 $TARGET_IP $PROTECTED_PORT 2>/dev/null; then
  echo "${YELLOW}ATENTIE: Portul $PROTECTED_PORT este deja deschis! (Ori knock-ul e deja activ, ori SSH-ul nu e protejat).${RESET}"
else
  echo "${GREEN}-> Portul $PROTECTED_PORT este inchis (Corect).${RESET}"
fi

echo "b) Trimitem secventa secreta: ${KNOCK_SEQ[*]} ..."
for port in "${KNOCK_SEQ[@]}"; do
  # nc -z doar incearca o conexiune rapida fara a trimite date
  nc -z -w 1 $TARGET_IP "$port" 2>/dev/null || nc -z -G 1 $TARGET_IP "$port" 2>/dev/null || true
  sleep 0.2
done

echo "c) Asteptam 2 secunde sa proceseze backend-ul cererile..."
sleep 2

echo "d) Verificam din nou portul $PROTECTED_PORT..."
if nc -z -w 2 $TARGET_IP $PROTECTED_PORT 2>/dev/null || nc -z -G 2 $TARGET_IP $PROTECTED_PORT 2>/dev/null; then
  echo "${GREEN}SUCCES! 🎉 Portul $PROTECTED_PORT s-a deschis ca prin magie!${RESET}"
else
  echo "${RED}ESEC. Portul $PROTECTED_PORT a ramas inchis.${RESET}"
fi

echo ""
echo "=========================================================="
echo " 2. TESTARE BRUTE FORCE & SCHEDULER AUTO-BLOCK"
echo "=========================================================="
echo "${YELLOW}🚨 ATENTIE MAJORĂ: Daca acest test reuseste, backend-ul iti va bloca complet IP-ul Mac-ului tau in iptables!${RESET}"
echo "${YELLOW}Nu vei mai putea accesa Angular, Backend-ul sau SSH-ul spre mașina virtuală pana nu intri direct din interfata mașinii virtuale (sau din panoul UTM/Parallels) sa iti scoti IP-ul din ban list.${RESET}"
echo ""

read -p "Esti sigur ca vrei sa sacrifici accesul actual pentru a testa blocarea? (y/n) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
  echo "Incepem atacul simulat SSH pe $TARGET_IP..."
  
  if ! command -v sshpass &> /dev/null; then
      echo "${RED}Ai nevoie de 'sshpass' instalat pe Mac. Ruleaza comanda: brew install sshpass${RESET}"
      exit 1
  fi

  echo ">>> FAZA 1: Generam 3 încercări eșuate (pentru a atinge pragul de WARNING)..."
  for i in {1..3}; do
    echo "  -> Incercarea de forță brută #$i..."
    sshpass -p 'o-parola-gresita' ssh -o StrictHostKeyChecking=no -o ConnectTimeout=3 ubuntu@$TARGET_IP true 2>/dev/null || true
    sleep 0.5
  done
  
  echo "Așteptăm 16 secunde ca Scheduler-ul să proceseze logurile..."
  for sec in {16..1}; do echo -ne "  ⏳ Timp rămas: $sec secunde...\r"; sleep 1; done
  echo -e "\n${YELLOW}>> Uită-te acum în interfața web (UI)! Ar trebui să îți fi apărut o alertă de tip WARNING pentru IP-ul tău.${RESET}"
  
  read -p "Apasă ENTER pentru a continua cu blocarea completă..."
  
  echo ">>> FAZA 2: Generam încă 4 încercări eșuate (pentru a depăși pragul de 6 și a primi BLOCK)..."
  for i in {4..7}; do
    echo "  -> Incercarea de forță brută #$i..."
    sshpass -p 'o-parola-gresita' ssh -o StrictHostKeyChecking=no -o ConnectTimeout=3 ubuntu@$TARGET_IP true 2>/dev/null || true
    sleep 0.5
  done
  
  echo "Așteptăm din nou 16 secunde pentru ca Scheduler-ul să aplice blocarea..."
  for sec in {16..1}; do echo -ne "  ⏳ Timp rămas: $sec secunde...\r"; sleep 1; done
  echo -e "\n${YELLOW}>> Uită-te iar în interfața web (UI)! Acum IP-ul ar trebui să apară BLOCAT (Block Alert).${RESET}"
  if curl --connect-timeout 3 -s http://$TARGET_IP:8090/api/test/ping >/dev/null; then
    echo "${RED}ESEC: Inca poti face ping. Adaptive Security nu ti-a blocat IP-ul.${RESET}"
  else
    echo "${GREEN}SUCCES ABSOLUT! 🎉 Conexiunea a picat instant. Adaptive Security Policy te-a detectat si ti-a blocat IP-ul Mac-ului direct din firewall-ul mașinii virtuale!${RESET}"
  fi
else
  echo "Testul de Brute Force a fost anulat preventiv."
fi
