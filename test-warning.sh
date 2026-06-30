#!/bin/bash
VM_IP="192.168.64.4"     # IP-ul VM-ului tău
ATTEMPTS=4               # ÎNTRE pragul de warning și cel de block

echo "Trimit $ATTEMPTS incercari SSH cu utilizatori inexistenti catre $VM_IP..."
for i in $(seq 1 $ATTEMPTS); do
  ssh -o BatchMode=yes -o ConnectTimeout=5 -o StrictHostKeyChecking=no "ghost_user_$i@$VM_IP" >/dev/null 2>&1
  echo "  incercarea $i/$ATTEMPTS trimisa"
  sleep 1
done
echo "Gata. In ~15s, IP-ul tau (cum il vede VM-ul) ar trebui sa apara ca WARNING."
