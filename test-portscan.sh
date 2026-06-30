#!/bin/bash
VM_IP="192.168.64.4"
BASE=20000
COUNT=5            # >= min-ports(5) si >= warning, dar < block

echo "Scanez $COUNT porturi distincte pe $VM_IP..."
for i in $(seq 1 $COUNT); do
  nc -z -G 1 -w 1 "$VM_IP" $((BASE + i)) >/dev/null 2>&1
  echo "  port $((BASE + i))"
done
echo "Gata. In ~15s IP-ul tau ar trebui sa apara ca WARNING (PORT_SCAN)."
