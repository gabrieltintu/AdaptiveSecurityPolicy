PID="${1:?Dă PID-ul: ./measure_res.sh <PID> [durata] [interval] [eticheta]}"
DUR="${2:-30}"; INT="${3:-2}"; LABEL="${4:-masuratoare}"
TCK=$(getconf CLK_TCK)
[ -d "/proc/$PID" ] || { echo "Procesul $PID nu există"; exit 1; }

read_tot(){ awk '{s=$0; sub(/^[^)]*\) /,"",s); split(s,a," "); print a[12]+a[13]}' /proc/$PID/stat; }

echo "== $LABEL: PID $PID, ${DUR}s la ${INT}s =="
printf "%-6s %9s %8s\n" "t(s)" "RAM(MB)" "CPU(%)"
prev=$(read_tot); t=0; n=0; ramsum=0; rammax=0; cpusum=0; cpumax=0
endt=$((SECONDS+DUR))
while [ $SECONDS -lt $endt ]; do
  sleep "$INT"
  [ -d "/proc/$PID" ] || { echo "Procesul a dispărut"; break; }
  cur=$(read_tot)
  rss=$(awk '/VmRSS/{print $2}' /proc/$PID/status)
  ram=$(awk "BEGIN{printf \"%.0f\",$rss/1024}")
  cpu=$(awk "BEGIN{printf \"%.1f\",100*($cur-$prev)/$TCK/$INT}")
  prev=$cur; t=$((t+INT)); n=$((n+1))
  printf "%-6s %9s %8s\n" "$t" "$ram" "$cpu"
  ramsum=$(awk "BEGIN{print $ramsum+$ram}"); cpusum=$(awk "BEGIN{print $cpusum+$cpu}")
  awk "BEGIN{exit !($ram>$rammax)}" && rammax=$ram
  awk "BEGIN{exit !($cpu>$cpumax)}" && cpumax=$cpu
done
[ $n -gt 0 ] && { echo "----"; \
  awk "BEGIN{printf \"RAM: medie %.0f MB | maxim %.0f MB\n\",$ramsum/$n,$rammax}"; \
  awk "BEGIN{printf \"CPU: medie %.1f%% | varf %.1f%% \n\",$cpusum/$n,$cpumax}"; }
