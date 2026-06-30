#!/usr/bin/env bash

BASE="http://localhost:8080"          

TOKEN="eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICI3R3NUS1V5bHJ3LXhzWjlyazdtbnhheDFmaEhpX1UzMW5IUmlEbGVSYzZFIn0.eyJleHAiOjE3ODE2MTM0OTUsImlhdCI6MTc4MTYxMzE5NSwiYXV0aF90aW1lIjoxNzgxNjEyMDc1LCJqdGkiOiIxOTgzNWVhYy1iMzY3LTRjNGEtOTIxNC0wZTY3MTNkMGNhNzciLCJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjgwODAvcmVhbG1zL2FkYXB0aXZlLXNlY3VyaXR5LXBvbGljeSIsImF1ZCI6ImFjY291bnQiLCJzdWIiOiI2ODcwYjhhMC0wNDg3LTRmOTQtOWE5Ni0xMmI3ODM4ZmYwNTciLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJhc3AtdWkiLCJzaWQiOiIzOGFiMTE3My00NTUyLTQ2ZjMtYmQ2My0xZmZjOGY0N\u2026hYnJpZWwgQWRtaW4iLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJnYWJyaWVsQGFkbWluLnJvIiwiZ2l2ZW5fbmFtZSI6IkdhYnJpZWwiLCJmYW1pbHlfbmFtZSI6IkFkbWluIiwiZW1haWwiOiJnYWJyaWVsQGFkbWluLnJvIn0.XNDYw3C6kpSu1nSy1NI8oFh2RK6dB31LJxJXlgU1sclLhsuwELg01bTwYEnH1fCZSZKf7qVDRETMPtK0Ha0pehP64bXDnvlpE2rX66zZutZxzDq00auRumK2xGCF4PtN8zGLjQaV8D7N_KwMQ9FzqG6RDm_An-Kr9nKmJ1TA8sgwTrOtv2obQ_VAXE-o7yfaM0FHvooGpUtz8wd3Nf7wjdntgC5gvoVrfX_l7ZhkbIMy6zBpdhMtfxy3Zcw0ZdaXDTlmY4VuOjhOnNKQHaO9PeQwAr3zweXi1TnE4FCnlZKB6rLldX3RZR01JL7Bta3ixu3LiwkaEbvqwNQIe1MnIA"             

N=10



ENDPOINTS=(

  "/api/monitoring/connections"

  "/api/monitoring/firewall-rules"

  "/api/monitoring/suspicious-ips"

  "/api/analytics/overview"

  "/api/events?page=0&size=20"

  "/api/policy"

  "/api/whitelist"

)



curl -o /dev/null -s -H "Authorization: Bearer $TOKEN" "$BASE/api/policy"



printf "%-38s %9s %9s %9s\n" "Ruta" "min(ms)" "med(ms)" "max(ms)"

for ep in "${ENDPOINTS[@]}"; do

  for i in $(seq 1 $N); do

    curl -o /dev/null -s -w "%{time_total}\n" -H "Authorization: Bearer $TOKEN" "$BASE$ep"

  done | awk -v ep="$ep" '

    { v=$1*1000; s+=v; if(min==""||v<min)min=v; if(v>max)max=v; n++ }

    END { printf "%-38s %9.1f %9.1f %9.1f\n", ep, min, s/n, max }'

done
