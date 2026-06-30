#!/usr/bin/env bash
# Porneste backend-ul Spring Boot cu credentialele din .env incarcate in mediu.
# (Spring Boot nu citeste .env automat; de aceea le exportam noi aici inainte de run.)
set -euo pipefail
cd "$(dirname "$0")"

if [ ! -f .env ]; then
  echo "Lipseste .env. Ruleaza intai:  cp .env.example .env" >&2
  exit 1
fi

set -a
# shellcheck disable=SC1091
source ./.env
set +a

cd adaptive-security-policy-api
exec ./mvnw spring-boot:run
