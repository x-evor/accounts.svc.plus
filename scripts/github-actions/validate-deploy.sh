#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${1:-https://accounts.svc.plus}"

curl \
  --silent \
  --show-error \
  --fail \
  --location \
  --max-time 20 \
  "${BASE_URL}/healthz" | grep -q '"status":"ok"'
