#!/usr/bin/env bash
set -euo pipefail

tags="$1"
preferred=""

while IFS= read -r line; do
  if [[ "$line" == *":latest" ]]; then
    continue
  fi
  if [[ -n "$line" ]]; then
    preferred="$line"
    break
  fi
done <<< "$tags"

if [[ -z "$preferred" ]]; then
  preferred="$(echo "$tags" | head -n 1)"
fi

echo "$preferred"
