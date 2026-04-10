#!/usr/bin/env bash
set -euo pipefail

TARGET_HOST="${1:?target host is required}"
RUN_APPLY="${2:?run_apply flag is required}"
PLAYBOOK_DIR="${3:?playbook dir is required}"

test -n "${ACCOUNTS_IMAGE_REPO:-}"
test -n "${ACCOUNTS_IMAGE_TAG:-}"

cd "${PLAYBOOK_DIR}"

args=(
  ansible-playbook
  -i inventory.ini
  deploy_accounts_svc_plus.yml
  -l "${TARGET_HOST}"
)

if [[ "${RUN_APPLY}" != "true" ]]; then
  args+=(-C)
fi

ANSIBLE_CONFIG="${PWD}/ansible.cfg" \
ACCOUNTS_PULL_IMAGE="${ACCOUNTS_PULL_IMAGE:-true}" \
"${args[@]}"
