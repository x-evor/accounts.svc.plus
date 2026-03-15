#!/usr/bin/env bash
set -euo pipefail

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "docker uninstall is only supported on Linux" >&2
  exit 1
fi

if [[ "${EUID}" -ne 0 ]]; then
  echo "docker uninstall must run as root" >&2
  exit 1
fi

SERVICE_NAME="${SERVICE_NAME:-accounts-svc-plus-docker}"
CONTAINER_NAME="${CONTAINER_NAME:-accounts-svc-plus}"
IMAGE_TAG="${IMAGE_TAG:-accounts-svc-plus:local}"
DOMAIN="${ACCOUNT_DOMAIN:-accounts.svc.plus}"
CONFIG_DIR="${CONFIG_DIR:-/etc/accounts.svc.plus}"
SYSTEMD_UNIT_PATH="${SYSTEMD_UNIT_PATH:-/etc/systemd/system/${SERVICE_NAME}.service}"
CADDY_CONF_DIR="${CADDY_CONF_DIR:-/etc/caddy/conf.d}"
CADDY_CONF_PATH="${CADDY_CONF_PATH:-${CADDY_CONF_DIR}/${DOMAIN}.conf}"

if command -v systemctl >/dev/null 2>&1; then
  systemctl disable --now "${SERVICE_NAME}.service" >/dev/null 2>&1 || true
fi

if command -v docker >/dev/null 2>&1; then
  docker rm -f "${CONTAINER_NAME}" >/dev/null 2>&1 || true
  docker image rm "${IMAGE_TAG}" >/dev/null 2>&1 || true
fi

rm -f "${SYSTEMD_UNIT_PATH}" "${CADDY_CONF_PATH}"
rm -rf "${CONFIG_DIR}"

if command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload
  if systemctl is-active --quiet caddy; then
    systemctl reload caddy || systemctl restart caddy
  fi
fi

echo "docker deployment removed"
