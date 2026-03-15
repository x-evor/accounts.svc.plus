#!/usr/bin/env bash
set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/_common.sh"

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "docker deployment is only supported on Linux" >&2
  exit 1
fi

if [[ "${EUID}" -ne 0 ]]; then
  echo "docker deployment must run as root" >&2
  exit 1
fi

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1" >&2
    exit 1
  fi
}

need_cmd docker
need_cmd systemctl
need_cmd install
need_cmd curl

SERVICE_NAME="${SERVICE_NAME:-accounts-svc-plus-docker}"
CONTAINER_NAME="${CONTAINER_NAME:-accounts-svc-plus}"
IMAGE_TAG="${IMAGE_TAG:-accounts-svc-plus:local}"
DOMAIN="${ACCOUNT_DOMAIN:-accounts.svc.plus}"
LISTEN_ADDR="${ACCOUNT_LISTEN_ADDR:-127.0.0.1:8080}"
PUBLIC_URL="${ACCOUNT_PUBLIC_URL:-https://${DOMAIN}}"
CONFIG_DIR="${CONFIG_DIR:-/etc/accounts.svc.plus}"
CONFIG_PATH="${CONFIG_PATH:-${CONFIG_DIR}/account.standalone.yaml}"
SYSTEMD_UNIT_PATH="${SYSTEMD_UNIT_PATH:-/etc/systemd/system/${SERVICE_NAME}.service}"
CADDY_CONF_DIR="${CADDY_CONF_DIR:-/etc/caddy/conf.d}"
CADDY_CONF_PATH="${CADDY_CONF_PATH:-${CADDY_CONF_DIR}/${DOMAIN}.conf}"
DOCKER_BIN="$(command -v docker)"

install -d -m 0755 "${CONFIG_DIR}" "${CADDY_CONF_DIR}"

cat > "${CONFIG_PATH}" <<EOF
mode: "server-agent"

log:
  level: info

auth:
  enable: true
  token:
    publicToken: "standalone-public-token"
    refreshSecret: "standalone-refresh-secret"
    accessSecret: "standalone-access-secret"
    accessExpiry: "1h"
    refreshExpiry: "168h"

server:
  addr: ":8080"
  readTimeout: 15s
  writeTimeout: 15s
  publicUrl: "${PUBLIC_URL}"
  allowedOrigins:
    - "${PUBLIC_URL}"
    - "http://localhost:8080"
    - "http://127.0.0.1:8080"

store:
  driver: "memory"
  dsn: ""

session:
  ttl: 24h

smtp:
  host: ""
  port: 587
  username: ""
  password: ""
  from: ""
  replyTo: ""
  timeout: 10s
  tls:
    mode: "auto"
    insecureSkipVerify: false

xray:
  sync:
    enabled: false
    interval: 5m
    outputPath: ""
    templatePath: ""
    validateCommand: []
    restartCommand: []

agent:
  id: "account-primary"
  controllerUrl: "http://127.0.0.1:8080"
  apiToken: "standalone-agent-token"
  httpTimeout: 15s
  statusInterval: 1m
  syncInterval: 5m
  tls:
    insecureSkipVerify: false

agents:
  credentials:
    - id: "account-primary"
      name: "Account Server (docker)"
      token: "standalone-agent-token"
      groups:
        - "default"
EOF

cat > "${SYSTEMD_UNIT_PATH}" <<EOF
[Unit]
Description=Accounts Service Plus (docker mode)
After=docker.service network-online.target
Requires=docker.service
Wants=network-online.target

[Service]
Type=simple
Restart=always
RestartSec=3
ExecStartPre=-${DOCKER_BIN} rm -f ${CONTAINER_NAME}
ExecStart=${DOCKER_BIN} run --rm --name ${CONTAINER_NAME} -p ${LISTEN_ADDR}:8080 -v ${CONFIG_PATH}:/etc/xcontrol/account.yaml:ro ${IMAGE_TAG}
ExecStop=${DOCKER_BIN} stop ${CONTAINER_NAME}

[Install]
WantedBy=multi-user.target
EOF

cat > "${CADDY_CONF_PATH}" <<EOF
${DOMAIN} {
    encode zstd gzip
    reverse_proxy ${LISTEN_ADDR}
}
EOF

docker build -t "${IMAGE_TAG}" .

systemctl daemon-reload
systemctl enable --now "${SERVICE_NAME}.service"

if systemctl is-active --quiet caddy; then
  systemctl reload caddy || systemctl restart caddy
fi

curl -fsS "http://${LISTEN_ADDR}/healthz" >/dev/null

echo "docker deployment complete"
echo "service: ${SERVICE_NAME}.service"
echo "image: ${IMAGE_TAG}"
echo "caddy: ${CADDY_CONF_PATH}"
