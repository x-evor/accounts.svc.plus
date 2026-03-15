#!/usr/bin/env bash
set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/_common.sh"

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "process deployment is only supported on Linux" >&2
  exit 1
fi

if [[ "${EUID}" -ne 0 ]]; then
  echo "process deployment must run as root" >&2
  exit 1
fi

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1" >&2
    exit 1
  fi
}

need_cmd systemctl
need_cmd install
need_cmd curl

if ! command -v go >/dev/null 2>&1; then
  bash scripts/init-go.sh
fi
need_cmd go

SERVICE_NAME="${SERVICE_NAME:-accounts-svc-plus}"
DOMAIN="${ACCOUNT_DOMAIN:-accounts.svc.plus}"
LISTEN_ADDR="${ACCOUNT_LISTEN_ADDR:-127.0.0.1:8080}"
PUBLIC_URL="${ACCOUNT_PUBLIC_URL:-https://${DOMAIN}}"
CONFIG_DIR="${CONFIG_DIR:-/etc/accounts.svc.plus}"
CONFIG_PATH="${CONFIG_PATH:-${CONFIG_DIR}/account.standalone.yaml}"
BINARY_PATH="${BINARY_PATH:-/usr/local/bin/accounts-svc-plus}"
SYSTEMD_UNIT_PATH="${SYSTEMD_UNIT_PATH:-/etc/systemd/system/${SERVICE_NAME}.service}"
CADDY_CONF_DIR="${CADDY_CONF_DIR:-/etc/caddy/conf.d}"
CADDY_CONF_PATH="${CADDY_CONF_PATH:-${CADDY_CONF_DIR}/${DOMAIN}.conf}"

tmp_binary="$(mktemp)"
trap 'rm -f "${tmp_binary}"' EXIT

go build -o "${tmp_binary}" ./cmd/accountsvc/main.go

install -d -m 0755 "$(dirname "${BINARY_PATH}")" "${CONFIG_DIR}" "${CADDY_CONF_DIR}"
install -m 0755 "${tmp_binary}" "${BINARY_PATH}"

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
  addr: "${LISTEN_ADDR}"
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
  controllerUrl: "http://${LISTEN_ADDR}"
  apiToken: "standalone-agent-token"
  httpTimeout: 15s
  statusInterval: 1m
  syncInterval: 5m
  tls:
    insecureSkipVerify: false

agents:
  credentials:
    - id: "account-primary"
      name: "Account Server (standalone)"
      token: "standalone-agent-token"
      groups:
        - "default"
EOF

cat > "${SYSTEMD_UNIT_PATH}" <<EOF
[Unit]
Description=Accounts Service Plus (process mode)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
DynamicUser=yes
StateDirectory=${SERVICE_NAME}
WorkingDirectory=/var/lib/${SERVICE_NAME}
Environment=HOME=/var/lib/${SERVICE_NAME}
ExecStart=${BINARY_PATH} --config ${CONFIG_PATH}
Restart=on-failure
RestartSec=3
NoNewPrivileges=yes

[Install]
WantedBy=multi-user.target
EOF

cat > "${CADDY_CONF_PATH}" <<EOF
${DOMAIN} {
    encode zstd gzip
    reverse_proxy ${LISTEN_ADDR}
}
EOF

systemctl daemon-reload
systemctl enable --now "${SERVICE_NAME}.service"

if systemctl is-active --quiet caddy; then
  systemctl reload caddy || systemctl restart caddy
fi

curl -fsS "http://${LISTEN_ADDR}/healthz" >/dev/null

echo "process deployment complete"
echo "service: ${SERVICE_NAME}.service"
echo "config: ${CONFIG_PATH}"
echo "caddy: ${CADDY_CONF_PATH}"
