#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  setup.sh <repo_name_or_dir> [--mode <process|docker|cloudrun>] [--deploy|--uninstall] [--repo <git_url>] [--ref <git_ref>] [--dir <path>]

Examples:
  # Remote install (process mode):
  # curl -fsSL "https://raw.githubusercontent.com/cloud-neutral-toolkit/<repo>/main/scripts/setup.sh?$(date +%s)" | bash -s -- <repo> --mode process --deploy
  #
  # Remote install (docker mode):
  # curl -fsSL "https://raw.githubusercontent.com/cloud-neutral-toolkit/<repo>/main/scripts/setup.sh?$(date +%s)" | bash -s -- <repo> --mode docker --deploy
  #
  # Remote install (Cloud Run mode):
  # curl -fsSL "https://raw.githubusercontent.com/cloud-neutral-toolkit/<repo>/main/scripts/setup.sh?$(date +%s)" | bash -s -- <repo> --mode cloudrun
  #
  # Local:
  # bash scripts/setup.sh <repo> --mode process
  #
  # Uninstall:
  # bash scripts/setup.sh <repo> --mode process --uninstall

Notes:
  - Safe: no secrets written; no destructive actions.
  - If .env does not exist, it copies .env.example -> .env (placeholder only).
EOF
}

log() { printf '[setup] %s\n' "$*"; }

normalize_mode() {
  case "${1:-process}" in
    process|proc|local|binary) printf 'process\n' ;;
    docker|container) printf 'docker\n' ;;
    cloudrun|cloud-run|gcp) printf 'cloudrun\n' ;;
    *)
      log "unsupported mode: ${1:-}"
      usage
      exit 2
      ;;
  esac
}

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    log "missing required command: $1"
    exit 1
  fi
}

if [[ "${1:-}" == "" || "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

NAME="$1"
shift

REPO_URL=""
REF="main"
DIR="$NAME"
MODE="process"
ACTION="setup"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --mode|--deploy-mode) MODE="${2:-}"; shift 2 ;;
    --deploy) ACTION="deploy"; shift ;;
    --uninstall) ACTION="uninstall"; shift ;;
    --repo) REPO_URL="${2:-}"; shift 2 ;;
    --ref) REF="${2:-}"; shift 2 ;;
    --dir) DIR="${2:-}"; shift 2 ;;
    *) log "unknown arg: $1"; usage; exit 2 ;;
  esac
done

MODE="$(normalize_mode "$MODE")"

if [[ -z "${REPO_URL}" ]]; then
  REPO_URL="https://github.com/cloud-neutral-toolkit/${NAME}.git"
fi

need_cmd git
need_cmd curl

if [[ -e "${DIR}" && ! -d "${DIR}" ]]; then
  log "path exists and is not a directory: ${DIR}"
  exit 2
fi

if [[ ! -d "${DIR}" ]]; then
  log "cloning ${REPO_URL} (ref=${REF}) -> ${DIR}"
  git clone --depth 1 --branch "${REF}" "${REPO_URL}" "${DIR}"
else
  if [[ ! -d "${DIR}/.git" ]]; then
    log "directory exists but is not a git repo: ${DIR}"
    exit 2
  fi
  log "repo directory already exists: ${DIR}"
fi

cd "${DIR}"

if [[ "${ACTION}" == "uninstall" ]]; then
  case "$MODE" in
    process) bash scripts/uninstall-process.sh ;;
    docker) bash scripts/uninstall-docker.sh ;;
    cloudrun)
      log "cloudrun uninstall is not supported by setup.sh; use gcloud directly"
      exit 2
      ;;
  esac
  exit 0
fi

did_any=false

case "$MODE" in
  process)
    if [[ -f "package.json" ]]; then
      need_cmd node
      if command -v corepack >/dev/null 2>&1; then
        corepack enable >/dev/null 2>&1 || true
      fi
      if command -v yarn >/dev/null 2>&1; then
        log "installing JS dependencies (yarn install)"
        yarn install
        did_any=true
      else
        log "yarn not found; install yarn (or enable corepack) then re-run"
        exit 1
      fi
    fi

    if [[ -f "go.mod" ]]; then
      if command -v go >/dev/null 2>&1; then
        log "downloading Go dependencies (go mod download)"
        go mod download
      elif [[ "${ACTION}" == "deploy" ]]; then
        log "go not found; process deploy will install it during scripts/install-process.sh"
      else
        need_cmd go
      fi
      did_any=true
    fi
    ;;
  docker)
    need_cmd docker
    log "docker mode selected; skipping host-level dependency installation"
    did_any=true
    ;;
  cloudrun)
    need_cmd docker
    need_cmd gcloud
    log "cloudrun mode selected; skipping host-level dependency installation"
    did_any=true
    ;;
esac

if [[ "${did_any}" == "false" ]]; then
  log "no supported project type detected (package.json/go.mod)."
  log "setup script completed without installing deps."
fi

if [[ ! -f ".env" && -f ".env.example" ]]; then
  log "creating .env from .env.example (placeholder only)"
  cp .env.example .env
fi

if [[ -f "scripts/post-setup.sh" ]]; then
  log "running scripts/post-setup.sh"
  bash scripts/post-setup.sh
fi

if [[ "${ACTION}" == "deploy" ]]; then
  case "$MODE" in
    process) bash scripts/install-process.sh ;;
    docker) bash scripts/install-docker.sh ;;
    cloudrun)
      if [[ -z "${GCP_PROJECT:-}" ]]; then
        log "cloudrun deploy requires GCP_PROJECT in the environment"
        exit 2
      fi
      make cloudrun-build
      make cloudrun-deploy
      ;;
  esac
fi

log "setup complete (mode=${MODE})"
log "next steps:"
case "$MODE" in
  process)
    if [[ -f ".env.example" ]]; then
      log "  cp .env.example .env"
    fi
    if [[ -f "Makefile" ]]; then
      log "  make init-db"
      log "  make start"
      log "  sudo bash scripts/install-process.sh"
    elif [[ -f "go.mod" ]]; then
      log "  go run ./cmd/accountsvc/main.go --config config/account.yaml"
    fi
    ;;
  docker)
    log "  docker build -t accounts-svc-plus ."
    log "  docker run --rm -p 8080:8080 -e CONFIG_TEMPLATE=/app/config/account.yaml -e CONFIG_PATH=/etc/xcontrol/account.yaml accounts-svc-plus"
    log "  sudo bash scripts/install-docker.sh"
    ;;
  cloudrun)
    log "  export GCP_PROJECT=<your-project>"
    log "  GCP_PROJECT=<your-project> make cloudrun-build"
    log "  GCP_PROJECT=<your-project> make cloudrun-deploy CLOUD_RUN_SERVICE_YAML=deploy/gcp/cloud-run/prod-service.yaml"
    ;;
esac
