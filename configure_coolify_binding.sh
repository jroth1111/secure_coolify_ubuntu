#!/usr/bin/env bash
set -Eeuo pipefail

# configure_coolify_binding.sh — Bind Coolify dashboard to Tailscale IP only
# Companion script for bootstrap_hardening.sh
#
# Usage:
#   sudo ./configure_coolify_binding.sh [--tailscale-ip <ip>] [--dry-run]

SCRIPT_NAME="$(basename "$0")"
COOLIFY_ENV="/data/coolify/source/.env"
TAILSCALE_IP=""
DRY_RUN="false"

log() {
  printf '[%s] %s\n' "$(date -Iseconds)" "$*"
}

warn() {
  log "WARN: $*"
}

die() {
  log "ERROR: $*"
  exit 1
}

usage() {
  cat <<'EOF'
Bind Coolify dashboard and Soketi to Tailscale IP only.

Usage:
  configure_coolify_binding.sh [options]

Options:
  --tailscale-ip <ip>   Override auto-detected Tailscale IPv4 address
  --dry-run             Print actions without changing system
  -h, --help            Show this help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --tailscale-ip)
      [[ -n "${2:-}" ]] || die "Option $1 requires a value."
      TAILSCALE_IP="$2"
      shift 2
      ;;
    --dry-run)
      DRY_RUN="true"
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      die "Unknown option: $1 (use --help)"
      ;;
  esac
done

# Require root
[[ "$(id -u)" -eq 0 ]] || die "Run as root."

# Auto-detect Tailscale IP if not provided
if [[ -z "${TAILSCALE_IP}" ]]; then
  command -v tailscale >/dev/null 2>&1 || die "tailscale command not found. Install Tailscale or use --tailscale-ip."
  TAILSCALE_IP="$(tailscale ip -4 2>/dev/null)" || die "Failed to detect Tailscale IPv4 address. Is Tailscale running?"
  [[ -n "${TAILSCALE_IP}" ]] || die "Tailscale returned empty IPv4 address."
fi

# Validate IP format
[[ "${TAILSCALE_IP}" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "Invalid IP address format: ${TAILSCALE_IP}"

log "Using Tailscale IP: ${TAILSCALE_IP}"

# Check Coolify env file exists
[[ -f "${COOLIFY_ENV}" ]] || die "Coolify .env file not found at ${COOLIFY_ENV}. Is Coolify installed?"

if [[ "${DRY_RUN}" == "true" ]]; then
  log "DRY-RUN: would backup ${COOLIFY_ENV}"
  log "DRY-RUN: would set APP_PORT=${TAILSCALE_IP}:8000"
  log "DRY-RUN: would set SOKETI_PORT=${TAILSCALE_IP}:6001"
  log "DRY-RUN: would restart Coolify"
  exit 0
fi

# Backup current .env
BACKUP="${COOLIFY_ENV}.bak.$(date +%s)"
cp -a "${COOLIFY_ENV}" "${BACKUP}"
log "Backed up ${COOLIFY_ENV} to ${BACKUP}"

# Helper: set or update a key=value in the .env file
set_env_var() {
  local key="$1"
  local value="$2"
  local file="$3"

  if grep -q "^${key}=" "${file}"; then
    sed -i "s|^${key}=.*|${key}=${value}|" "${file}"
    log "Updated ${key}=${value}"
  else
    echo "${key}=${value}" >> "${file}"
    log "Added ${key}=${value}"
  fi
}

set_env_var "APP_PORT" "${TAILSCALE_IP}:8000" "${COOLIFY_ENV}"
set_env_var "SOKETI_PORT" "${TAILSCALE_IP}:6001" "${COOLIFY_ENV}"

# Restart Coolify to apply changes
log "Restarting Coolify..."
cd /data/coolify/source
docker compose down --remove-orphans 2>/dev/null || true
docker compose up -d

# Wait for Coolify to start
sleep 5

# Verify binding
log "Verifying bindings..."

BOUND_8000="$(ss -tlnp 2>/dev/null | grep ':8000 ' || true)"
if echo "${BOUND_8000}" | grep -q "${TAILSCALE_IP}:8000"; then
  log "PASS: Port 8000 bound to ${TAILSCALE_IP}"
else
  warn "Port 8000 may not be bound to ${TAILSCALE_IP} yet. Check: ss -tlnp | grep 8000"
fi

BOUND_6001="$(ss -tlnp 2>/dev/null | grep ':6001 ' || true)"
if echo "${BOUND_6001}" | grep -q "${TAILSCALE_IP}:6001"; then
  log "PASS: Port 6001 bound to ${TAILSCALE_IP}"
else
  warn "Port 6001 may not be bound to ${TAILSCALE_IP} yet. Check: ss -tlnp | grep 6001"
fi

# Test that public IP is NOT serving the dashboard
if command -v nc >/dev/null 2>&1; then
  PUBLIC_IP="$(ip -o route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src") print $(i+1)}')"
  if [[ -n "${PUBLIC_IP}" && "${PUBLIC_IP}" != "${TAILSCALE_IP}" ]]; then
    if nc -z -w2 "${PUBLIC_IP}" 8000 2>/dev/null; then
      warn "Port 8000 still appears reachable on public IP ${PUBLIC_IP}."
    else
      log "PASS: Port 8000 not reachable on public IP ${PUBLIC_IP}"
    fi
  fi
fi

log "Coolify binding configuration complete."
log "Dashboard: http://${TAILSCALE_IP}:8000"
