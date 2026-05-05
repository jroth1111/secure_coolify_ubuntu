#!/usr/bin/env bash
if [[ -z "${BASH_VERSINFO:-}" || "${BASH_VERSINFO[0]}" -lt 4 ]]; then
  for candidate in /opt/homebrew/bin/bash /usr/local/bin/bash; do
    if [[ -x "${candidate}" ]]; then
      exec "${candidate}" "$0" "$@"
    fi
  done
  printf 'FATAL: %s requires Bash 4+ (found %s). On macOS: brew install bash, then run with /opt/homebrew/bin/bash %s ...\n' \
    "$(basename "$0")" "${BASH_VERSION:-unknown}" "$(basename "$0")" >&2
  exit 1
fi
set -Eeuo pipefail

# configure_coolify_binding.sh — Restrict Coolify dashboard access to Tailscale via UFW
# Companion script for bootstrap_hardening.sh
#
# Usage:
#   sudo ./configure_coolify_binding.sh [--tailscale-ip <ip>] [--dry-run]

SCRIPT_NAME="$(basename "$0")"
COOLIFY_ENV="/data/coolify/source/.env"
TAILSCALE_IP=""
DRY_RUN="false"
IPV4_RE='^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'

log() {
  printf '[%s] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*"
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
Restrict Coolify dashboard and Soketi access to Tailscale via UFW.

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
[[ "${TAILSCALE_IP}" =~ ${IPV4_RE} ]] || die "Invalid IP address format: ${TAILSCALE_IP}"
IFS='.' read -r ip_o1 ip_o2 _ip_o3 _ip_o4 <<< "${TAILSCALE_IP}"
if ! (( ip_o1 == 100 && ip_o2 >= 64 && ip_o2 <= 127 )); then
  die "IP is not in Tailscale CGNAT range 100.64.0.0/10: ${TAILSCALE_IP}"
fi
unset ip_o1 ip_o2 _ip_o3 _ip_o4

command -v tailscale >/dev/null 2>&1 || die "tailscale command not found. Install Tailscale before binding."
host_tailscale_ip="$(tailscale ip -4 2>/dev/null || true)"
[[ -n "${host_tailscale_ip}" ]] || die "Unable to detect host Tailscale IPv4 address."
if [[ "${TAILSCALE_IP}" != "${host_tailscale_ip}" ]]; then
  die "Provided Tailscale IP (${TAILSCALE_IP}) does not match host address (${host_tailscale_ip})."
fi
unset host_tailscale_ip

log "Using Tailscale IP: ${TAILSCALE_IP}"

# Check Coolify env file exists
[[ -f "${COOLIFY_ENV}" ]] || die "Coolify .env file not found at ${COOLIFY_ENV}. Is Coolify installed?"

if [[ "${DRY_RUN}" == "true" ]]; then
  log "DRY-RUN: would add UFW rules for ports 8000, 6001, and 6002 on tailscale0"
  log "DRY-RUN: would verify Coolify is listening on port 8000"
  log "DRY-RUN: would verify port 8000 is not reachable on public IP"
  exit 0
fi

# Dashboard security is enforced via UFW, not APP_PORT socket binding.
# Coolify's docker-compose.prod.yml uses APP_PORT in both ports: and expose: directives;
# expose: requires a plain port number, so IP:port format is incompatible.
# UFW default-deny incoming + explicit allow rules on tailscale0 provides the same
# defense-in-depth: dashboard reachable via Tailscale, blocked from public interfaces.

delete_non_tailscale_rule_numbers() {
  local numbered rules=()
  numbered="$(ufw status numbered 2>/dev/null || true)"
  mapfile -t rules < <(
    awk '
      BEGIN { IGNORECASE=1 }
      /\[[[:space:]]*[0-9]+\]/ && /ALLOW IN/ && /(8000|6001|6002)(\/tcp)?/ {
        line=tolower($0)
        if (index(line, "tailscale0") == 0) {
          rule=$1
          gsub(/\[/, "", rule)
          gsub(/\]/, "", rule)
          print rule
        }
      }
    ' <<< "${numbered}" | sort -rn
  )
  printf '%s\n' "${rules[@]}"
}

verify_tailscale_ufw_rules() {
  local ufw_status port
  ufw_status="$(ufw status verbose 2>/dev/null || true)"
  for port in 8000 6001 6002; do
    if ! awk -v p="${port}/tcp" '
        BEGIN { found=0 }
        {
          line=tolower($0)
          if (index(line, tolower(p)) && index(line, "tailscale0") && index(line, "allow")) {
            found=1
          }
        }
        END { exit(found ? 0 : 1) }
      ' <<< "${ufw_status}"; then
      die "UFW rule missing for ${port}/tcp on tailscale0."
    fi
  done
}

log "Ensuring UFW restricts dashboard ports to tailscale0..."
command -v ufw >/dev/null 2>&1 || die "ufw not found. This script requires ufw to enforce dashboard restrictions."

while IFS= read -r rule_number; do
  [[ -n "${rule_number}" ]] || continue
  ufw --force delete "${rule_number}" >/dev/null 2>&1 \
    || die "Failed to remove non-tailscale UFW rule #${rule_number} for dashboard ports."
done < <(delete_non_tailscale_rule_numbers)

# Idempotent — ufw silently skips duplicate rules
ufw allow in on tailscale0 proto tcp to any port 8000 comment "coolify-hardening-dashboard-tailscale" >/dev/null 2>&1 \
  || die "Failed to apply UFW rule for port 8000 on tailscale0."
ufw allow in on tailscale0 proto tcp to any port 6001 comment "coolify-hardening-soketi-tailscale" >/dev/null 2>&1 \
  || die "Failed to apply UFW rule for port 6001 on tailscale0."
ufw allow in on tailscale0 proto tcp to any port 6002 comment "coolify-hardening-terminal-tailscale" >/dev/null 2>&1 \
  || die "Failed to apply UFW rule for port 6002 on tailscale0."

verify_tailscale_ufw_rules
log "UFW rules verified for ports 8000, 6001, and 6002 on tailscale0."

# Wait for Coolify to start (up to 60s)
log "Waiting for Coolify to bind port 8000 (up to 60s)..."
for (( _i = 1; _i <= 12; _i++ )); do
  if ss -tlnp 2>/dev/null | grep -q ':8000 '; then
    break
  fi
  sleep 5
done
unset _i

verify_tailscale_ufw_rules
log "UFW rules still verified after Coolify startup wait."

# Verify security posture
log "Verifying bindings..."

bound_8000=""
bound_6001=""
bound_6002=""
public_ip=""
bound_8000="$(ss -tlnp 2>/dev/null | grep ':8000 ' || true)"
if [[ -n "${bound_8000}" ]]; then
  log "PASS: Port 8000 is listening"
else
  warn "Port 8000 not yet listening. Check: ss -tlnp | grep 8000"
fi

bound_6001="$(ss -tlnp 2>/dev/null | grep ':6001 ' || true)"
if [[ -n "${bound_6001}" ]]; then
  log "PASS: Port 6001 is listening"
else
  warn "Port 6001 not yet listening (may start later). Check: ss -tlnp | grep 6001"
fi

bound_6002="$(ss -tlnp 2>/dev/null | grep ':6002 ' || true)"
if [[ -n "${bound_6002}" ]]; then
  log "PASS: Port 6002 is listening"
else
  warn "Port 6002 not yet listening (may start later). Check: ss -tlnp | grep 6002"
fi

public_ip="$(ip -o route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src") print $(i+1)}')"
if [[ -n "${public_ip}" && "${public_ip}" != "${TAILSCALE_IP}" ]]; then
  log "INFO: External exposure for ${public_ip}:8000 is validated from an off-host probe (Gate E is authoritative)."
fi

log "Coolify binding firewall configuration complete."
log "Dashboard access restricted to Tailscale via UFW on ${TAILSCALE_IP}:8000"
