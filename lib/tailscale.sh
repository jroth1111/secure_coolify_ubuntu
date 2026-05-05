#!/usr/bin/env bash
# lib/tailscale.sh — Tailscale install + lifecycle helpers.
# Source this file; do not execute it directly.
#
# Caller must provide: log, warn, die, run, write_file, is_true, unit_available
# (typically defined in base/bootstrap.sh or lib/common.sh).
# Caller may set: TAILSCALE_AUTH_KEY, DRY_RUN.

[[ "${BASH_SOURCE[0]}" != "${0}" ]] \
  || { printf 'Source this file, do not execute it.\n' >&2; exit 1; }
[[ -z "${_LIB_TAILSCALE_LOADED:-}" ]] || return 0
_LIB_TAILSCALE_LOADED=1

TAILSCALE_IFACE="${TAILSCALE_IFACE:-tailscale0}"
TAILSCALED_NOTIFY_DROPIN="${TAILSCALED_NOTIFY_DROPIN:-/etc/systemd/system/tailscaled.service.d/10-notify-access.conf}"

# Cached IPv4 address from the most recent successful `tailscale ip -4` call.
DETECTED_TAILSCALE_IP="${DETECTED_TAILSCALE_IP:-}"

verify_tailscale_iface() {
  ip link show "${TAILSCALE_IFACE}" >/dev/null 2>&1 || die "Interface ${TAILSCALE_IFACE} not found. Refusing Tailscale-only SSH hardening."
}

get_tailscale_ip() {
  if [[ -n "${DETECTED_TAILSCALE_IP}" ]]; then
    echo "${DETECTED_TAILSCALE_IP}"
    return 0
  fi

  command -v tailscale >/dev/null 2>&1 || return 1
  DETECTED_TAILSCALE_IP="$(tailscale ip -4 2>/dev/null)" || return 1
  echo "${DETECTED_TAILSCALE_IP}"
}

emit_tailscale_result_sentinel() {
  local ts_ip=""
  ts_ip="$(get_tailscale_ip 2>/dev/null || true)"
  [[ "${ts_ip}" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 0
  printf 'HARDEN_RESULT_TAILSCALE_IP=%s\n' "${ts_ip}"
}

tailscale_runssh_pref_value() {
  local attempts="${1:-5}"
  local delay_seconds="${2:-1}"
  local attempt=1
  local run_ssh_pref="unknown"

  while (( attempt <= attempts )); do
    run_ssh_pref="$(tailscale debug prefs 2>/dev/null | jq -r 'if has("RunSSH") then (.RunSSH|tostring) else "unknown" end' 2>/dev/null || echo "unknown")"
    if [[ "${run_ssh_pref}" == "true" || "${run_ssh_pref}" == "false" ]]; then
      printf '%s\n' "${run_ssh_pref}"
      return 0
    fi
    if (( attempt < attempts )); then
      sleep "${delay_seconds}"
    fi
    attempt=$((attempt + 1))
  done

  printf '%s\n' "${run_ssh_pref:-unknown}"
}

install_tailscale() {
  if command -v tailscale >/dev/null 2>&1; then
    log "Tailscale already installed."
    return 0
  fi

  if is_true "${DRY_RUN:-false}"; then
    log "DRY-RUN: would install Tailscale via official apt repository."
    return 0
  fi

  log "Installing Tailscale via official apt repository..."
  local codename keyring listfile
  source /etc/os-release
  codename="${VERSION_CODENAME:-}"
  [[ -n "${codename}" ]] || die "Unable to determine Ubuntu codename for Tailscale repository."
  keyring="/usr/share/keyrings/tailscale-archive-keyring.gpg"
  listfile="/etc/apt/sources.list.d/tailscale.list"

  run curl -fsSL "https://pkgs.tailscale.com/stable/ubuntu/${codename}.noarmor.gpg" -o "${keyring}"
  run curl -fsSL "https://pkgs.tailscale.com/stable/ubuntu/${codename}.tailscale-keyring.list" -o "${listfile}"
  run apt-get update
  run env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends tailscale

  if [[ -n "${TAILSCALE_AUTH_KEY:-}" ]]; then
    log "Authenticating Tailscale with provided auth key..."
    run tailscale up --authkey="${TAILSCALE_AUTH_KEY}" --ssh=false
  else
    log "Interactive Tailscale authentication required."
    log "Run: tailscale up --ssh=false"
    log "Waiting for Tailscale connection (timeout: 120s)..."

    local timeout=120
    local elapsed=0
    while ! ip link show "${TAILSCALE_IFACE}" >/dev/null 2>&1; do
      if (( elapsed >= timeout )); then
        die "Timeout waiting for Tailscale interface. Run 'tailscale up --ssh=false' manually and retry."
      fi
      sleep 2
      elapsed=$((elapsed + 2))
      log "Waiting for ${TAILSCALE_IFACE}... (${elapsed}s/${timeout}s)"
    done
  fi

  log "Tailscale installed and configured."
}

ensure_tailscaled_notify_access() {
  if ! unit_available "tailscaled.service"; then
    log "tailscaled.service not installed; skipping NotifyAccess hardening."
    return 0
  fi

  local notify_access
  notify_access="$(systemctl show tailscaled.service -p NotifyAccess --value 2>/dev/null || true)"

  write_file "${TAILSCALED_NOTIFY_DROPIN}" "0644" "root" "root" <<'EOF'
[Service]
NotifyAccess=all
EOF

  run systemctl daemon-reload

  if [[ "${notify_access}" == "all" ]]; then
    log "tailscaled NotifyAccess already set to all."
    return 0
  fi

  if is_true "${DRY_RUN:-false}"; then
    log "DRY-RUN: would restart tailscaled.service to apply NotifyAccess=all."
    return 0
  fi

  if systemctl is-active --quiet tailscaled.service 2>/dev/null; then
    run systemctl restart tailscaled.service
  else
    run systemctl start tailscaled.service
  fi

  local retries=20
  local ready="false"
  while (( retries > 0 )); do
    if tailscale status --json >/dev/null 2>&1; then
      ready="true"
      break
    fi
    sleep 1
    retries=$((retries - 1))
  done

  [[ "${ready}" == "true" ]] || die "tailscaled did not become ready after NotifyAccess restart."
  log "tailscaled NotifyAccess hardened to all."
}

ensure_tailscale_ssh_disabled() {
  if ! command -v tailscale >/dev/null 2>&1; then
    return 0
  fi

  local run_ssh_pref
  run_ssh_pref="$(tailscale_runssh_pref_value 5 1)"

  if [[ "${run_ssh_pref}" != "false" ]]; then
    if is_true "${DRY_RUN:-false}"; then
      if [[ "${run_ssh_pref}" == "unknown" ]]; then
        log "DRY-RUN: would run 'tailscale set --ssh=false' because Tailscale RunSSH preference could not be confirmed after retries."
      else
        log "DRY-RUN: would run 'tailscale set --ssh=false' to keep host sshd as the only SSH control plane."
      fi
      return 0
    fi

    if [[ "${run_ssh_pref}" == "unknown" ]]; then
      warn "Unable to confirm Tailscale RunSSH preference after retries; forcing 'tailscale set --ssh=false'."
    fi
    run tailscale set --ssh=false
    run_ssh_pref="$(tailscale_runssh_pref_value 5 1)"
    [[ "${run_ssh_pref}" == "false" ]] || die "Failed to disable Tailscale SSH (RunSSH=${run_ssh_pref:-unknown})."
    log "Tailscale SSH disabled (RunSSH=false); host sshd remains authoritative."
  else
    log "Tailscale SSH already disabled (RunSSH=false)."
  fi
}
