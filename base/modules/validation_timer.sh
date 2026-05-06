configure_hardening_validation_timer() {
  if is_true "${DRY_RUN}"; then
    log "DRY-RUN: would install hardening-validate.timer (daily base/validate.sh run)."
    return 0
  fi

  # Locate validate_hardening.sh relative to this script, with multiple fallbacks
  local script_dir validate_src validate_dest
  if [[ -n "${BASH_SOURCE[0]:-}" ]]; then
    script_dir="$(cd "${BASH_SOURCE[0]%/*}" 2>/dev/null && pwd)" || {
      # Fallback 1: realpath (common on Linux)
      if command -v realpath >/dev/null 2>&1; then
        script_dir="$(dirname "$(realpath "${BASH_SOURCE[0]}")" 2>/dev/null)" || script_dir=""
      fi
      # Fallback 2: readlink -f (macOS/BSD)
      if [[ -z "${script_dir}" ]] && command -v readlink >/dev/null 2>&1; then
        script_dir="$(dirname "$(readlink -f "${BASH_SOURCE[0]}" 2>/dev/null || echo "${BASH_SOURCE[0]}")")"
      fi
    }
  fi

  # Final fallback: use directory of script invocation
  script_dir="${script_dir:-$(pwd)}"

  validate_src="${script_dir}/validate.sh"
  validate_dest="/usr/local/sbin/validate-hardening"

  if [[ -f "${validate_src}" ]]; then
    install -m 0750 -o root -g root "${validate_src}" "${validate_dest}"
    log "Installed ${validate_src} → ${validate_dest}"
  else
    warn "validate.sh not found at ${validate_src}; skipping timer install."
    return 0
  fi

  cat > /etc/systemd/system/hardening-validate.service <<'SVCEOF'
[Unit]
Description=Run hardening validation checks
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/validate-hardening
SVCEOF

  cat > /etc/systemd/system/hardening-validate.timer <<'TIMEREOF'
[Unit]
Description=Daily hardening validation

[Timer]
OnCalendar=daily
Persistent=true

[Install]
WantedBy=timers.target
TIMEREOF

  run systemctl daemon-reload
  run systemctl enable --now hardening-validate.timer
  log "hardening-validate.timer enabled (runs base/validate.sh daily)."
}
