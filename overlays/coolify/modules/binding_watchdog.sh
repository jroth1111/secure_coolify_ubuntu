configure_coolify_binding_watchdog() {
  if ! is_true "${BIND_DASHBOARD_TO_TAILSCALE}"; then
    return 0
  fi

  write_file "${COOLIFY_BINDING_GUARD_SCRIPT}" "0750" "root" "root" <<'GUARD_EOF'
#!/usr/bin/env bash
# Coolify dashboard UFW binding guard.
# Verifies that UFW rules restricting the Coolify dashboard (port 8000), Soketi
# (port 6001), and terminal (port 6002) to the tailscale0 interface exist, and
# re-applies them if missing.
# Does NOT modify Coolify's .env — security is enforced entirely by UFW.
set -Euo pipefail

TAILSCALE_IFACE="tailscale0"
LOG_TAG="coolify-binding-guard"

log() { logger -t "${LOG_TAG}" -- "$*"; }

command -v ufw >/dev/null 2>&1 || { log "ufw not found; skipping."; exit 0; }

ufw_status="$(ufw status 2>/dev/null | head -1)" || true
[[ "${ufw_status}" == "Status: active" ]] || { log "UFW not active; skipping."; exit 0; }

changed=false

# Check and re-apply UFW rule for port 8000 on tailscale0
if ! ufw status | grep -q "8000.*on ${TAILSCALE_IFACE}"; then
  log "UFW rule for port 8000 on ${TAILSCALE_IFACE} missing — re-applying."
  ufw allow in on "${TAILSCALE_IFACE}" proto tcp to any port 8000 \
    comment "coolify-hardening-dashboard-tailscale" 2>/dev/null || true
  changed=true
fi

# Check and re-apply UFW rule for port 6001 on tailscale0
if ! ufw status | grep -q "6001.*on ${TAILSCALE_IFACE}"; then
  log "UFW rule for port 6001 on ${TAILSCALE_IFACE} missing — re-applying."
  ufw allow in on "${TAILSCALE_IFACE}" proto tcp to any port 6001 \
    comment "coolify-hardening-soketi-tailscale" 2>/dev/null || true
  changed=true
fi

# Check and re-apply UFW rule for port 6002 on tailscale0
if ! ufw status | grep -q "6002.*on ${TAILSCALE_IFACE}"; then
  log "UFW rule for port 6002 on ${TAILSCALE_IFACE} missing — re-applying."
  ufw allow in on "${TAILSCALE_IFACE}" proto tcp to any port 6002 \
    comment "coolify-hardening-terminal-tailscale" 2>/dev/null || true
  changed=true
fi

if "${changed}"; then
  log "UFW rules re-applied for ports 8000, 6001, and 6002 on ${TAILSCALE_IFACE}."
else
  log "UFW rules for ports 8000, 6001, and 6002 on ${TAILSCALE_IFACE} are present — no action needed."
fi
GUARD_EOF

  write_file "${COOLIFY_BINDING_GUARD_SERVICE}" "0644" "root" "root" <<'UNIT_EOF'
[Unit]
Description=Verify Coolify dashboard UFW rules on tailscale0 are present
After=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/coolify-binding-guard.sh
UNIT_EOF

  write_file "${COOLIFY_BINDING_GUARD_TIMER}" "0644" "root" "root" <<'TIMER_EOF'
[Unit]
Description=Periodically verify Coolify dashboard UFW rules on tailscale0

[Timer]
OnBootSec=2min
OnUnitActiveSec=5min
AccuracySec=30s

[Install]
WantedBy=timers.target
TIMER_EOF

  run systemctl daemon-reload
  run systemctl enable --now coolify-binding-guard.timer
  log "Coolify binding watchdog enabled (checks every 5 minutes)."
}

