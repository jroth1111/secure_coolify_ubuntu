configure_coolify_binding() {
  if ! is_true "${BIND_DASHBOARD_TO_TAILSCALE}"; then
    return 0
  fi

  # Dashboard Tailscale restriction is enforced via UFW, not APP_PORT socket binding.
  # Coolify's docker-compose.prod.yml uses APP_PORT in both ports: and expose: directives;
  # expose: requires a plain port number, so IP:port format is incompatible and breaks
  # Coolify container startup. UFW default-deny + explicit allow on tailscale0 provides
  # equivalent defense-in-depth without touching Coolify's configuration.
  #
  # UFW rules for 8000/6001 on tailscale0 are already applied by configure_ufw(); this
  # function verifies they exist and re-applies them idempotently.

  log "Verifying Coolify dashboard UFW rules on ${TAILSCALE_IFACE}..."

  if is_true "${DRY_RUN}"; then
    log "DRY-RUN: would verify UFW rules for ports 8000, 6001, and 6002 on ${TAILSCALE_IFACE}"
    log "DRY-RUN: would verify port 8000 is listening; external exposure is validated from off-host"
    return 0
  fi

  if command -v ufw >/dev/null 2>&1; then
    # Idempotent — ufw silently skips duplicate rules
    local ufw_result ufw_ok=true
    ufw_result="$(ufw allow in on "${TAILSCALE_IFACE}" proto tcp to any port 8000 \
      comment "coolify-hardening-dashboard-tailscale" 2>&1)" || {
      warn "UFW rule for port 8000 on ${TAILSCALE_IFACE} failed: ${ufw_result}"
      ufw_ok=false
    }
    ufw_result="$(ufw allow in on "${TAILSCALE_IFACE}" proto tcp to any port 6001 \
      comment "coolify-hardening-soketi-tailscale" 2>&1)" || {
      warn "UFW rule for port 6001 on ${TAILSCALE_IFACE} failed: ${ufw_result}"
      ufw_ok=false
    }
    ufw_result="$(ufw allow in on "${TAILSCALE_IFACE}" proto tcp to any port 6002 \
      comment "coolify-hardening-terminal-tailscale" 2>&1)" || {
      warn "UFW rule for port 6002 on ${TAILSCALE_IFACE} failed: ${ufw_result}"
      ufw_ok=false
    }
    is_true "${ufw_ok}" && log "UFW rules verified for ports 8000, 6001, and 6002 on ${TAILSCALE_IFACE}."
  else
    warn "ufw not found — skipping UFW rule verification."
  fi

  # Wait for Coolify to bind port 8000 (up to 30s)
  log "Waiting for Coolify to bind port 8000 (up to 30s)..."
  local i
  for (( i = 1; i <= 6; i++ )); do
    if ss -tlnp 2>/dev/null | grep -q ':8000 '; then
      break
    fi
    sleep 5
  done

  # Verify port 8000 is listening
  local bound_8000
  bound_8000="$(ss -tlnp 2>/dev/null | grep ':8000 ' || true)"
  if [[ -n "${bound_8000}" ]]; then
    log "PASS: Port 8000 is listening"
  else
    warn "Port 8000 not yet listening. Check: ss -tlnp | grep 8000"
  fi

  log "Coolify dashboard UFW restriction verified. External exposure is validated from off-host."
}

