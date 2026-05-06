coolify_binding_check() {
  # Skip if binding restriction was not configured
  if ! is_true "${BIND_DASHBOARD_TO_TAILSCALE}"; then
    record "INFO" "coolify: dashboard UFW restriction" "not configured (use --bind-dashboard-to-tailscale)"
    return 0
  fi

  # Dashboard Tailscale restriction is enforced via UFW rules on tailscale0, not by
  # socket binding (APP_PORT=IP:port breaks Coolify's expose: directive). Check UFW rules.

  if ! command -v ufw >/dev/null 2>&1; then
    record "FAIL" "coolify: ufw" "ufw command not found"
    return 0
  fi

  local ufw_out
  ufw_out="$(ufw status 2>/dev/null)" || true

  # Check UFW rule for port 8000 on tailscale0
  if echo "${ufw_out}" | grep -q "8000.*on ${TAILSCALE_IFACE}"; then
    record "PASS" "coolify: UFW rule port 8000 on ${TAILSCALE_IFACE}"
  else
    record "FAIL" "coolify: UFW rule port 8000" "rule for port 8000 on ${TAILSCALE_IFACE} missing"
  fi

  # Check UFW rule for port 6001 on tailscale0
  if echo "${ufw_out}" | grep -q "6001.*on ${TAILSCALE_IFACE}"; then
    record "PASS" "coolify: UFW rule port 6001 on ${TAILSCALE_IFACE}"
  else
    record "INFO" "coolify: UFW rule port 6001" "rule for port 6001 on ${TAILSCALE_IFACE} missing (Soketi may not be in use)"
  fi

  # Check UFW rule for port 6002 on tailscale0
  if echo "${ufw_out}" | grep -q "6002.*on ${TAILSCALE_IFACE}"; then
    record "PASS" "coolify: UFW rule port 6002 on ${TAILSCALE_IFACE}"
  else
    record "INFO" "coolify: UFW rule port 6002" "rule for port 6002 on ${TAILSCALE_IFACE} missing (terminal may not be in use)"
  fi

  # Check port 8000 is listening (any address — UFW restricts which interfaces can reach it)
  local bound_8000
  bound_8000="$(ss -tlnp 2>/dev/null | grep ':8000 ' || true)"
  if [[ -n "${bound_8000}" ]]; then
    record "PASS" "coolify: port 8000 listening"
  else
    record "INFO" "coolify: port 8000" "not yet listening (Coolify may still be starting)"
  fi

  # Note: nc-based self-connect tests cannot validate public exposure — the kernel
  # routes server→own-public-IP locally, bypassing UFW INPUT rules entirely.
  # Public port exposure is validated via UFW rule inspection in ufw_check() instead.
  # External connectivity tests (Gate E/F in deploy.sh) verify from the operator machine.

  # Verify UFW binding-guard timer is active (periodically re-applies UFW rules if removed)
  if systemctl is-active --quiet coolify-binding-guard.timer 2>/dev/null; then
    record "PASS" "coolify: UFW binding-guard timer active"
  else
    record "FAIL" "coolify: UFW binding-guard timer" "not active — UFW rule drift may go undetected"
  fi
}

