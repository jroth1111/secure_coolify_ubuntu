configure_ufw() {
  local cidr

  # Reconcile managed rules by comment to avoid an all-open fail window from `ufw reset`.
  if is_true "${DRY_RUN}"; then
    log "DRY-RUN: reconcile managed UFW rules (remove stale coolify-hardening-* rules)"
  else
    local ufw_numbered
    local managed_nums=()
    local line rule_num idx
    ufw_numbered="$(ufw status numbered 2>/dev/null || true)"
    while IFS= read -r line; do
      [[ "${line}" == *"coolify-hardening-"* ]] || continue
      rule_num="$(sed -n 's/^\[\([0-9]\+\)\].*/\1/p' <<< "${line}")"
      [[ -n "${rule_num}" ]] && managed_nums+=("${rule_num}")
    done <<< "${ufw_numbered}"
    for (( idx=${#managed_nums[@]}-1; idx>=0; idx-- )); do
      run ufw --force delete "${managed_nums[$idx]}"
    done
  fi

  run ufw default deny incoming
  run ufw default allow outgoing
  run ufw default deny routed

  run ufw allow in on "${TAILSCALE_IFACE}" proto tcp to any port "${SSH_PORT}" comment "coolify-hardening-ssh-tailscale"

  # Allow Coolify to SSH to the host from Docker bridge CIDRs.
  # Compatibility mode uses broad ranges; strict mode uses discovered bridge CIDRs.
  for cidr in "${DOCKER_SSH_CIDRS[@]}"; do
    run ufw allow in proto tcp from "${cidr}" to any port "${SSH_PORT}" comment "coolify-hardening-ssh-docker-bridge"
  done

  # Allow Coolify dashboard, Soketi, and terminal on Tailscale interface only.
  # UFW default deny blocks external access; these rules make them reachable via VPN.
  # 8000 = dashboard, 6001 = Soketi real-time, 6002 = terminal (required since beta.336)
  run ufw allow in on "${TAILSCALE_IFACE}" proto tcp to any port 8000 comment "coolify-hardening-dashboard-tailscale"
  run ufw allow in on "${TAILSCALE_IFACE}" proto tcp to any port 6001 comment "coolify-hardening-soketi-tailscale"
  run ufw allow in on "${TAILSCALE_IFACE}" proto tcp to any port 6002 comment "coolify-hardening-terminal-tailscale"

  if is_true "${TUNNEL_MODE}"; then
    log "Tunnel mode: skipping WAN 80/443 UFW rules (traffic arrives via outbound tunnel)."
  else
    run ufw allow in on "${WAN_IFACE}" proto tcp to any port 80 comment "coolify-hardening-http"
    run ufw allow in on "${WAN_IFACE}" proto tcp to any port 443 comment "coolify-hardening-https"
  fi

  if is_true "${TAILSCALE_DIRECT_WAN}"; then
    run ufw allow in on "${WAN_IFACE}" proto udp to any port 41641 comment "coolify-hardening-tailscale-direct"
  else
    log "Tailscale direct WAN optimization disabled: keeping WAN UDP 41641 closed (DERP fallback only)."
  fi

  # ICMP is allowed via UFW's default before.rules (ufw allow proto icmp is not supported)

  run ufw --force enable
}
