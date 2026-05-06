tailscale_check() {
  if ip link show "${TAILSCALE_IFACE}" >/dev/null 2>&1; then
    record "PASS" "tailscale: ${TAILSCALE_IFACE} present"
  else
    record "FAIL" "tailscale: ${TAILSCALE_IFACE}" "interface not found"
    return
  fi

  if unit_available "tailscaled.service"; then
    local notify_access
    notify_access="$(systemctl show tailscaled.service -p NotifyAccess --value 2>/dev/null || true)"
    if [[ "${notify_access}" == "all" ]]; then
      record "PASS" "tailscale: tailscaled NotifyAccess=all"
    else
      record "FAIL" "tailscale: tailscaled NotifyAccess" "expected all, got ${notify_access:-unknown}"
    fi

    if [[ -f "${TAILSCALED_NOTIFY_DROPIN}" ]] && grep -Eq '^[[:space:]]*NotifyAccess[[:space:]]*=[[:space:]]*all[[:space:]]*$' "${TAILSCALED_NOTIFY_DROPIN}"; then
      record "PASS" "tailscale: NotifyAccess drop-in present"
    else
      record "FAIL" "tailscale: NotifyAccess drop-in" "missing/invalid ${TAILSCALED_NOTIFY_DROPIN}"
    fi
  else
    record "INFO" "tailscale: tailscaled service" "unit not installed"
  fi

  # Check actual connection state via tailscale CLI (not just interface presence).
  # Interface can exist while the daemon is in a broken/logged-out state.
  if command -v tailscale >/dev/null 2>&1; then
    local ts_state
    ts_state="$(tailscale status --json 2>/dev/null \
      | jq -r '.BackendState // "unknown"' \
      2>/dev/null || echo "unknown")"
    if [[ "${ts_state}" == "Running" ]]; then
      record "PASS" "tailscale: BackendState=Running"
    else
      record "FAIL" "tailscale: BackendState" "expected Running, got ${ts_state}"
    fi

    # Check that a Tailscale IPv4 (100.x) has actually been assigned
    local ts_ip
    ts_ip="$(tailscale ip -4 2>/dev/null || true)"
    if [[ -n "${ts_ip}" ]]; then
      record "PASS" "tailscale: IPv4 assigned (${ts_ip})"
    else
      record "FAIL" "tailscale: IPv4 address" "no Tailscale IPv4 — check auth key and login state"
    fi

    local run_ssh_pref
    run_ssh_pref="$(tailscale_runssh_pref_value 5 1)"
    if [[ "${run_ssh_pref}" == "false" ]]; then
      record "PASS" "tailscale: RunSSH=false"
    elif [[ "${run_ssh_pref}" == "unknown" ]]; then
      record "FAIL" "tailscale: RunSSH" "expected false, got unknown after retries"
    else
      record "FAIL" "tailscale: RunSSH" "expected false, got ${run_ssh_pref}"
    fi

    local direct_count relay_count
    direct_count="$(tailscale status --json 2>/dev/null | jq -r '[.Peer[]? | select((.CurAddr // "") != "" and ((.Relay // "") == ""))] | length' 2>/dev/null || echo "")"
    relay_count="$(tailscale status --json 2>/dev/null | jq -r '[.Peer[]? | select((.Relay // "") != "")] | length' 2>/dev/null || echo "")"
    if [[ "${direct_count}" =~ ^[0-9]+$ && "${relay_count}" =~ ^[0-9]+$ ]]; then
      record "INFO" "tailscale: peer path summary" "direct=${direct_count}, relay=${relay_count}"
    else
      record "INFO" "tailscale: peer path summary" "unable to parse direct/relay counts"
    fi

    if command -v journalctl >/dev/null 2>&1 && unit_available "tailscaled.service"; then
      local ts_active_since ts_notify_warn_count
      ts_active_since="$(systemctl show tailscaled.service -p ActiveEnterTimestamp --value 2>/dev/null || true)"
      ts_notify_warn_count="$(journalctl -u tailscaled --since "${ts_active_since:-now}" --no-pager 2>/dev/null \
        | grep -Ec 'Got notification message from PID .*reception only permitted for main PID|Cannot find unit for notify message of PID .*, ignoring\.' || true)"
      if [[ "${ts_notify_warn_count}" =~ ^[0-9]+$ && "${ts_notify_warn_count}" -eq 0 ]]; then
        record "PASS" "tailscale: no systemd notify warnings after last start"
      else
        record "FAIL" "tailscale: no systemd notify warnings after last start" "found ${ts_notify_warn_count:-unknown} warning(s)"
      fi
    fi
  else
    record "INFO" "tailscale: CLI" "tailscale binary not found; skipping state/IP checks"
  fi
}
