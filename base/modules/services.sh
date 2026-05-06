disable_unused_services() {
  local services=(rpcbind avahi-daemon cups cups-browsed ModemManager udisks2 fwupd upower)
  local unit
  for svc in "${services[@]}"; do
    for unit in "${svc}.service" "${svc}.socket"; do
      if systemctl list-unit-files --no-legend "${unit}" 2>/dev/null | grep -q "${unit}"; then
        log "Disabling and masking ${unit}"
        run systemctl disable --now "${unit}" 2>/dev/null || true
        run systemctl mask "${unit}" 2>/dev/null || true
      fi
    done
  done
}

configure_apport() {
  if [[ -f "${APPORT_DEFAULT_FILE}" ]]; then
    if grep -qE '^[[:space:]]*enabled[[:space:]]*=' "${APPORT_DEFAULT_FILE}"; then
      run sed -i -E 's/^[[:space:]]*enabled[[:space:]]*=.*/enabled=0/' "${APPORT_DEFAULT_FILE}"
    else
      if is_true "${DRY_RUN}"; then
        log "DRY-RUN: append 'enabled=0' to ${APPORT_DEFAULT_FILE}"
      else
        printf '\nenabled=0\n' >> "${APPORT_DEFAULT_FILE}"
      fi
    fi
  else
    warn "${APPORT_DEFAULT_FILE} not found; skipping apport defaults update."
  fi

  if unit_available "apport.service"; then
    run systemctl disable --now apport.service
    run systemctl mask apport.service
    log "Apport disabled and masked."
  else
    log "apport.service not installed; skipping."
  fi
}

configure_cron_extra_opts() {
  if ! unit_available "cron.service"; then
    log "cron.service not installed; skipping EXTRA_OPTS normalization."
    return 0
  fi

  write_file "${CRON_EXTRA_OPTS_DROPIN}" "0644" "root" "root" <<'EOF'
[Service]
Environment="EXTRA_OPTS="
EOF

  run systemctl daemon-reload
  run systemctl restart cron
  log "cron.service EXTRA_OPTS environment normalized."
}

configure_networkd_wait_online() {
  if ! unit_available "systemd-networkd-wait-online.service"; then
    log "systemd-networkd-wait-online.service not installed; skipping wait-online tuning."
    return 0
  fi

  write_file "${NETWORKD_WAIT_ONLINE_DROPIN}" "0644" "root" "root" <<'EOF'
[Service]
ExecStart=
ExecStart=/lib/systemd/systemd-networkd-wait-online --any --timeout=15
EOF

  run systemctl daemon-reload

  if ifupdown_is_authoritative; then
    local -a stray_units=()
    unit_available "systemd-networkd.socket" && stray_units+=("systemd-networkd.socket")
    unit_available "systemd-networkd.service" && stray_units+=("systemd-networkd.service")
    unit_available "networkd-dispatcher.service" && stray_units+=("networkd-dispatcher.service")
    if (( ${#stray_units[@]} > 0 )); then
      run systemctl stop "${stray_units[@]}"
      run systemctl disable "${stray_units[@]}"
    fi
    log "ifupdown is authoritative; disabled stray systemd-networkd units to keep apt-helper wait-online on networking.service."
    return 0
  fi

  log "systemd-networkd-wait-online tuned for --any with 15s timeout."
}
