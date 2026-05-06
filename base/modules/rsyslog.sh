rsyslog_collect_log_targets() {
  local cfg
  local -a cfgs=()

  [[ -f /etc/rsyslog.conf ]] && cfgs+=("/etc/rsyslog.conf")
  for cfg in /etc/rsyslog.d/*.conf; do
    [[ -f "${cfg}" ]] || continue
    cfgs+=("${cfg}")
  done

  ((${#cfgs[@]} > 0)) || return 0

  awk '
    /^[[:space:]]*#/ { next }
    {
      for (i = 1; i <= NF; i++) {
        tok = $i
        if (tok ~ /^-?\/var\/log\//) {
          sub(/^-/, "", tok)
          sub(/[;,]+$/, "", tok)
          print tok
        }
      }
    }
  ' "${cfgs[@]}" | sort -u
}

ensure_logrotate_create_directive() {
  local file="$1"
  local log_owner="syslog"
  local log_group="$2"
  if [[ $# -ge 3 ]]; then
    log_owner="$2"
    log_group="$3"
  fi
  local create_line="create 640 ${log_owner} ${log_group}"

  if [[ ! -f "${file}" ]]; then
    warn "Logrotate file ${file} not found; skipping create directive check."
    return 0
  fi

  if grep -Eq "^[[:space:]]*create[[:space:]]+640[[:space:]]+${log_owner}[[:space:]]+${log_group}([[:space:]]|$)" "${file}"; then
    return 0
  fi

  if is_true "${DRY_RUN}"; then
    log "DRY-RUN: add '${create_line}' to ${file}"
    return 0
  fi

  if grep -qE '^[[:space:]]*delaycompress[[:space:]]*$' "${file}"; then
    sed -i "/^[[:space:]]*delaycompress[[:space:]]*$/a\\\t${create_line}" "${file}"
    return 0
  fi

  if grep -qE '^[[:space:]]*compress[[:space:]]*$' "${file}"; then
    sed -i "/^[[:space:]]*compress[[:space:]]*$/a\\\t${create_line}" "${file}"
    return 0
  fi

  if grep -qE '^[[:space:]]*sharedscripts[[:space:]]*$' "${file}"; then
    sed -i "/^[[:space:]]*sharedscripts[[:space:]]*$/i\\\t${create_line}" "${file}"
    return 0
  fi

  sed -i "/^[[:space:]]*}[[:space:]]*$/i\\\t${create_line}" "${file}"
}

configure_rsyslog_targets() {
  local target
  local log_owner="syslog"
  local log_group="adm"

  if ! getent passwd "${log_owner}" >/dev/null 2>&1; then
    warn "User '${log_owner}' not found; using fallback owner root for managed log files."
    log_owner="root"
  fi

  if ! getent group "${log_group}" >/dev/null 2>&1; then
    if getent group syslog >/dev/null 2>&1; then
      log_group="syslog"
    else
      warn "Neither 'adm' nor 'syslog' group found; using fallback group root for managed log files."
      log_group="root"
    fi
  fi

  if getent group syslog >/dev/null 2>&1; then
    if is_true "${DRY_RUN}"; then
      log "DRY-RUN: ensure /var/log is root:syslog mode 0770"
    else
      install -d -m 0770 -o root -g syslog /var/log
    fi
  else
    warn "Group 'syslog' not found; skipping /var/log ownership enforcement."
  fi

  while IFS= read -r target; do
    [[ -n "${target}" ]] || continue
    if is_true "${DRY_RUN}"; then
      log "DRY-RUN: ensure ${target} exists (0640 ${log_owner}:${log_group})"
      continue
    fi
    local target_dir
    target_dir="$(dirname "${target}")"
    if [[ ! -d "${target_dir}" ]]; then
      install -d -m 0755 "${target_dir}"
    fi
    touch "${target}"
    chown "${log_owner}:${log_group}" "${target}"
    chmod 0640 "${target}"
  done < <(rsyslog_collect_log_targets)

  ensure_logrotate_create_directive "/etc/logrotate.d/ufw" "${log_owner}" "${log_group}"
  ensure_logrotate_create_directive "/etc/logrotate.d/rsyslog" "${log_owner}" "${log_group}"

  if unit_available "rsyslog.service"; then
    run systemctl restart rsyslog
  else
    warn "rsyslog.service not found; skipping restart."
  fi
}
