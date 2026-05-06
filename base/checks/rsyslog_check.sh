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

rsyslog_check() {
  local mode owner group group_digit
  local target q_target target_owner target_group target_mode
  local target_count=0
  local expected_dir_group="syslog"
  local expected_target_owner="syslog"
  local expected_target_group="adm"
  local rsyslog_service_loaded="false"

  if ! getent group syslog >/dev/null 2>&1; then
    expected_dir_group="root"
  fi
  if ! getent passwd syslog >/dev/null 2>&1; then
    expected_target_owner="root"
  fi
  if ! getent group "${expected_target_group}" >/dev/null 2>&1; then
    if getent group syslog >/dev/null 2>&1; then
      expected_target_group="syslog"
    else
      expected_target_group="root"
    fi
  fi
  if systemctl show -p LoadState --value rsyslog 2>/dev/null | grep -qx 'loaded'; then
    rsyslog_service_loaded="true"
  fi

  owner="$(stat -c '%U' /var/log 2>/dev/null || true)"
  group="$(stat -c '%G' /var/log 2>/dev/null || true)"
  mode="$(stat -c '%a' /var/log 2>/dev/null || true)"

  if [[ "${owner}" == "root" && "${group}" == "${expected_dir_group}" ]]; then
    record "PASS" "rsyslog: /var/log owner/group"
  else
    record "FAIL" "rsyslog: /var/log owner/group" \
      "expected root:${expected_dir_group}, got ${owner:-unknown}:${group:-unknown}"
  fi

  if [[ "${mode}" =~ ^[0-7]{3,4}$ ]]; then
    if [[ "${expected_dir_group}" == "syslog" ]]; then
      group_digit="${mode: -2:1}"
      if (( (10#${group_digit} & 2) != 0 )); then
        record "PASS" "rsyslog: /var/log group-write enabled"
      else
        record "FAIL" "rsyslog: /var/log group-write" \
          "mode ${mode} lacks group write; rsyslog cannot create missing targets"
      fi
    else
      record "INFO" "rsyslog: /var/log group-write" \
        "not required when syslog group is unavailable"
    fi
  else
    record "FAIL" "rsyslog: /var/log mode" "unreadable (${mode:-unknown})"
  fi

  while IFS= read -r target; do
    [[ -n "${target}" ]] || continue
    ((++target_count))
    if [[ -f "${target}" ]]; then
      record "PASS" "rsyslog: target exists (${target})"
      target_owner="$(stat -c '%U' "${target}" 2>/dev/null || true)"
      target_group="$(stat -c '%G' "${target}" 2>/dev/null || true)"
      target_mode="$(stat -c '%a' "${target}" 2>/dev/null || true)"
      if [[ "${target_owner}" == "${expected_target_owner}" && "${target_group}" == "${expected_target_group}" && "${target_mode}" == "640" ]]; then
        record "PASS" "rsyslog: target ownership (${target})"
      else
        record "FAIL" "rsyslog: target ownership (${target})" \
          "expected ${expected_target_owner}:${expected_target_group} mode 640, got ${target_owner:-unknown}:${target_group:-unknown} mode ${target_mode:-unknown}"
      fi
      printf -v q_target '%q' "${target}"
      if getent passwd syslog >/dev/null 2>&1; then
        if su -s /bin/sh -c "test -w ${q_target}" syslog >/dev/null 2>&1; then
          record "PASS" "rsyslog: target writable by syslog (${target})"
        else
          record "FAIL" "rsyslog: target writable by syslog (${target})" "permission denied"
        fi
      else
        record "INFO" "rsyslog: target writable by syslog (${target})" "syslog user unavailable; ownership fallback in effect"
      fi
    else
      record "FAIL" "rsyslog: target exists (${target})" "missing"
    fi
  done < <(rsyslog_collect_log_targets)

  if (( target_count == 0 )); then
    record "INFO" "rsyslog: configured /var/log targets" "none found in rsyslog config"
  fi

  if [[ -f /etc/logrotate.d/rsyslog ]] \
    && grep -Eq "^[[:space:]]*create[[:space:]]+640[[:space:]]+${expected_target_owner}[[:space:]]+${expected_target_group}([[:space:]]|$)" /etc/logrotate.d/rsyslog; then
    record "PASS" "rsyslog: logrotate create directive"
  elif [[ ! -f /etc/logrotate.d/rsyslog ]]; then
    record "INFO" "rsyslog: logrotate create directive" "/etc/logrotate.d/rsyslog missing; rsyslog package may be absent"
  else
    record "FAIL" "rsyslog: logrotate create directive" \
      "missing in /etc/logrotate.d/rsyslog (expected create 640 ${expected_target_owner} ${expected_target_group})"
  fi

  if [[ -f /etc/logrotate.d/ufw ]] \
    && grep -Eq "^[[:space:]]*create[[:space:]]+640[[:space:]]+${expected_target_owner}[[:space:]]+${expected_target_group}([[:space:]]|$)" /etc/logrotate.d/ufw; then
    record "PASS" "rsyslog: ufw logrotate create directive"
  else
    record "FAIL" "rsyslog: ufw logrotate create directive" \
      "missing in /etc/logrotate.d/ufw (expected create 640 ${expected_target_owner} ${expected_target_group})"
  fi

  if [[ "${rsyslog_service_loaded}" == "true" ]] && systemctl is-active --quiet rsyslog 2>/dev/null; then
    record "PASS" "rsyslog: service active"
  elif [[ "${rsyslog_service_loaded}" != "true" ]]; then
    record "INFO" "rsyslog: service active" "service not running (unit absent)"
  else
    record "FAIL" "rsyslog: service active" "service not running"
  fi

  local active_since
  active_since="$(systemctl show -p ActiveEnterTimestamp --value rsyslog 2>/dev/null || true)"
  if [[ -n "${active_since}" ]]; then
    if journalctl -u rsyslog --since "${active_since}" --no-pager -o cat 2>/dev/null \
      | grep -Eq 'suspended \(module '\''builtin:omfile'\''\)|Permission denied|open error|e/2007|e/2433'; then
      record "FAIL" "rsyslog: runtime log-write health" \
        "omfile suspend/permission errors present since last restart"
    else
      record "PASS" "rsyslog: runtime log-write health"
    fi
  else
    record "INFO" "rsyslog: runtime log-write health" "unable to determine service activation timestamp"
  fi
}
