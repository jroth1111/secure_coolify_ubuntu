auditd_check() {
  if systemctl is-active --quiet auditd 2>/dev/null; then
    record "PASS" "auditd: active"
  elif [[ "${IS_CONTAINER}" == "true" ]]; then
    record "INFO" "auditd: active" "not active in container test environment"
  else
    record "FAIL" "auditd: active" "service not running"
    return
  fi

  local rules
  rules="$(auditctl -l 2>/dev/null)" || { record "FAIL" "auditd: rules" "cannot list"; return; }

  if grep -q "identity" <<< "${rules}"; then
    record "PASS" "auditd: identity rules loaded"
  else
    record "FAIL" "auditd: identity rules" "not loaded"
  fi

  if grep -q "sudoers-change" <<< "${rules}"; then
    record "PASS" "auditd: sudoers rules loaded"
  else
    record "FAIL" "auditd: sudoers rules" "not loaded"
  fi

  if grep -q "kernel-module" <<< "${rules}"; then
    record "PASS" "auditd: kernel-module rules loaded"
  else
    record "FAIL" "auditd: kernel-module rules" "not loaded"
  fi

  if grep -q "user_commands" <<< "${rules}"; then
    record "PASS" "auditd: user_commands execve rules loaded"
  else
    record "FAIL" "auditd: user_commands execve rules" "not loaded"
  fi

  if [[ -f "${AUDITD_CONF}" ]]; then
    if grep -qE '^[[:space:]]*max_log_file_action[[:space:]]*=[[:space:]]*keep_logs' "${AUDITD_CONF}"; then
      record "PASS" "auditd: max_log_file_action=keep_logs"
    else
      record "FAIL" "auditd: max_log_file_action" "expected keep_logs in ${AUDITD_CONF}"
    fi

    if grep -qE '^[[:space:]]*disk_full_action[[:space:]]*=[[:space:]]*suspend' "${AUDITD_CONF}" \
      && grep -qE '^[[:space:]]*disk_error_action[[:space:]]*=[[:space:]]*suspend' "${AUDITD_CONF}"; then
      record "PASS" "auditd: disk failure actions configured"
    else
      record "FAIL" "auditd: disk failure actions" "expected disk_full_action/disk_error_action=suspend"
    fi

    local space_left space_left_action admin_space_left admin_space_left_action
    space_left="$(grep -E '^[[:space:]]*space_left[[:space:]]*=' "${AUDITD_CONF}" | tail -1 | sed 's/.*=[[:space:]]*//')"
    space_left_action="$(grep -E '^[[:space:]]*space_left_action[[:space:]]*=' "${AUDITD_CONF}" | tail -1 | sed 's/.*=[[:space:]]*//')"
    if [[ "${space_left:-0}" =~ ^[0-9]+$ ]] && (( space_left > 0 )) && [[ "${space_left_action}" == "syslog" ]]; then
      record "PASS" "auditd: space_left=${space_left}, space_left_action=syslog"
    else
      record "FAIL" "auditd: space_left thresholds" "expected space_left>0 and space_left_action=syslog"
    fi

    admin_space_left="$(grep -E '^[[:space:]]*admin_space_left[[:space:]]*=' "${AUDITD_CONF}" | tail -1 | sed 's/.*=[[:space:]]*//')"
    admin_space_left_action="$(grep -E '^[[:space:]]*admin_space_left_action[[:space:]]*=' "${AUDITD_CONF}" | tail -1 | sed 's/.*=[[:space:]]*//')"
    if [[ "${admin_space_left:-0}" =~ ^[0-9]+$ ]] && (( admin_space_left > 0 )) && [[ "${admin_space_left_action}" == "suspend" ]]; then
      record "PASS" "auditd: admin_space_left=${admin_space_left}, admin_space_left_action=suspend"
    else
      record "FAIL" "auditd: admin_space_left thresholds" "expected admin_space_left>0 and admin_space_left_action=suspend"
    fi
  else
    record "INFO" "auditd: policy config" "${AUDITD_CONF} not found"
  fi

  local audit_status lost backlog
  audit_status="$(auditctl -s 2>/dev/null || true)"
  if [[ -n "${audit_status}" ]]; then
    lost="$(awk '/^lost[[:space:]]/ {print $2; exit}' <<< "${audit_status}")"
    backlog="$(awk '/^backlog[[:space:]]/ {print $2; exit}' <<< "${audit_status}")"
    if [[ "${lost:-0}" =~ ^[0-9]+$ ]] && [[ "${lost}" == "0" ]]; then
      record "PASS" "auditd: queue loss (lost=0)"
    elif [[ "${lost:-}" =~ ^[0-9]+$ ]] && (( lost > 100 )); then
      record "FAIL" "auditd: queue loss" "lost=${lost} (>100 events dropped)"
    elif [[ "${lost:-}" =~ ^[0-9]+$ ]]; then
      record "INFO" "auditd: queue loss" "lost=${lost} (minor — below threshold)"
    else
      record "INFO" "auditd: queue loss" "unable to parse 'lost' from auditctl -s"
    fi
    [[ -n "${backlog}" ]] && record "INFO" "auditd: backlog" "backlog=${backlog}"
  else
    record "INFO" "auditd: queue status" "auditctl -s unavailable"
  fi
}
