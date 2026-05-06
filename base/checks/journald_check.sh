journald_check() {
  if [[ -f "${JOURNALD_DROPIN}" ]] && grep -q "^Storage=persistent$" "${JOURNALD_DROPIN}"; then
    record "PASS" "journald: persistent storage config"
  else
    record "FAIL" "journald: persistent storage config" "drop-in missing or not persistent"
  fi

  # Verify persistent storage directory exists (journald creates /var/log/journal when Storage=persistent)
  if [[ -d /var/log/journal ]]; then
    record "PASS" "journald: /var/log/journal directory exists"
  else
    record "FAIL" "journald: /var/log/journal" "directory missing — persistent storage not active"
  fi

  if [[ -f "${JOURNALD_DROPIN}" ]] && grep -q "^SystemKeepFree=500M$" "${JOURNALD_DROPIN}"; then
    record "PASS" "journald: keep-free policy"
  else
    record "FAIL" "journald: keep-free policy" "SystemKeepFree=500M missing"
  fi

  local usage
  usage="$(journalctl --disk-usage 2>/dev/null | head -1)" || true
  if [[ -n "${usage}" ]]; then
    record "INFO" "journald: disk usage" "${usage}"
  fi
}
