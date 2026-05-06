apport_check() {
  if [[ -f "${APPORT_DEFAULT_FILE}" ]]; then
    local apport_enabled
    apport_enabled="$(awk -F= '/^[[:space:]]*enabled[[:space:]]*=/{gsub(/[[:space:]]/, "", $2); print $2; exit}' "${APPORT_DEFAULT_FILE}" || true)"
    if [[ "${apport_enabled}" == "0" ]]; then
      record "PASS" "apport: enabled=0"
    else
      record "FAIL" "apport: enabled" "expected 0, got ${apport_enabled:-<unset>}"
    fi
  else
    record "INFO" "apport: defaults file" "${APPORT_DEFAULT_FILE} missing"
  fi

  if systemctl list-unit-files --no-legend apport.service 2>/dev/null | grep -q "^apport\\.service"; then
    if systemctl is-active --quiet apport.service 2>/dev/null; then
      record "FAIL" "apport: service active" "apport.service is running"
    else
      record "PASS" "apport: service inactive"
    fi

    local state
    state="$(systemctl is-enabled apport.service 2>/dev/null || true)"
    if [[ "${state}" == "masked" || "${state}" == "disabled" ]]; then
      record "PASS" "apport: service disabled/masked (${state})"
    else
      record "FAIL" "apport: service enabled state" "expected masked/disabled, got ${state:-unknown}"
    fi
  else
    record "INFO" "apport: service" "not installed"
  fi
}
