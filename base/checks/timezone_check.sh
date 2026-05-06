timezone_check() {
  local current_tz=""
  if command -v timedatectl >/dev/null 2>&1; then
    current_tz="$(timedatectl show --property=Timezone --value 2>/dev/null || true)"
  fi
  if [[ -z "${current_tz}" || "${current_tz}" == "n/a" ]]; then
    if [[ -f /etc/timezone ]]; then
      current_tz="$(tr -d '[:space:]' < /etc/timezone 2>/dev/null || true)"
    elif [[ -L /etc/localtime ]]; then
      current_tz="$(readlink /etc/localtime 2>/dev/null || true)"
      current_tz="${current_tz#*/zoneinfo/}"
    fi
  fi
  if [[ -z "${current_tz}" || "${current_tz}" == "n/a" ]]; then
    record "INFO" "timezone: current timezone" "unable to determine timezone from timedatectl or system files"
    return
  fi
  record "INFO" "timezone: current" "${current_tz}"

  if [[ -z "${CONFIGURED_TIMEZONE}" ]]; then
    record "INFO" "timezone: configured value" "state missing timezone; cannot verify expected value"
    return
  fi

  if [[ "${current_tz}" == "${CONFIGURED_TIMEZONE}" ]]; then
    record "PASS" "timezone: configured (${CONFIGURED_TIMEZONE})"
  else
    record "FAIL" "timezone: configured (${CONFIGURED_TIMEZONE})" \
      "current timezone is ${current_tz}"
  fi
}
