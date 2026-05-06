cron_check() {
  if ! unit_available "cron.service"; then
    record "INFO" "cron: service" "not installed"
    return 0
  fi

  local cron_env
  cron_env="$(systemctl show cron.service -p Environment --value 2>/dev/null || true)"
  if [[ "${cron_env}" =~ (^|[[:space:]])EXTRA_OPTS= ]]; then
    record "PASS" "cron: EXTRA_OPTS environment set"
  else
    record "FAIL" "cron: EXTRA_OPTS environment set" "missing Environment override (expected ${CRON_EXTRA_OPTS_DROPIN})"
  fi

  if command -v journalctl >/dev/null 2>&1; then
    local active_since unset_count
    active_since="$(systemctl show cron.service -p ActiveEnterTimestamp --value 2>/dev/null || true)"
    unset_count="$(journalctl -u cron --since "${active_since:-now}" --no-pager 2>/dev/null \
      | grep -c 'Referenced but unset environment variable evaluates to an empty string: EXTRA_OPTS' || true)"
    if [[ "${unset_count}" =~ ^[0-9]+$ && "${unset_count}" -eq 0 ]]; then
      record "PASS" "cron: no EXTRA_OPTS unset warnings after last start"
    else
      record "FAIL" "cron: no EXTRA_OPTS unset warnings after last start" "found ${unset_count:-unknown} warning(s)"
    fi
  else
    record "INFO" "cron: warning scan" "journalctl not available"
  fi
}
