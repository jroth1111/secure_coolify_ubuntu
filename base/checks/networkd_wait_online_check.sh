networkd_wait_online_check() {
  local ifupdown_authoritative="false"
  if ifupdown_is_authoritative; then
    ifupdown_authoritative="true"
    record "PASS" "networkd-wait-online: ifupdown authoritative"
  fi

  if [[ "${ifupdown_authoritative}" == "true" ]]; then
    local -a stray_units=()
    unit_available "systemd-networkd.socket" && stray_units+=("systemd-networkd.socket")
    unit_available "systemd-networkd.service" && stray_units+=("systemd-networkd.service")
    unit_available "networkd-dispatcher.service" && stray_units+=("networkd-dispatcher.service")

    local unit active_state enabled_state
    local -a offenders=()
    for unit in "${stray_units[@]}"; do
      active_state="$(systemctl is-active "${unit}" 2>/dev/null || true)"
      enabled_state="$(systemctl is-enabled "${unit}" 2>/dev/null || true)"
      if [[ "${active_state}" != "inactive" || ( "${enabled_state}" != "disabled" && "${enabled_state}" != "masked" ) ]]; then
        offenders+=("${unit}(active=${active_state:-unknown},enabled=${enabled_state:-unknown})")
      fi
    done

    if (( ${#offenders[@]} == 0 )); then
      record "PASS" "networkd-wait-online: stray systemd-networkd stack disabled"
    else
      record "FAIL" "networkd-wait-online: stray systemd-networkd stack disabled" "${offenders[*]}"
    fi
  else
    if ! unit_available "systemd-networkd-wait-online.service"; then
      record "INFO" "networkd-wait-online: service" "not installed"
    else
      if [[ -f "${NETWORKD_WAIT_ONLINE_DROPIN}" ]] \
        && grep -Eq '^[[:space:]]*ExecStart=/lib/systemd/systemd-networkd-wait-online --any --timeout=15[[:space:]]*$' "${NETWORKD_WAIT_ONLINE_DROPIN}"; then
        record "PASS" "networkd-wait-online: drop-in present (--any --timeout=15)"
      else
        record "FAIL" "networkd-wait-online: drop-in present" "missing/invalid ${NETWORKD_WAIT_ONLINE_DROPIN}"
      fi

      local exec_start
      exec_start="$(systemctl show systemd-networkd-wait-online.service -p ExecStart --value 2>/dev/null || true)"
      if [[ "${exec_start}" == *"--any"* && "${exec_start}" == *"--timeout=15"* ]]; then
        record "PASS" "networkd-wait-online: effective ExecStart tuned"
      else
        record "FAIL" "networkd-wait-online: effective ExecStart tuned" "expected --any --timeout=15, got ${exec_start:-unknown}"
      fi
    fi
  fi

  if [[ -x "${APT_HELPER_BIN}" ]] && command -v timeout >/dev/null 2>&1; then
    if timeout 20 "${APT_HELPER_BIN}" wait-online >/dev/null 2>&1; then
      record "PASS" "networkd-wait-online: apt-helper wait-online succeeds"
    else
      record "FAIL" "networkd-wait-online: apt-helper wait-online succeeds" "current provider timed out or failed"
    fi
  else
    record "INFO" "networkd-wait-online: apt-helper runtime check" "timeout or ${APT_HELPER_BIN} unavailable"
  fi
}
