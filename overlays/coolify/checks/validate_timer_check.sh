validate_timer_check() {
  if systemctl is-active --quiet hardening-validate.timer 2>/dev/null; then
    record "PASS" "validate-timer: active"
  elif systemctl list-unit-files --no-legend hardening-validate.timer 2>/dev/null | grep -q hardening-validate; then
    record "FAIL" "validate-timer: active" "timer installed but not active"
  else
    record "INFO" "validate-timer: not installed" "run bootstrap to install"
  fi
}

