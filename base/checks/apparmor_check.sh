apparmor_check() {
  if command -v aa-status >/dev/null 2>&1; then
    if aa-status --enabled 2>/dev/null; then
      record "PASS" "apparmor: enabled"
    elif [[ "${IS_CONTAINER}" == "true" ]]; then
      record "INFO" "apparmor: status" "cannot verify in container"
    else
      record "FAIL" "apparmor: enabled" "AppArmor not enabled"
    fi
  elif [[ "${IS_CONTAINER}" == "true" ]]; then
    record "INFO" "apparmor: status" "cannot check in container"
  else
    record "FAIL" "apparmor: aa-status" "command not found"
  fi
}
