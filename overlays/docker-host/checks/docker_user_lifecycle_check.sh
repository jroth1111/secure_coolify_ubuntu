docker_user_lifecycle_check() {
  local unit_file="/etc/systemd/system/docker-user-hardening.service"
  if [[ ! -f "${unit_file}" ]]; then
    if docker_hardening_expected; then
      record "FAIL" "docker-user: unit file" "not found at ${unit_file}"
    else
      record "INFO" "docker-user: unit file" "Docker hardening not yet expected; skipped"
    fi
    return
  fi

  if grep -q "PartOf=docker.service" "${unit_file}"; then
    record "PASS" "docker-user: PartOf=docker.service"
  else
    record "FAIL" "docker-user: PartOf=docker.service" "missing — rules lost on Docker daemon restart"
  fi

  if grep -q "WantedBy=docker.service" "${unit_file}"; then
    record "PASS" "docker-user: WantedBy=docker.service"
  else
    record "FAIL" "docker-user: WantedBy=docker.service" "missing — rules may not re-apply after Docker start"
  fi

  local docker_service_present="false"
  if unit_available "docker.service"; then
    docker_service_present="true"
  fi
  if [[ "${docker_service_present}" != "true" ]]; then
    record "INFO" "docker-user: enabled state" "docker.service unavailable; enable/start deferred"
    return
  fi

  local enabled_state
  enabled_state="$(systemctl is-enabled docker-user-hardening.service 2>/dev/null || echo "unknown")"
  if [[ "${enabled_state}" == "enabled" || "${enabled_state}" == "enabled-runtime" ]]; then
    record "PASS" "docker-user: enabled"
  else
    record "FAIL" "docker-user: enabled" "state=${enabled_state} — rules may not re-apply on Docker restart"
  fi

  # Functional: service must have run at least once since boot (rules are only in iptables if it did).
  local active_state
  active_state="$(systemctl show docker-user-hardening.service --property=ActiveState --value 2>/dev/null || echo "unknown")"
  if [[ "${active_state}" == "active" || "${active_state}" == "activating" ]]; then
    record "PASS" "docker-user: service has run (${active_state})"
  else
    # For a oneshot service, "inactive" is normal after a successful run.
    local result
    result="$(systemctl show docker-user-hardening.service --property=Result --value 2>/dev/null || echo "unknown")"
    if [[ "${result}" == "success" ]]; then
      record "PASS" "docker-user: service completed successfully"
    else
      record "FAIL" "docker-user: service result" "result=${result} — rules may not have been applied"
    fi
  fi
}
