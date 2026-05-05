docker_daemon_ready() {
  systemctl is-active --quiet docker.service 2>/dev/null || return 1
  docker info >/dev/null 2>&1
}

wait_for_systemd_unit_success() {
  local unit_name="$1"
  local attempts="${2:-15}"
  local delay="${3:-2}"
  local attempt active_state result

  for (( attempt=1; attempt<=attempts; attempt++ )); do
    if systemctl is-active --quiet "${unit_name}" 2>/dev/null; then
      return 0
    fi

    active_state="$(systemctl show "${unit_name}" --property=ActiveState --value 2>/dev/null || true)"
    result="$(systemctl show "${unit_name}" --property=Result --value 2>/dev/null || true)"
    if [[ "${active_state}" == "inactive" && "${result}" == "success" ]]; then
      return 0
    fi

    (( attempt < attempts )) || break
    sleep "${delay}"
  done

  return 1
}

wait_for_docker_daemon_ready() {
  local attempts="${1:-20}"
  local delay="${2:-2}"
  local attempt

  [[ "${DOCKER_PRESENT}" == "true" ]] || return 0
  for (( attempt=1; attempt<=attempts; attempt++ )); do
    if docker_daemon_ready; then
      return 0
    fi
    (( attempt < attempts )) || break
    sleep "${delay}"
  done

  return 1
}

docker_user_rules_present() {
  iptables -S DOCKER-USER 2>/dev/null | grep -q "coolify-hardening"
}

ensure_docker_user_service_applied() {
  local context="${1:-docker-user-hardening}"

  if [[ "${DOCKER_PRESENT}" != "true" ]]; then
    return 0
  fi

  wait_for_docker_daemon_ready 20 2 \
    || die "${context}: Docker daemon did not become ready."
  run systemctl start docker-user-hardening.service
  if is_true "${DRY_RUN}"; then
    return 0
  fi

  wait_for_systemd_unit_success "docker-user-hardening.service" 15 2 \
    || die "${context}: docker-user-hardening.service did not complete successfully."
  docker_user_rules_present \
    || die "${context}: DOCKER-USER rules were not applied."
  DOCKER_RULES_APPLIED="true"
}

wait_for_fail2ban_sshd_jail() {
  local attempts="${1:-15}"
  local delay="${2:-2}"
  local attempt

  if is_true "${DRY_RUN}"; then
    return 0
  fi

  for (( attempt=1; attempt<=attempts; attempt++ )); do
    if systemctl is-active --quiet fail2ban 2>/dev/null \
      && fail2ban-client status sshd >/dev/null 2>&1; then
      return 0
    fi
    (( attempt < attempts )) || break
    sleep "${delay}"
  done

  return 1
}
