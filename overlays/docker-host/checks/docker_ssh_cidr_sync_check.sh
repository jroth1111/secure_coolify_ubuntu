docker_ssh_cidr_sync_check() {
  if ! is_true "${STRICT_DOCKER_SSH_CIDRS}"; then
    record "INFO" "docker-ssh-cidr-sync: strict mode" "disabled"
    return
  fi

  if [[ ! -f "${DOCKER_SSH_CIDR_SYNC_SCRIPT}" ]]; then
    record "FAIL" "docker-ssh-cidr-sync: script" "missing at ${DOCKER_SSH_CIDR_SYNC_SCRIPT}"
    return
  fi

  # Guard against legacy script versions that inserted host/prefix values
  # (for example 10.0.0.1/24) into sshd Match Address and broke sshd reloads.
  if grep -q 'normalize_cidr()' "${DOCKER_SSH_CIDR_SYNC_SCRIPT}"; then
    record "PASS" "docker-ssh-cidr-sync: CIDR normalization"
  else
    record "FAIL" "docker-ssh-cidr-sync: CIDR normalization" \
      "normalize_cidr() missing; host/prefix CIDRs can break sshd Match Address"
  fi

  if ! command -v systemctl >/dev/null 2>&1; then
    record "INFO" "docker-ssh-cidr-sync: systemd" "systemctl unavailable"
    return
  fi

  if systemctl is-active --quiet "${DOCKER_SSH_CIDR_SYNC_TIMER}" 2>/dev/null; then
    record "PASS" "docker-ssh-cidr-sync: timer active"
  elif systemctl list-unit-files --no-legend "${DOCKER_SSH_CIDR_SYNC_TIMER}" 2>/dev/null | grep -q "${DOCKER_SSH_CIDR_SYNC_TIMER}"; then
    record "FAIL" "docker-ssh-cidr-sync: timer active" "installed but inactive"
  else
    record "FAIL" "docker-ssh-cidr-sync: timer active" "timer not installed"
  fi

  local active_state result
  active_state="$(systemctl show "${DOCKER_SSH_CIDR_SYNC_SERVICE}" --property=ActiveState --value 2>/dev/null || echo "unknown")"
  if [[ "${active_state}" == "active" || "${active_state}" == "activating" ]]; then
    record "PASS" "docker-ssh-cidr-sync: service has run (${active_state})"
  else
    # Oneshot services are expected to go inactive after successful completion.
    result="$(systemctl show "${DOCKER_SSH_CIDR_SYNC_SERVICE}" --property=Result --value 2>/dev/null || echo "unknown")"
    if [[ "${result}" == "success" ]]; then
      record "PASS" "docker-ssh-cidr-sync: service completed successfully"
    else
      record "FAIL" "docker-ssh-cidr-sync: service result" \
        "result=${result} — inspect: journalctl -u ${DOCKER_SSH_CIDR_SYNC_SERVICE}"
    fi
  fi

  local docker_runtime_ready="false"
  local docker_sock="${DOCKER_SOCK:-/var/run/docker.sock}"
  if command -v docker >/dev/null 2>&1; then
    if command -v systemctl >/dev/null 2>&1 \
      && systemctl is-active --quiet docker.service 2>/dev/null; then
      docker_runtime_ready="true"
    elif [[ -S "${docker_sock}" ]] && docker info >/dev/null 2>&1; then
      docker_runtime_ready="true"
    fi
  fi

  if docker_hardening_expected && [[ "${docker_runtime_ready}" == "true" ]]; then
    local cidr
    local -a compat_cidrs=()
    local -A seen_compat=()

    while IFS= read -r cidr; do
      cidr="${cidr//[[:space:]]/}"
      case "${cidr}" in
        10.0.0.0/8|172.16.0.0/12)
          if [[ -z "${seen_compat[${cidr}]:-}" ]]; then
            compat_cidrs+=("${cidr}")
            seen_compat["${cidr}"]=1
          fi
          ;;
      esac
    done < <(printf '%s\n' "${DOCKER_SSH_CIDRS:-10.0.0.0/8,172.16.0.0/12}" | tr ',' '\n')

    if (( ${#compat_cidrs[@]} > 0 )); then
      record "FAIL" "docker-ssh-cidr-sync: compatibility fallback cleared" \
        "strict mode still includes broad fallback CIDRs after Docker install: $(IFS=,; echo "${compat_cidrs[*]}")"
    else
      record "PASS" "docker-ssh-cidr-sync: compatibility fallback cleared"
    fi
  elif docker_hardening_expected && [[ "${GATE_C_MODE}" != "true" ]]; then
    record "INFO" "docker-ssh-cidr-sync: compatibility fallback cleared" \
      "Docker runtime not ready; compatibility fallback still tolerated"
  fi
}
