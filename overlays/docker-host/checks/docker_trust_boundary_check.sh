docker_trust_boundary_check() {
  local docker_sock="${DOCKER_SOCK:-/var/run/docker.sock}"
  local socket_present="false"

  if ! command -v docker >/dev/null 2>&1; then
    record "INFO" "docker-trust: docker" "Docker not installed; skipped"
    return
  fi

  local mode owner group other
  if [[ -S "${docker_sock}" ]]; then
    socket_present="true"
    mode="$(stat -c '%a' "${docker_sock}" 2>/dev/null || echo "")"
    owner="$(stat -c '%U' "${docker_sock}" 2>/dev/null || echo "")"
    group="$(stat -c '%G' "${docker_sock}" 2>/dev/null || echo "")"

    if [[ -n "${mode}" ]]; then
      other="${mode: -1}"
      if [[ "${other}" =~ ^[0-7]$ ]] && (( (10#${other} & 2) != 0 )); then
        record "FAIL" "docker-trust: socket world-writable check" \
          "${docker_sock} mode=${mode} allows world write"
      else
        record "PASS" "docker-trust: socket world-writable check"
      fi
    else
      record "FAIL" "docker-trust: socket mode" "cannot read mode for ${docker_sock}"
    fi

    if [[ "${owner}" == "root" ]]; then
      record "PASS" "docker-trust: socket owner is root"
    else
      record "FAIL" "docker-trust: socket owner" "expected root, got ${owner:-<unknown>}"
    fi

    if [[ "${group}" == "docker" || "${group}" == "root" ]]; then
      record "PASS" "docker-trust: socket group is ${group}"
    else
      record "INFO" "docker-trust: socket group" \
        "group=${group:-<unknown>} (verify intended access model)"
    fi
  else
    record "INFO" "docker-trust: socket" "${docker_sock} not present; socket-specific checks skipped"
  fi

  if getent group docker >/dev/null 2>&1; then
    local docker_members
    docker_members="$(getent group docker | awk -F: '{print $4}')"

    if [[ -z "${docker_members}" ]]; then
      record "PASS" "docker-trust: docker group has no named members"
    else
      record "FAIL" "docker-trust: docker group has no named members" \
        "named members present: ${docker_members} (root-equivalent Docker access)"
    fi

    if [[ -n "${ADMIN_USER}" ]] && grep -qE "(^|,)$(regex_escape "${ADMIN_USER}")($|,)" <<< "${docker_members}"; then
      record "FAIL" "docker-trust: admin user not in docker group" \
        "${ADMIN_USER} is in docker group (root-equivalent Docker access)"
    else
      record "PASS" "docker-trust: admin user not in docker group"
    fi
  else
    record "INFO" "docker-trust: docker group" "group not present"
  fi

  if [[ "${socket_present}" != "true" ]]; then
    record "INFO" "docker-trust: privileged containers" "skipped because ${docker_sock} is not present"
    return
  fi

  local docker_ps_output docker_ps_status
  docker_ps_status=0
  docker_ps_output="$(docker ps -q 2>/dev/null)" || docker_ps_status=$?
  if (( docker_ps_status != 0 )); then
    record "INFO" "docker-trust: privileged containers" "unable to enumerate running containers"
    return
  fi

  local priv_containers
  priv_containers="$(xargs -r docker inspect --format '{{if .HostConfig.Privileged}}{{.Name}}{{end}}' <<< "${docker_ps_output}" 2>/dev/null \
    | sed 's|^/||' \
    | awk 'NF' \
    | paste -sd, - || true)"
  if [[ -z "${priv_containers}" ]]; then
    record "PASS" "docker-trust: privileged containers allowlist" "no privileged containers running"
    return
  fi

  local allowed_name priv_name
  local -a allowed_names=() priv_names=() unapproved_privileged=()
  local -A allowed_privileged=()
  IFS=',' read -r -a allowed_names <<< "${ALLOWED_PRIVILEGED_CONTAINERS:-}"
  for allowed_name in "${allowed_names[@]}"; do
    allowed_name="${allowed_name//[[:space:]]/}"
    allowed_name="${allowed_name#/}"
    [[ -n "${allowed_name}" ]] || continue
    allowed_privileged["${allowed_name}"]=1
  done

  IFS=',' read -r -a priv_names <<< "${priv_containers}"
  for priv_name in "${priv_names[@]}"; do
    priv_name="${priv_name//[[:space:]]/}"
    priv_name="${priv_name#/}"
    [[ -n "${priv_name}" ]] || continue
    if [[ -z "${allowed_privileged[${priv_name}]:-}" ]]; then
      unapproved_privileged+=("${priv_name}")
    fi
  done

  if (( ${#unapproved_privileged[@]} > 0 )); then
    record "FAIL" "docker-trust: privileged containers allowlist" \
      "unapproved privileged containers: $(IFS=,; echo "${unapproved_privileged[*]}")"
  else
    record "PASS" "docker-trust: privileged containers allowlist" \
      "allowed privileged containers: ${priv_containers}"
  fi
}
