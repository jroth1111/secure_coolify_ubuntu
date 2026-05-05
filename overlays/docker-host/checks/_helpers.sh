docker_hardening_expected() {
  if is_true "${DOCKER_PRESENT:-false}" || is_true "${DOCKER_RULES_APPLIED:-false}"; then
    return 0
  fi

  if [[ "${GATE_C_MODE}" == "true" ]]; then
    return 1
  fi

  command -v docker >/dev/null 2>&1
}

load_docker_ssh_cidrs() {
  local raw="${DOCKER_SSH_CIDRS:-10.0.0.0/8,172.16.0.0/12}"
  local item
  local -a cidrs=()
  local -A seen=()

  IFS=',' read -r -a cidrs <<< "${raw}"
  for item in "${cidrs[@]}"; do
    item="${item//[[:space:]]/}"
    [[ -n "${item}" ]] || continue
    if [[ -z "${seen[${item}]:-}" ]]; then
      seen["${item}"]=1
      printf '%s\n' "${item}"
    fi
  done

  # In strict mode, also include currently detected Docker bridge CIDRs so
  # post-hardening network drift is surfaced by validation.
  if is_true "${STRICT_DOCKER_SSH_CIDRS}"; then
    while IFS= read -r item; do
      item="${item//[[:space:]]/}"
      [[ -n "${item}" ]] || continue
      if [[ -z "${seen[${item}]:-}" ]]; then
        seen["${item}"]=1
        printf '%s\n' "${item}"
      fi
    done < <(
      docker network ls --format '{{.Name}} {{.Driver}}' 2>/dev/null \
        | awk '$2 == "bridge" && ($1 == "bridge" || $1 == "coolify" || $1 ~ /^br-/) {print $1}' \
        | xargs -r docker network inspect --format '{{range .IPAM.Config}}{{.Subnet}}{{"\n"}}{{end}}' 2>/dev/null \
        | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$' \
        | sort -u
    )
  fi
}
