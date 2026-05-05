add_docker_ssh_cidr() {
  local cidr="$1"
  local existing
  local normalized_cidr

  [[ -n "${cidr}" ]] || return 0
  # SSH/UFW rules here are IPv4-focused.
  [[ "${cidr}" =~ ^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/([0-9]|[12][0-9]|3[0-2])$ ]] || return 0

  # Normalize host/prefix form (e.g. 10.0.0.1/24) to canonical network/prefix
  # (10.0.0.0/24) so Match Address and UFW rules remain valid.
  normalized_cidr="$(python3 - "${cidr}" <<'PY'
import ipaddress
import sys
try:
    net = ipaddress.ip_network(sys.argv[1], strict=False)
    if isinstance(net, ipaddress.IPv4Network):
        print(str(net))
except Exception:
    pass
PY
)"
  [[ -n "${normalized_cidr}" ]] || return 0
  cidr="${normalized_cidr}"

  for existing in "${DOCKER_SSH_CIDRS[@]}"; do
    [[ "${existing}" == "${cidr}" ]] && return 0
  done
  DOCKER_SSH_CIDRS+=("${cidr}")
}

discover_docker_ssh_cidrs() {
  local cidr
  DOCKER_SSH_CIDRS=()

  # Discovery source 1: active Docker bridge networks.
  if command -v docker >/dev/null 2>&1; then
    while IFS= read -r cidr; do
      add_docker_ssh_cidr "${cidr}"
    done < <(
      docker network ls --filter driver=bridge -q 2>/dev/null \
        | xargs -r docker network inspect --format '{{range .IPAM.Config}}{{.Subnet}}{{"\n"}}{{end}}' 2>/dev/null \
        | awk 'NF' \
        | sort -u
    )
  fi

  # Discovery source 2: local Docker bridge interfaces.
  # This still works when the Docker daemon is stopped.
  if command -v ip >/dev/null 2>&1; then
    while IFS= read -r cidr; do
      add_docker_ssh_cidr "${cidr}"
    done < <(
      ip -o -4 addr show 2>/dev/null \
        | awk '$2 ~ /^docker0$/ || $2 ~ /^br-[[:alnum:]]+$/ { print $4 }' \
        | awk 'NF' \
        | sort -u
    )
  fi

  if is_true "${STRICT_DOCKER_SSH_CIDRS}"; then
    if [[ ${#DOCKER_SSH_CIDRS[@]} -eq 0 ]]; then
      if [[ "${DOCKER_PRESENT}" == "true" ]]; then
        warn "STRICT_DOCKER_SSH_CIDRS enabled but no Docker bridge CIDRs discovered; falling back to compatibility ranges."
      else
        log "STRICT_DOCKER_SSH_CIDRS enabled while Docker is not installed yet; using compatibility ranges until docker-ssh-cidr-sync discovers bridges."
      fi
      DOCKER_SSH_CIDRS=(10.0.0.0/8 172.16.0.0/12)
    fi
  else
    DOCKER_SSH_CIDRS=(10.0.0.0/8 172.16.0.0/12)
  fi

  log "Docker SSH CIDRs: ${DOCKER_SSH_CIDRS[*]}"
}
