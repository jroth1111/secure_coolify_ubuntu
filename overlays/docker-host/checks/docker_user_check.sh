docker_user_check() {
  if ! command -v iptables >/dev/null 2>&1; then
    record "FAIL" "docker-user: iptables" "iptables not found"
    return
  fi

  # Check if Docker is installed first
  if ! command -v docker >/dev/null 2>&1; then
    record "INFO" "docker-user: Docker" "Docker not installed; skipping DOCKER-USER checks"
    return
  fi

  # Warn if Docker is using nftables backend (experimental in Docker 29+)
  # DOCKER-USER chain behavior differs in nftables mode; iptables rules won't apply.
  # See: https://docs.docker.com/engine/network/firewall-nftables/
  if docker info 2>/dev/null | grep -qiE 'iptables:\s*false|firewall:\s*nftables'; then
    record "FAIL" "docker-user: backend" "Docker using nftables backend — DOCKER-USER iptables rules will NOT work"
    return
  else
    record "PASS" "docker-user: iptables backend"
  fi

  local docker_service_present="false"
  if unit_available "docker.service"; then
    docker_service_present="true"
  fi
  if [[ "${DOCKER_RULES_APPLIED}" != "true" && "${docker_service_present}" != "true" ]]; then
    record "INFO" "docker-user: IPv4" "docker.service unavailable and DOCKER-USER apply deferred"
    return
  fi

  local rules attempt chain_ready="false"
  for (( attempt=1; attempt<=10; attempt++ )); do
    rules="$(iptables -t filter -S DOCKER-USER 2>/dev/null)" || rules=""
    if [[ -n "${rules}" ]]; then
      chain_ready="true"
      break
    fi
    (( attempt < 10 )) || break
    sleep 2
  done
  if [[ "${chain_ready}" != "true" ]]; then
    record "FAIL" "docker-user: IPv4" "DOCKER-USER chain absent (Docker may need restart)"
    return
  fi

  if grep -q "coolify-hardening-wan-drop" <<< "${rules}"; then
    record "PASS" "docker-user: IPv4 wan-drop"
  else
    record "FAIL" "docker-user: IPv4 wan-drop" "rule missing"
  fi

  if grep -q "coolify-hardening-bridge-docker0" <<< "${rules}"; then
    record "PASS" "docker-user: IPv4 bridge-docker0"
  else
    record "FAIL" "docker-user: IPv4 bridge-docker0" "rule missing"
  fi

  if is_true "${TUNNEL_MODE}" && grep -q "coolify-hardening-wan-web" <<< "${rules}"; then
    record "FAIL" "docker-user: tunnel-mode no wan-web" "wan-web ACCEPT present"
  elif is_true "${TUNNEL_MODE}"; then
    record "PASS" "docker-user: tunnel-mode no wan-web"
  fi

  if command -v ip6tables >/dev/null 2>&1; then
    local rules6
    rules6="$(ip6tables -t filter -S DOCKER-USER 2>/dev/null)" || { record "INFO" "docker-user: IPv6" "DOCKER-USER chain absent"; return; }

    if grep -q "coolify-hardening-wan-drop6" <<< "${rules6}"; then
      record "PASS" "docker-user: IPv6 wan-drop6"
    else
      record "FAIL" "docker-user: IPv6 wan-drop6" "rule missing"
    fi
  else
    record "INFO" "docker-user: IPv6" "ip6tables not available"
  fi
}
