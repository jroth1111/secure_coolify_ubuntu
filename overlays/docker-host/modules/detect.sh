detect_docker() {
  if command -v docker >/dev/null 2>&1; then
    DOCKER_PRESENT="true"
    log "Docker detected."

    # Docker nftables backend makes DOCKER-USER iptables enforcement ineffective.
    local docker_info
    docker_info="$(docker info 2>/dev/null || true)"
    if [[ -n "${docker_info}" ]] && grep -qiE 'iptables:\s*false|firewall:\s*nftables' <<< "${docker_info}"; then
      die "Docker nftables backend detected; DOCKER-USER iptables hardening is unsupported. Reconfigure Docker to iptables backend before continuing."
    fi
  else
    log "Docker not detected."
  fi
}
