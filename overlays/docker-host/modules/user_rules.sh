install_docker_user_assets() {
  write_file "${DOCKER_USER_SCRIPT}" "0750" "root" "root" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail

WAN_IFACE="${WAN_IFACE:-${1:-}}"
TAILSCALE_IFACE="${TAILSCALE_IFACE:-tailscale0}"
TUNNEL_MODE="${TUNNEL_MODE:-false}"

if [[ -z "${WAN_IFACE}" ]]; then
  echo "WAN_IFACE is required." >&2
  exit 1
fi

if ! command -v iptables >/dev/null 2>&1; then
  echo "iptables is required." >&2
  exit 1
fi

is_true() {
  case "${1,,}" in
    1|true|yes|y|on) return 0 ;;
    *) return 1 ;;
  esac
}

ipt() {
  iptables -w "$@"
}

# --- IPv4 ---

ipt -t filter -N DOCKER-USER 2>/dev/null || true
if ! ipt -t filter -C FORWARD -j DOCKER-USER >/dev/null 2>&1; then
  ipt -t filter -I FORWARD 1 -j DOCKER-USER
fi

while true; do
  line_no="$(ipt -t filter -L DOCKER-USER --line-numbers -n | awk '/coolify-hardening-/ { print $1; exit }')"
  [[ -n "${line_no}" ]] || break
  ipt -t filter -D DOCKER-USER "${line_no}" || true
done

ipt -t filter -A DOCKER-USER -m conntrack --ctstate RELATED,ESTABLISHED -m comment --comment "coolify-hardening-estab" -j RETURN
ipt -t filter -A DOCKER-USER -i "${TAILSCALE_IFACE}" -m comment --comment "coolify-hardening-tailscale" -j ACCEPT
ipt -t filter -A DOCKER-USER -i docker0 -m comment --comment "coolify-hardening-bridge-docker0" -j RETURN
ipt -t filter -A DOCKER-USER -i "br+" -m comment --comment "coolify-hardening-bridge-user" -j RETURN
if ! is_true "${TUNNEL_MODE}"; then
  ipt -t filter -A DOCKER-USER -i "${WAN_IFACE}" -p tcp -m multiport --dports 80,443 -m comment --comment "coolify-hardening-wan-web" -j ACCEPT
fi
ipt -t filter -A DOCKER-USER -i "${WAN_IFACE}" -m comment --comment "coolify-hardening-wan-drop" -j DROP
ipt -t filter -A DOCKER-USER -m comment --comment "coolify-hardening-return" -j RETURN

# --- IPv6 ---

if command -v ip6tables >/dev/null 2>&1; then
  ipt6() {
    ip6tables -w "$@"
  }

  ipt6 -t filter -N DOCKER-USER 2>/dev/null || true
  if ! ipt6 -t filter -C FORWARD -j DOCKER-USER >/dev/null 2>&1; then
    ipt6 -t filter -I FORWARD 1 -j DOCKER-USER
  fi

  while true; do
    line_no="$(ipt6 -t filter -L DOCKER-USER --line-numbers -n | awk '/coolify-hardening-/ { print $1; exit }')"
    [[ -n "${line_no}" ]] || break
    ipt6 -t filter -D DOCKER-USER "${line_no}" || true
  done

  ipt6 -t filter -A DOCKER-USER -m conntrack --ctstate RELATED,ESTABLISHED -m comment --comment "coolify-hardening-estab6" -j RETURN
  ipt6 -t filter -A DOCKER-USER -i "${TAILSCALE_IFACE}" -m comment --comment "coolify-hardening-tailscale6" -j ACCEPT
  ipt6 -t filter -A DOCKER-USER -i docker0 -m comment --comment "coolify-hardening-bridge-docker06" -j RETURN
  ipt6 -t filter -A DOCKER-USER -i "br+" -m comment --comment "coolify-hardening-bridge-user6" -j RETURN
  if ! is_true "${TUNNEL_MODE}"; then
    ipt6 -t filter -A DOCKER-USER -i "${WAN_IFACE}" -p tcp -m multiport --dports 80,443 -m comment --comment "coolify-hardening-wan-web6" -j ACCEPT
  fi
  ipt6 -t filter -A DOCKER-USER -i "${WAN_IFACE}" -m comment --comment "coolify-hardening-wan-drop6" -j DROP
  ipt6 -t filter -A DOCKER-USER -m comment --comment "coolify-hardening-return6" -j RETURN
else
  echo "ip6tables not available; skipping IPv6 DOCKER-USER rules." >&2
fi
EOF

  write_file "${DOCKER_USER_ENV_FILE}" "0644" "root" "root" <<EOF
WAN_IFACE=${WAN_IFACE}
TAILSCALE_IFACE=${TAILSCALE_IFACE}
TUNNEL_MODE=${TUNNEL_MODE}
EOF

  write_file "${DOCKER_USER_UNIT_FILE}" "0644" "root" "root" <<EOF
[Unit]
Description=Apply managed DOCKER-USER hardening rules
After=docker.service
Requires=docker.service
PartOf=docker.service

[Service]
Type=oneshot
EnvironmentFile=${DOCKER_USER_ENV_FILE}
ExecStart=${DOCKER_USER_SCRIPT}
RemainAfterExit=yes

[Install]
WantedBy=docker.service
EOF
}

configure_docker_user() {
  install_docker_user_assets

  # Remove stale WantedBy=multi-user.target symlinks from prior script versions
  if ! is_true "${DRY_RUN}"; then
    systemctl disable docker-user-hardening.service 2>/dev/null || true
  fi
  run systemctl daemon-reload
  local docker_service_present="false"
  if unit_available "docker.service"; then
    docker_service_present="true"
    run systemctl enable docker-user-hardening.service
  else
    log "docker.service not found yet; deferring docker-user-hardening enable until Docker is installed."
  fi

  if [[ "${DOCKER_PRESENT}" == "true" ]]; then
    # Docker CLI may exist while docker.service is not yet installed/available.
    if [[ "${docker_service_present}" == "true" ]]; then
      ensure_docker_user_service_applied "Docker hardening"
    else
      warn "Docker CLI detected but docker.service is not present; DOCKER-USER enable/start deferred."
    fi
  else
    log "Docker not detected; DOCKER-USER unit installed with deferred enable/start until Docker is installed."
  fi
}
