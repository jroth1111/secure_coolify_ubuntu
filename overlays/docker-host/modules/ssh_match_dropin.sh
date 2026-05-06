configure_docker_ssh_match_dropin() {
  local dropin="${DOCKER_SSH_MATCH_DROPIN:-/etc/ssh/sshd_config.d/15-docker-ssh-match.conf}"
  local cidr
  local match_addresses=""

  for cidr in "${DOCKER_SSH_CIDRS[@]}"; do
    if [[ -n "${match_addresses}" ]]; then
      match_addresses+=","
    fi
    match_addresses+="${cidr}"
  done

  if [[ -z "${match_addresses}" ]]; then
    log "No Docker bridge CIDRs discovered; skipping ${dropin}."
    return 0
  fi

  if is_true "${DRY_RUN}"; then
    log "DRY-RUN: would write ${dropin} for Docker bridge CIDRs: ${match_addresses}"
    return 0
  fi

  write_file "${dropin}" "0644" "root" "root" <<EOF
# Managed by bootstrap hardening — docker-host overlay.
# Coolify connects to its own host as root via Docker bridge networks.
# Re-written on each docker-ssh-cidr-sync.timer run.
Match Address ${match_addresses}
    PermitRootLogin prohibit-password
    AllowUsers ${ADMIN_USER} root
EOF

  if ! sshd -t; then
    rm -f "${dropin}"
    warn "sshd -t failed after writing ${dropin}; dropin removed."
    return 1
  fi

  reload_ssh_service || true
  log "Docker SSH match dropin written: ${dropin} (CIDRs: ${match_addresses})"
}
