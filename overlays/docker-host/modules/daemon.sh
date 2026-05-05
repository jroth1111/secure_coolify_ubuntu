DOCKER_DAEMON_JSON="/etc/docker/daemon.json"

configure_docker_daemon() {
  # Required settings for hardening
  # Note: log-driver uses json-file (same as Coolify) for compatibility.
  # Hardening owns: log-driver, log-opts, live-restore, default-ipc-mode,
  #   storage-driver, default-ulimits. Coolify may add: default-address-pools.
  #
  # Intentionally NOT added (verified against 344 Coolify service templates):
  #   no-new-privileges  — breaks Glances, Home Assistant, Forgejo DinD
  #   userns-remap       — breaks volume ownership + Docker socket mounting
  #   icc: false          — breaks inter-container networking (app→PostgreSQL→Redis)
  #   userland-proxy: false — risky for user service deployments
  local required_settings
  required_settings="$(jq -nc \
    --argjson nproc_hard "${DOCKER_NPROC_HARD}" \
    --argjson nproc_soft "${DOCKER_NPROC_SOFT}" \
    '{
      "log-driver":"json-file",
      "log-opts":{"max-size":"10m","max-file":"3"},
      "live-restore":true,
      "default-ipc-mode":"private",
      "storage-driver":"overlay2",
      "default-ulimits":{
        "nofile":{"Name":"nofile","Hard":65536,"Soft":65536},
        "nproc":{"Name":"nproc","Hard":$nproc_hard,"Soft":$nproc_soft}
      }
    }')"

  if [[ "${DOCKER_PRESENT}" != "true" ]]; then
    log "Docker not present; skipping daemon.json creation (will be needed post-install)."
    return 0
  fi

  if [[ -f "${DOCKER_DAEMON_JSON}" ]]; then
    # File exists - merge our required settings with existing config
    log "Merging hardening settings into existing ${DOCKER_DAEMON_JSON}"

    if is_true "${DRY_RUN}"; then
      log "DRY-RUN: would merge hardening settings into ${DOCKER_DAEMON_JSON}"
      return 0
    fi

    # Check if jq is available for proper JSON merging
    if ! command -v jq >/dev/null 2>&1; then
      warn "jq not installed; installing for JSON merge..."
      retry_apt_update
      run env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends jq
    fi

    # Backup existing config
    local backup="${DOCKER_DAEMON_JSON}.bak.$(date +%s)"
    cp -a "${DOCKER_DAEMON_JSON}" "${backup}"
    log "Backed up ${DOCKER_DAEMON_JSON} to ${backup}"

    # Merge: our settings take precedence but preserve other existing settings
    local merged required_tmp
    required_tmp="$(mktemp)"
    echo "${required_settings}" > "${required_tmp}"
    merged="$(jq -s '.[0] * .[1]' "${DOCKER_DAEMON_JSON}" "${required_tmp}" 2>/dev/null)"
    rm -f "${required_tmp}"

    if [[ -z "${merged}" ]]; then
      die "Failed to merge ${DOCKER_DAEMON_JSON} with jq; cannot safely apply hardening settings."
    else
      echo "${merged}" > "${DOCKER_DAEMON_JSON}"
      chmod 0644 "${DOCKER_DAEMON_JSON}"
    fi

    if systemctl is-active --quiet docker; then
      DOCKER_DAEMON_NEEDS_RESTART="true"
      log "Docker daemon.json updated; restart deferred until after DOCKER-USER rules are applied."
    else
      rm -f "${DOCKER_DAEMON_JSON}".bak.*
    fi

    log "Docker daemon.json updated with hardening settings."
    return 0
  fi

  # File doesn't exist - create it
  # Note: log-driver uses json-file (same as Coolify) for compatibility.
  # Hardening owns: log-driver, log-opts, live-restore, default-ipc-mode,
  #   storage-driver, default-ulimits. Coolify may add: default-address-pools.
  write_file "${DOCKER_DAEMON_JSON}" "0644" "root" "root" <<EOF
{
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "3"
  },
  "live-restore": true,
  "default-ipc-mode": "private",
  "storage-driver": "overlay2",
  "default-ulimits": {
    "nofile": { "Name": "nofile", "Hard": 65536, "Soft": 65536 },
    "nproc": { "Name": "nproc", "Hard": ${DOCKER_NPROC_HARD}, "Soft": ${DOCKER_NPROC_SOFT} }
  }
}
EOF

  log "Docker daemon.json written with log rotation, live-restore, IPC isolation, overlay2, and ulimits."
}
