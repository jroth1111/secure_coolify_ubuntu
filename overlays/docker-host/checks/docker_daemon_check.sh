docker_daemon_check() {
  local daemon_json="/etc/docker/daemon.json"
  if [[ ! -f "${daemon_json}" ]]; then
    if docker_hardening_expected; then
      record "FAIL" "docker-daemon: daemon.json" "file missing (no log rotation)"
    else
      record "INFO" "docker-daemon: daemon.json" "Docker hardening not yet expected; skipped"
    fi
    return
  fi

  # Check log-driver is json-file (matches Coolify's expectation)
  local log_driver
  log_driver="$(jq -r '.["log-driver"] // ""' "${daemon_json}" 2>/dev/null || true)"
  if [[ "${log_driver}" == "json-file" ]]; then
    record "PASS" "docker-daemon: log-driver is json-file"
  elif [[ "${log_driver}" == "" ]]; then
    record "FAIL" "docker-daemon: log-driver" "not set in daemon.json"
  else
    record "FAIL" "docker-daemon: log-driver" "expected 'json-file', got '${log_driver}'"
  fi

  # Check log-opts have rotation configured
  if jq -e '.["log-opts"]["max-size"]' "${daemon_json}" >/dev/null 2>&1; then
    record "PASS" "docker-daemon: log-opts.max-size configured"
  else
    record "FAIL" "docker-daemon: log-opts.max-size" "not set in daemon.json"
  fi

  local live_restore
  live_restore="$(jq -r 'if has("live-restore") then .["live-restore"] else "missing" end | tostring' "${daemon_json}" 2>/dev/null || echo "invalid")"
  case "${live_restore}" in
    true)
      record "PASS" "docker-daemon: live-restore=true"
      ;;
    false)
      record "FAIL" "docker-daemon: live-restore" "expected true, got false"
      ;;
    missing)
      record "FAIL" "docker-daemon: live-restore" "not set in daemon.json"
      ;;
    *)
      record "FAIL" "docker-daemon: live-restore" "invalid value in daemon.json"
      ;;
  esac

  # CIS 5.19: isolate container IPC namespaces
  local ipc_mode
  ipc_mode="$(jq -r '.["default-ipc-mode"] // ""' "${daemon_json}" 2>/dev/null || true)"
  if [[ "${ipc_mode}" == "private" ]]; then
    record "PASS" "docker-daemon: default-ipc-mode is private"
  else
    record "FAIL" "docker-daemon: default-ipc-mode" "expected 'private', got '${ipc_mode:-<unset>}'"
  fi

  # Make overlay2 explicit to prevent regression
  local storage
  storage="$(jq -r '.["storage-driver"] // ""' "${daemon_json}" 2>/dev/null || true)"
  if [[ "${storage}" == "overlay2" ]]; then
    record "PASS" "docker-daemon: storage-driver is overlay2"
  else
    record "FAIL" "docker-daemon: storage-driver" "expected 'overlay2', got '${storage:-<unset>}'"
  fi

  # Prevent fork bombs / fd exhaustion
  if jq -e '.["default-ulimits"]["nofile"]' "${daemon_json}" >/dev/null 2>&1 \
    && jq -e '.["default-ulimits"]["nproc"]' "${daemon_json}" >/dev/null 2>&1; then
    record "PASS" "docker-daemon: default-ulimits (nofile+nproc) configured"
  else
    record "FAIL" "docker-daemon: default-ulimits" "nofile and/or nproc not set in daemon.json"
  fi

  # Verify the RUNNING daemon matches the config file — daemon.json changes only take
  # effect after a restart, so file and live state can diverge silently.
  if docker info >/dev/null 2>&1; then
    local live_driver
    live_driver="$(docker info --format '{{.LoggingDriver}}' 2>/dev/null || true)"
    if [[ "${live_driver}" == "json-file" ]]; then
      record "PASS" "docker-daemon: live log-driver is json-file"
    elif [[ -n "${live_driver}" ]]; then
      record "FAIL" "docker-daemon: live log-driver" \
        "daemon reports '${live_driver}' — restart Docker to apply daemon.json"
    fi
  else
    record "INFO" "docker-daemon: live config" "docker daemon not responding; skipping live check"
  fi
}
