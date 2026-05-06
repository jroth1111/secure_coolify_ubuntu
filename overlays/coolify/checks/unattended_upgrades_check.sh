unattended_upgrades_check() {
  local apt_local="/etc/apt/apt.conf.d/52unattended-upgrades-local"
  local security_origin='origin=Ubuntu,codename=${distro_codename}-security,label=Ubuntu'
  local updates_origin='origin=Ubuntu,codename=${distro_codename}-updates,label=Ubuntu'
  local docker_origin_archive='origin=Docker,label=Docker CE,archive=${distro_codename},component=stable'
  local docker_origin_suite='origin=Docker,label=Docker CE,suite=${distro_codename},component=stable'
  local profile="${UPDATE_PROFILE:-}"

  if [[ ! -f "${apt_local}" ]]; then
    record "FAIL" "auto-updates: local config" "not found at ${apt_local}"
    return
  fi

  if [[ -z "${profile}" ]]; then
    profile="$(infer_update_profile "${apt_local}")"
    record "INFO" "auto-updates: profile" "state missing update_profile; inferred ${profile} from local config"
  fi

  case "${profile}" in
    security-only|balanced) ;;
    *)
      record "FAIL" "auto-updates: profile" "unsupported profile '${profile}'"
      return
      ;;
  esac

  if grep -qF "${security_origin}" "${apt_local}"; then
    record "PASS" "auto-updates: Ubuntu security origin covered"
  else
    record "FAIL" "auto-updates: Ubuntu security origin" "not in origins pattern"
  fi

  if [[ "${profile}" == "balanced" ]]; then
    if grep -qF "${updates_origin}" "${apt_local}"; then
      record "PASS" "auto-updates: Ubuntu updates origin covered"
    else
      record "FAIL" "auto-updates: Ubuntu updates origin" "missing for balanced profile"
    fi

    if grep -qF "${docker_origin_archive}" "${apt_local}" || grep -qF "${docker_origin_suite}" "${apt_local}"; then
      record "PASS" "auto-updates: Docker CE origin pinned to stable"
    elif grep -q "origin=Docker,label=Docker CE" "${apt_local}"; then
      record "FAIL" "auto-updates: Docker CE origin" "present but not pinned to archive/suite + component=stable"
    else
      record "FAIL" "auto-updates: Docker CE origin" "missing for balanced profile"
    fi
  else
    if grep -qF "${updates_origin}" "${apt_local}"; then
      record "FAIL" "auto-updates: Ubuntu updates origin" "present but profile is security-only"
    else
      record "PASS" "auto-updates: Ubuntu updates origin excluded (security-only)"
    fi

    if grep -qF "${docker_origin_archive}" "${apt_local}" \
      || grep -qF "${docker_origin_suite}" "${apt_local}" \
      || grep -q "origin=Docker,label=Docker CE" "${apt_local}"; then
      record "FAIL" "auto-updates: Docker CE origin" "present but profile is security-only"
    else
      record "PASS" "auto-updates: Docker CE origin excluded (security-only)"
    fi
  fi

  if grep -q 'Unattended-Upgrade::Automatic-Reboot' "${apt_local}"; then
    record "PASS" "auto-updates: reboot policy configured"
  else
    record "FAIL" "auto-updates: reboot policy" "not configured"
  fi

  # Functional: verify apt timers are actually running (config alone doesn't prove execution).
  for timer in apt-daily.timer apt-daily-upgrade.timer; do
    if systemctl is-active --quiet "${timer}" 2>/dev/null; then
      record "PASS" "auto-updates: ${timer} active"
    else
      record "FAIL" "auto-updates: ${timer}" "timer not active — unattended-upgrades will not run"
    fi
  done

  # Verify apt timers have Persistent=false to prevent boot-time catch-up blocking package ops.
  # See: https://documentation.ubuntu.com/server/how-to/software/automatic-updates/
  for timer in apt-daily.timer apt-daily-upgrade.timer; do
    local override_file="/etc/systemd/system/${timer}.d/override.conf"
    if [[ -f "${override_file}" ]] && grep -q "Persistent=false" "${override_file}"; then
      record "PASS" "auto-updates: ${timer} Persistent=false"
    else
      record "FAIL" "auto-updates: ${timer} Persistent" \
        "override missing — boot-time catch-up may block package operations"
    fi
  done
}

