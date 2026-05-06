detect_os() {
  [[ -f /etc/os-release ]] || die "/etc/os-release not found."
  # shellcheck disable=SC1091
  source /etc/os-release
  [[ "${ID:-}" == "ubuntu" ]] || die "Only Ubuntu is supported."
  OS_VERSION="${VERSION_ID:-unknown}"

  if [[ "${OS_VERSION}" != "24.04" ]] && ! is_true "${FORCE}"; then
    die "Expected Ubuntu 24.04.x (found ${OS_VERSION}). Use --force to override."
  fi
}

check_disk_space() {
  local swap_size="${SWAP_SIZE:-2G}"
  local required_mb=512
  if [[ "${swap_size}" != "0" ]]; then
    local swap_num="${swap_size%[GgMm]}"
    local swap_unit="${swap_size: -1}"
    case "${swap_unit,,}" in
      g) required_mb=$(( required_mb + swap_num * 1024 )) ;;
      m) required_mb=$(( required_mb + swap_num )) ;;
    esac
  fi
  if is_true "${DRY_RUN}"; then
    log "DRY-RUN: would check disk space (required: ${required_mb}M)."
    return 0
  fi

  # If a stale swapfile exists and will be removed, we can reclaim that space.
  local swapfile_mb=0
  if [[ -f /swapfile ]] && ! swapon --show --noheadings 2>/dev/null | grep -q '/swapfile'; then
    swapfile_mb="$(du -m /swapfile 2>/dev/null | cut -f1)" || swapfile_mb=0
  fi

  local avail_mb
  avail_mb="$(df -m / 2>/dev/null | awk 'NR==2 {print $4}')"
  if [[ -z "${avail_mb}" || ! "${avail_mb}" =~ ^[0-9]+$ ]]; then
    warn "Cannot determine available disk space; skipping pre-flight check."
    return 0
  fi

  # Add reclaimed swapfile space to available
  local effective_avail=$(( avail_mb + swapfile_mb ))

  if (( effective_avail < required_mb )); then
    die "Insufficient disk space: ${avail_mb}M available (+${swapfile_mb}M from stale swap), ${required_mb}M required (swap: ${swap_size} + 512M base)."
  fi
  log "Disk pre-flight: ${avail_mb}M available, ${required_mb}M required. OK."
}

detect_wan_iface() {
  if [[ -n "${WAN_IFACE}" ]]; then
    return 0
  fi

  WAN_IFACE="$(ip -o route get 1.1.1.1 2>/dev/null | awk '{for (i = 1; i <= NF; i++) if ($i == "dev") { print $(i+1); exit }}')"
  [[ -n "${WAN_IFACE}" ]] || die "Unable to auto-detect WAN interface. Set --wan-iface."
}

ssh_session_safety_gate() {
  if [[ -z "${SSH_CONNECTION:-}" ]]; then
    return 0
  fi

  local src_ip
  src_ip="${SSH_CONNECTION%% *}"
  if [[ "${src_ip}" != 100.* && "${src_ip}" != fd7a:* ]] && ! is_true "${FORCE}"; then
    die "Current SSH source (${src_ip}) is not Tailscale-like; refusing to continue without --force."
  fi
}
