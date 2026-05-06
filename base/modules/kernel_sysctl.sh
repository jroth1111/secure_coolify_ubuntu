configure_sysctl() {
  # Migration: remove old 60-prefixed drop-in (replaced by 99- for precedence)
  local old_sysctl="/etc/sysctl.d/60-coolify-hardening.conf"
  if [[ -f "${old_sysctl}" && "${old_sysctl}" != "${SYSCTL_DROPIN_FILE}" ]]; then
    log "Removing superseded sysctl drop-in ${old_sysctl} (replaced by ${SYSCTL_DROPIN_FILE})."
    run rm -f "${old_sysctl}"
  fi

  # Check if BBR kernel module is available
  local bbr_available="false"
  if modinfo tcp_bbr &>/dev/null; then
    bbr_available="true"
  fi

  {
    cat <<'SYSCTL_BASE'
# Managed by bootstrap hardening — Coolify/Docker safe
net.ipv4.ip_forward = 1
net.ipv4.tcp_syncookies = 1
# Redis/Coolify reliability under memory pressure
vm.overcommit_memory = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
# Allow non-root ping sockets so cloudflared ICMP proxy init does not warn.
net.ipv4.ping_group_range = 0 2147483647
net.ipv4.conf.all.rp_filter = 2
net.ipv4.conf.default.rp_filter = 2
# SYN flood hardening
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.suid_dumpable = 0
kernel.unprivileged_bpf_disabled = 2
kernel.kexec_load_disabled = 1
kernel.sysrq = 4
kernel.randomize_va_space = 2
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.yama.ptrace_scope = 1
kernel.perf_event_paranoid = 3
SYSCTL_BASE

    if [[ "${bbr_available}" == "true" ]]; then
      cat <<'SYSCTL_BBR'
# TCP performance: BBR congestion control
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
SYSCTL_BBR
    fi

    if [[ "${SWAP_SIZE:-2G}" != "0" ]]; then
      cat <<'SYSCTL_SWAP'
# Swap tuning: prefer RAM, use swap only under pressure
vm.swappiness = 10
SYSCTL_SWAP
    fi
  } | write_file "${SYSCTL_DROPIN_FILE}" "0644" "root" "root"

  if [[ "${bbr_available}" == "false" ]]; then
    warn "BBR not available: kernel module tcp_bbr not found. Using default congestion control."
  fi

  run sysctl --system

  if ! is_true "${DRY_RUN}"; then
    local syncookies ip_forward overcommit
    syncookies="$(sysctl -n net.ipv4.tcp_syncookies 2>/dev/null || echo "?")"
    ip_forward="$(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo "?")"
    overcommit="$(sysctl -n vm.overcommit_memory 2>/dev/null || echo "?")"
    [[ "${syncookies}" == "1" ]] || die "Post-sysctl check failed: tcp_syncookies is ${syncookies}, expected 1."
    [[ "${ip_forward}" == "1" ]] || die "Post-sysctl check failed: ip_forward is ${ip_forward}, expected 1 (Docker requires this)."
    [[ "${overcommit}" == "1" ]] || die "Post-sysctl check failed: vm.overcommit_memory is ${overcommit}, expected 1."

    if [[ "${bbr_available}" == "true" ]]; then
      local bbr
      bbr="$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo "?")"
      [[ "${bbr}" == "bbr" ]] || warn "BBR not active: ${bbr} (kernel module tcp_bbr may be unavailable)."
    fi
  fi
}
