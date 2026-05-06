sysctl_check() {
  local key expected val
  declare -A sysctl_expects=(
    [net.ipv4.tcp_syncookies]="1"
    [net.ipv4.ip_forward]="1"
    [net.ipv4.conf.all.rp_filter]="2"
    [net.ipv4.tcp_max_syn_backlog]="2048"
    [net.ipv4.tcp_synack_retries]="2"
    [fs.protected_hardlinks]="1"
    [fs.protected_symlinks]="1"
    [fs.suid_dumpable]="0"
    [kernel.unprivileged_bpf_disabled]="2"
    [kernel.kexec_load_disabled]="1"
    [kernel.sysrq]="4"
    [kernel.randomize_va_space]="2"
    [kernel.dmesg_restrict]="1"
    [kernel.perf_event_paranoid]="3"
    [kernel.yama.ptrace_scope]="1"
    [kernel.kptr_restrict]="2"
    [vm.overcommit_memory]="1"
    [vm.swappiness]="10"
  )

  for key in "${!sysctl_expects[@]}"; do
    expected="${sysctl_expects[${key}]}"
    val="$(sysctl -n "${key}" 2>/dev/null || echo "?")"
    if [[ "${val}" == "${expected}" ]]; then
      record "PASS" "sysctl: ${key}=${val}"
    elif [[ "${val}" == "?" && "${IS_CONTAINER}" == "true" ]]; then
      record "INFO" "sysctl: ${key}" "unavailable in container namespace"
    else
      record "FAIL" "sysctl: ${key}" "expected ${expected}, got ${val}"
    fi
  done

  # BBR congestion control (informational — depends on kernel module availability)
  local bbr_val
  bbr_val="$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo "?")"
  if [[ "${bbr_val}" == "bbr" ]]; then
    record "PASS" "sysctl: tcp_congestion_control=bbr"
  elif [[ "${bbr_val}" == "?" && "${IS_CONTAINER}" == "true" ]]; then
    record "INFO" "sysctl: tcp_congestion_control" "unavailable in container namespace"
  else
    record "INFO" "sysctl: tcp_congestion_control=${bbr_val}" "BBR not active (kernel module may be unavailable)"
  fi

  local qdisc_val
  qdisc_val="$(sysctl -n net.core.default_qdisc 2>/dev/null || echo "?")"
  if [[ "${qdisc_val}" == "fq" ]]; then
    record "PASS" "sysctl: default_qdisc=fq"
  elif [[ "${qdisc_val}" == "?" && "${IS_CONTAINER}" == "true" ]]; then
    record "INFO" "sysctl: default_qdisc" "unavailable in container namespace"
  else
    record "INFO" "sysctl: default_qdisc=${qdisc_val}" "fq not active (BBR may be unavailable)"
  fi
}
