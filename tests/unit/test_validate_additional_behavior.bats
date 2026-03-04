#!/usr/bin/env bats
# Additional behavior tests to close function coverage gaps in validate_hardening.sh

load '../helpers'

setup() {
  source_validate_script
  reset_validate_runtime
}

@test "parse_cli_args: sets json mode and state file path" {
  parse_cli_args --json
  [ "${JSON_MODE}" = "true" ]
  [ "${STATE_FILE}" = "/var/lib/bootstrap-hardening/state" ]
}

@test "record (runtime): increments PASS count for PASS status" {
  record "PASS" "runtime-check" "ok"
  local json
  json="$(emit_validate_results_json)"
  assert_json_check_status "${json}" "runtime-check" "PASS"
  assert_json_fail_count "${json}" "0"
}

@test "check (runtime): records FAIL when command exits non-zero" {
  check "runtime-check" false
  local json
  json="$(emit_validate_results_json)"
  assert_json_check_status "${json}" "runtime-check" "FAIL"
  assert_json_check_detail_contains "${json}" "runtime-check" "false"
  assert_json_fail_count "${json}" "1"
}

@test "detect_container_runtime: flags containerized runtime" {
  systemd-detect-virt() {
    echo docker
    return 0
  }

  detect_container_runtime
  [ "${IS_CONTAINER}" = "true" ]
}

@test "load_state_context: imports state values into runtime vars" {
  local state
  state="$(mktemp)"
  cat > "${state}" <<STATE
admin_user=alice
ssh_port=2222
wan_iface=eth0
tailscale_direct_wan=true
update_profile=balanced
STATE

  STATE_FILE="${state}"
  load_state_context

  [ "${ADMIN_USER}" = "alice" ]
  [ "${SSH_PORT}" = "2222" ]
  [ "${WAN_IFACE}" = "eth0" ]
  [ "${TAILSCALE_DIRECT_WAN}" = "true" ]
  [ "${UPDATE_PROFILE}" = "balanced" ]

  rm -f "${state}"
}

@test "regex_escape: escapes regex metacharacters" {
  run regex_escape 'a.b[c]\\d+$'
  assert_success
  assert_output 'a\.b\[c\]\\d\+\$'
}

@test "load_docker_ssh_cidrs: returns de-duplicated configured CIDRs" {
  DOCKER_SSH_CIDRS='10.0.0.0/8, 172.16.0.0/12,10.0.0.0/8'
  STRICT_DOCKER_SSH_CIDRS='false'

  run load_docker_ssh_cidrs
  assert_success
  assert_line --index 0 '10.0.0.0/8'
  assert_line --index 1 '172.16.0.0/12'
}

@test "infer_update_profile: detects balanced profile when updates origin present" {
  local apt_local
  apt_local="$(mktemp)"
  printf '"origin=Ubuntu,codename=${distro_codename}-updates,label=Ubuntu";\n' > "${apt_local}"

  run infer_update_profile "${apt_local}"
  assert_success
  assert_output 'balanced'

  rm -f "${apt_local}"
}

@test "ufw_check: records active firewall and tailscale-scoped rules" {
  SSH_PORT="22"
  TAILSCALE_IFACE="tailscale0"
  WAN_IFACE="eth0"
  TUNNEL_MODE="false"
  TAILSCALE_DIRECT_WAN="false"
  DOCKER_SSH_CIDRS='10.0.0.0/8'

  ufw() {
    if [[ "$1" == "status" ]]; then
      cat <<UFW
Status: active
22/tcp                     ALLOW IN    on tailscale0
22                         ALLOW       10.0.0.0/8
8000/tcp                   ALLOW IN    on tailscale0
6001/tcp                   ALLOW IN    on tailscale0
6002/tcp                   ALLOW IN    on tailscale0
UFW
      return 0
    fi
    return 0
  }

  ufw_check
  local json
  json="$(emit_validate_results_json)"
  assert_json_check_status "${json}" "ufw: active" "PASS"
  assert_json_check_status "${json}" "ufw: SSH on tailscale0" "PASS"
  assert_json_fail_count "${json}" "0"
}

@test "swap_check: reports disabled swap when swap_size is 0" {
  swap_size="0"

  swap_check
  local json
  json="$(emit_validate_results_json)"
  assert_json_check_status "${json}" "swap: disabled" "INFO"
  assert_json_fail_count "${json}" "0"
}

@test "apparmor_check: passes when aa-status reports enabled" {
  aa-status() {
    [[ "$1" == "--enabled" ]] && return 0
    return 0
  }

  apparmor_check
  local json
  json="$(emit_validate_results_json)"
  assert_json_check_status "${json}" "apparmor: enabled" "PASS"
  assert_json_fail_count "${json}" "0"
}

@test "listening_ports_info: records discovered listening ports" {
  ss() {
    cat <<SS
State Recv-Q Send-Q Local Address:Port Peer Address:Port Process
LISTEN 0      4096   0.0.0.0:22      0.0.0.0:*
SS
  }

  listening_ports_info
  local json
  json="$(emit_validate_results_json)"
  assert_json_check_status "${json}" "listening: TCP ports" "INFO"
  assert_json_check_detail_contains "${json}" "listening: TCP ports" "22"
}

@test "coolify_ssh_check: returns cleanly when Coolify SSH dir is absent" {
  run coolify_ssh_check
  assert_success
}

@test "cloudflared_check: reports info when cloudflared is not installed" {
  systemctl() { return 1; }
  cloudflared_check
  local json
  json="$(emit_validate_results_json)"
  assert_json_check_status "${json}" "cloudflared: not installed" "INFO"
  assert_json_fail_count "${json}" "0"
}

@test "coolify_container_check: reports info when Docker is missing" {
  command() {
    if [[ "$1" == "-v" && "$2" == "docker" ]]; then
      return 1
    fi
    builtin command "$@"
  }

  coolify_container_check
  local json
  json="$(emit_validate_results_json)"
  assert_json_check_status "${json}" "coolify-containers: docker" "INFO"
  assert_json_fail_count "${json}" "0"
}

@test "admin_sudo_check: reports info when admin user is not configured" {
  ADMIN_USER=""
  admin_sudo_check
  local json
  json="$(emit_validate_results_json)"
  assert_json_check_status "${json}" "admin: sudo" "INFO"
  assert_json_fail_count "${json}" "0"
}

@test "auditd_check: executes and records audit status outcomes" {
  IS_CONTAINER="true"
  systemctl() { return 1; }
  auditctl() { return 1; }

  auditd_check
  local json
  json="$(emit_validate_results_json)"
  assert_json_check_status "${json}" "auditd: active" "INFO"
  assert_json_check_status "${json}" "auditd: rules" "FAIL"
  assert_json_fail_count "${json}" "1"
}

@test "banner_check: records banner verification result" {
  banner_check
  local json
  local status
  json="$(emit_validate_results_json)"
  status="$(json_check_status "${json}" "banner: /etc/issue.net")"
  [[ -n "${status}" ]]
}

@test "coolify_binding_check: records binding guard posture" {
  BIND_DASHBOARD_TO_TAILSCALE="false"
  coolify_binding_check
  local json
  json="$(emit_validate_results_json)"
  assert_json_check_status "${json}" "coolify: dashboard UFW restriction" "INFO"
  assert_json_fail_count "${json}" "0"
}

@test "disabled_services_check: passes when services are masked" {
  systemctl() {
    if [[ "$1" == "is-enabled" ]]; then
      echo masked
      return 0
    fi
    return 0
  }

  disabled_services_check
  local json
  json="$(emit_validate_results_json)"
  assert_json_check_status "${json}" "disabled: rpcbind.service (masked)" "PASS"
  assert_json_check_status "${json}" "disabled: avahi-daemon.service (masked)" "PASS"
  assert_json_check_status "${json}" "disabled: cups.service (masked)" "PASS"
  assert_json_fail_count "${json}" "0"
}

@test "docker_daemon_check: records daemon config status" {
  command() {
    if [[ "$1" == "-v" && "$2" == "docker" ]]; then
      return 1
    fi
    builtin command "$@"
  }

  docker_daemon_check
  local json
  json="$(emit_validate_results_json)"
  assert_json_check_status "${json}" "docker-daemon: daemon.json" "INFO"
  assert_json_fail_count "${json}" "0"
}

@test "docker_trust_boundary_check: records info when Docker is unavailable" {
  command() {
    if [[ "$1" == "-v" && "$2" == "docker" ]]; then
      return 1
    fi
    builtin command "$@"
  }

  docker_trust_boundary_check
  local json
  json="$(emit_validate_results_json)"
  assert_json_check_status "${json}" "docker-trust: docker" "INFO"
  assert_json_fail_count "${json}" "0"
}

@test "docker_user_check: fails fast when iptables is unavailable" {
  command() {
    if [[ "$1" == "-v" && "$2" == "iptables" ]]; then
      return 1
    fi
    builtin command "$@"
  }

  docker_user_check
  local json
  json="$(emit_validate_results_json)"
  assert_json_check_status "${json}" "docker-user: iptables" "FAIL"
  assert_json_fail_count "${json}" "1"
}

@test "docker_user_check: records info when docker service is unavailable and apply was deferred" {
  DOCKER_RULES_APPLIED="false"

  command() {
    if [[ "$1" == "-v" ]]; then
      case "$2" in
        iptables|docker|systemctl) return 0 ;;
      esac
    fi
    builtin command "$@"
  }
  docker() { return 0; }
  systemctl() {
    if [[ "$1" == "list-unit-files" ]]; then
      printf 'UNIT FILE STATE\n'
      return 0
    fi
    return 0
  }
  iptables() {
    echo "iptables should be skipped for deferred docker rules" >&2
    return 99
  }

  docker_user_check
  local json
  json="$(emit_validate_results_json)"
  assert_json_check_status "${json}" "docker-user: IPv4" "INFO"
  assert_json_fail_count "${json}" "0"
}

@test "docker_user_lifecycle_check: records info when Docker is not installed" {
  command() {
    if [[ "$1" == "-v" && "$2" == "docker" ]]; then
      return 1
    fi
    builtin command "$@"
  }

  docker_user_lifecycle_check
  local json
  json="$(emit_validate_results_json)"
  assert_json_check_status "${json}" "docker-user: unit file" "INFO"
  assert_json_fail_count "${json}" "0"
}

@test "fail2ban_check: records fail/info when fail2ban is absent" {
  systemctl() { return 1; }
  fail2ban_check
  local json
  json="$(emit_validate_results_json)"
  assert_json_check_status "${json}" "fail2ban: active" "FAIL"
  assert_json_fail_count "${json}" "1"
}

@test "journald_check: records journald persistence posture" {
  JOURNALD_DROPIN="$(mktemp)"
  cat > "${JOURNALD_DROPIN}" <<'EOF'
[Journal]
Storage=persistent
SystemKeepFree=500M
EOF

  journald_check
  local json
  json="$(emit_validate_results_json)"
  assert_json_check_status "${json}" "journald: persistent storage config" "PASS"
  rm -f "${JOURNALD_DROPIN}"
}

@test "ssh_check: records PASS for expected hardened sshd output" {
  sshd() {
    if [[ "$1" == "-T" ]]; then
      cat <<SSHD
permitrootlogin no
passwordauthentication no
pubkeyauthentication yes
permitemptypasswords no
compression no
ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com
macs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
kexalgorithms sntrup761x25519-sha512@openssh.com,curve25519-sha256
hostkeyalgorithms ssh-ed25519,rsa-sha2-512,rsa-sha2-256
allowusers alice
SSHD
      return 0
    fi
    return 0
  }

  ADMIN_USER="alice"
  ssh_check
  local json
  json="$(emit_validate_results_json)"
  assert_json_check_status "${json}" "ssh: permitrootlogin=no" "PASS"
  assert_json_check_status "${json}" "ssh: passwordauthentication=no" "PASS"
}

@test "sysctl_check: records PASS when expected values are present" {
  sysctl() {
    if [[ "$1" == "-n" ]]; then
      case "$2" in
        net.ipv4.tcp_syncookies|net.ipv4.ip_forward|fs.protected_hardlinks|fs.protected_symlinks|kernel.kptr_restrict|kernel.dmesg_restrict|kernel.unprivileged_bpf_disabled|net.ipv4.conf.all.accept_source_route|net.ipv4.conf.default.accept_source_route|net.ipv4.conf.all.accept_redirects|net.ipv4.conf.default.accept_redirects|net.ipv4.conf.all.secure_redirects|net.ipv4.conf.default.secure_redirects|net.ipv4.conf.all.send_redirects|net.ipv4.conf.default.send_redirects|net.ipv4.icmp_echo_ignore_broadcasts|net.ipv4.icmp_ignore_bogus_error_responses)
          echo 1 ;;
        kernel.perf_event_paranoid)
          echo 3 ;;
        kernel.yama.ptrace_scope)
          echo 1 ;;
        vm.swappiness)
          echo 10 ;;
        *)
          echo 1 ;;
      esac
      return 0
    fi
    return 0
  }

  sysctl_check
  local json
  json="$(emit_validate_results_json)"
  assert_json_check_status "${json}" "sysctl: net.ipv4.tcp_syncookies=1" "PASS"
  assert_json_check_status "${json}" "sysctl: vm.swappiness=10" "PASS"
}

@test "timesync_check: passes when timedatectl reports synchronized NTP" {
  timedatectl() {
    if [[ "$1" == "show" && "$2" == "--property=NTP" ]]; then
      echo yes
      return 0
    fi
    if [[ "$1" == "show" && "$2" == "--property=NTPSynchronized" ]]; then
      echo yes
      return 0
    fi
    return 0
  }

  timesync_check
  local json
  json="$(emit_validate_results_json)"
  assert_json_check_status "${json}" "timesync: NTP active" "PASS"
  assert_json_check_status "${json}" "timesync: NTPSynchronized" "PASS"
}

@test "tailscale_check: fails when tailscale interface is missing" {
  TAILSCALE_IFACE="tailscale0"

  ip() { return 1; }
  tailscale() { return 1; }

  tailscale_check
  local json
  json="$(emit_validate_results_json)"
  assert_json_check_status "${json}" "tailscale: tailscale0" "FAIL"
  assert_json_fail_count "${json}" "1"
}

@test "unattended_upgrades_check: fails when local policy file is missing" {
  unattended_upgrades_check
  local json
  json="$(emit_validate_results_json)"
  assert_json_check_status "${json}" "auto-updates: local config" "FAIL"
  assert_json_fail_count "${json}" "1"
}

@test "validate_timer_check: records timer state outcome" {
  systemctl() {
    if [[ "$1" == "is-enabled" ]]; then
      echo enabled
      return 0
    fi
    if [[ "$1" == "is-active" ]]; then
      return 0
    fi
    return 0
  }

  validate_timer_check
  local json
  json="$(emit_validate_results_json)"
  assert_json_check_status "${json}" "validate-timer: active" "PASS"
  assert_json_fail_count "${json}" "0"
}

@test "main: runs check pipeline and emits JSON summary" {
  parse_cli_args() { JSON_MODE="true"; }
  detect_container_runtime() { :; }
  load_state_context() { :; }
  ssh_check() { record "PASS" "ssh: ok"; }
  ufw_check() { record "PASS" "ufw: ok"; }
  docker_user_check() { record "PASS" "docker-user: ok"; }
  docker_user_lifecycle_check() { record "PASS" "docker-user-lifecycle: ok"; }
  sysctl_check() { record "PASS" "sysctl: ok"; }
  fail2ban_check() { record "PASS" "fail2ban: ok"; }
  auditd_check() { record "PASS" "auditd: ok"; }
  journald_check() { record "PASS" "journald: ok"; }
  timesync_check() { record "PASS" "timesync: ok"; }
  swap_check() { record "INFO" "swap: skipped"; }
  banner_check() { record "PASS" "banner: ok"; }
  admin_sudo_check() { record "PASS" "sudo: ok"; }
  docker_daemon_check() { record "PASS" "daemon: ok"; }
  docker_trust_boundary_check() { record "PASS" "trust: ok"; }
  apparmor_check() { record "PASS" "apparmor: ok"; }
  disabled_services_check() { record "PASS" "services: ok"; }
  tailscale_check() { record "PASS" "tailscale: ok"; }
  coolify_binding_check() { record "PASS" "binding: ok"; }
  coolify_ssh_check() { record "PASS" "coolify ssh: ok"; }
  coolify_container_check() { record "PASS" "containers: ok"; }
  validate_timer_check() { record "PASS" "timer: ok"; }
  listening_ports_info() { record "INFO" "ports: info"; }
  cloudflared_check() { record "INFO" "cloudflared: info"; }

  run main
  assert_success
  assert_output --partial '"pass"'
}
