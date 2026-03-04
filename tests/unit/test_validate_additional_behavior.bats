#!/usr/bin/env bats
# Additional behavior tests to close function coverage gaps in validate_hardening.sh

load '../helpers'

setup() {
  source_validate_script
  PASS_COUNT=0
  FAIL_COUNT=0
  INFO_COUNT=0
  RESULTS=()
  JSON_MODE="false"
}

@test "parse_cli_args: sets json mode and state file path" {
  parse_cli_args --json --state-file /tmp/state-test
  [ "${JSON_MODE}" = "true" ]
  [ "${STATE_FILE}" = "/tmp/state-test" ]
}

@test "record (runtime): increments PASS count for PASS status" {
  record "PASS" "runtime-check"
  [ "${PASS_COUNT}" -eq 1 ]
}

@test "check (runtime): records FAIL when command exits non-zero" {
  check "runtime-check" false
  [ "${FAIL_COUNT}" -eq 1 ]
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
  [ "${PASS_COUNT}" -ge 4 ]
}

@test "swap_check: reports disabled swap when swap_size is 0" {
  swap_size="0"

  swap_check
  [ "${INFO_COUNT}" -ge 1 ]
}

@test "apparmor_check: passes when aa-status reports enabled" {
  aa-status() {
    [[ "$1" == "--enabled" ]] && return 0
    return 0
  }

  apparmor_check
  [ "${PASS_COUNT}" -ge 1 ]
}

@test "listening_ports_info: records discovered listening ports" {
  ss() {
    cat <<SS
State Recv-Q Send-Q Local Address:Port Peer Address:Port Process
LISTEN 0      4096   0.0.0.0:22      0.0.0.0:*
SS
  }

  listening_ports_info
  [ "${INFO_COUNT}" -ge 1 ]
}

@test "coolify_ssh_check: returns cleanly when Coolify SSH dir is absent" {
  run coolify_ssh_check
  assert_success
}

@test "cloudflared_check: reports info when cloudflared is not installed" {
  systemctl() { return 1; }
  cloudflared_check
  [ "${INFO_COUNT}" -ge 1 ]
}

@test "coolify_container_check: reports info when Docker is missing" {
  command() {
    if [[ "$1" == "-v" && "$2" == "docker" ]]; then
      return 1
    fi
    builtin command "$@"
  }

  coolify_container_check
  [ "${INFO_COUNT}" -ge 1 ]
}

@test "admin_sudo_check: reports info when admin user is not configured" {
  ADMIN_USER=""
  admin_sudo_check
  [ "${INFO_COUNT}" -ge 1 ]
}

@test "auditd_check: executes and records audit status outcomes" {
  IS_CONTAINER="true"
  systemctl() { return 1; }
  auditctl() { return 1; }

  auditd_check
  [ $((PASS_COUNT + FAIL_COUNT + INFO_COUNT)) -ge 1 ]
}

@test "banner_check: records banner verification result" {
  banner_check
  [ $((PASS_COUNT + FAIL_COUNT)) -ge 1 ]
}

@test "coolify_binding_check: records binding guard posture" {
  coolify_binding_check
  [ $((PASS_COUNT + FAIL_COUNT + INFO_COUNT)) -ge 1 ]
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
  [ "${PASS_COUNT}" -ge 3 ]
}

@test "docker_daemon_check: records daemon config status" {
  docker_daemon_check
  [ $((PASS_COUNT + FAIL_COUNT + INFO_COUNT)) -ge 1 ]
}

@test "docker_trust_boundary_check: records info when Docker is unavailable" {
  command() {
    if [[ "$1" == "-v" && "$2" == "docker" ]]; then
      return 1
    fi
    builtin command "$@"
  }

  docker_trust_boundary_check
  [ "${INFO_COUNT}" -ge 1 ]
}

@test "docker_user_check: fails fast when iptables is unavailable" {
  command() {
    if [[ "$1" == "-v" && "$2" == "iptables" ]]; then
      return 1
    fi
    builtin command "$@"
  }

  docker_user_check
  [ "${FAIL_COUNT}" -ge 1 ]
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
  [ "${INFO_COUNT}" -ge 1 ]
  [ "${FAIL_COUNT}" -eq 0 ]
}

@test "docker_user_lifecycle_check: records info when Docker is not installed" {
  command() {
    if [[ "$1" == "-v" && "$2" == "docker" ]]; then
      return 1
    fi
    builtin command "$@"
  }

  docker_user_lifecycle_check
  [ "${INFO_COUNT}" -ge 1 ]
}

@test "fail2ban_check: records fail/info when fail2ban is absent" {
  systemctl() { return 1; }
  fail2ban_check
  [ $((FAIL_COUNT + INFO_COUNT)) -ge 1 ]
}

@test "journald_check: records journald persistence posture" {
  journald_check
  [ $((PASS_COUNT + FAIL_COUNT + INFO_COUNT)) -ge 1 ]
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
  [ "${PASS_COUNT}" -ge 5 ]
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
  [ "${PASS_COUNT}" -ge 5 ]
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
  [ "${PASS_COUNT}" -ge 2 ]
}

@test "tailscale_check: fails when tailscale interface is missing" {
  TAILSCALE_IFACE="tailscale0"

  ip() { return 1; }
  tailscale() { return 1; }

  tailscale_check
  [ "${FAIL_COUNT}" -ge 1 ]
}

@test "unattended_upgrades_check: fails when local policy file is missing" {
  unattended_upgrades_check
  [ "${FAIL_COUNT}" -ge 1 ]
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
  [ "${PASS_COUNT}" -ge 1 ]
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
