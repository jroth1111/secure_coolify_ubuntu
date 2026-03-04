#!/usr/bin/env bats
# Robust outcome checks for critical validate_hardening.sh security checks.

load '../helpers'

setup() {
  source_validate_script
  PASS_COUNT=0
  FAIL_COUNT=0
  INFO_COUNT=0
  RESULTS=()
  JSON_MODE="false"
}

@test "validate runtime is_true: true returns success" {
  run is_true "true"
  assert_success
}

@test "validate runtime is_true: false returns failure" {
  run is_true "false"
  assert_failure
}

@test "ufw_check: fails when dashboard is exposed on WAN interface" {
  run bash -c '
    source "'"${VALIDATE_SCRIPT}"'"
    PASS_COUNT=0
    FAIL_COUNT=0
    INFO_COUNT=0
    RESULTS=()
    JSON_MODE="false"

    SSH_PORT="22"
    TAILSCALE_IFACE="tailscale0"
    WAN_IFACE="eth0"
    TUNNEL_MODE="false"
    TAILSCALE_DIRECT_WAN="false"
    DOCKER_SSH_CIDRS="10.0.0.0/8"

    ufw() {
      if [[ "$1" == "status" ]]; then
        cat <<UFW
Status: active
22/tcp                     ALLOW IN    on tailscale0
22                         ALLOW       10.0.0.0/8
8000/tcp                   ALLOW IN    on tailscale0
6001/tcp                   ALLOW IN    on tailscale0
6002/tcp                   ALLOW IN    on tailscale0
8000/tcp                   ALLOW IN    on eth0
UFW
        return 0
      fi
      return 0
    }

    ufw_check
  '
  assert_success
  assert_output --partial "[FAIL]"
  assert_output --partial "ufw: dashboard (8000) NOT on WAN"
}

@test "ssh_check: fails when external root login is allowed" {
  run bash -c '
    source "'"${VALIDATE_SCRIPT}"'"
    PASS_COUNT=0
    FAIL_COUNT=0
    INFO_COUNT=0
    RESULTS=()
    JSON_MODE="false"
    ADMIN_USER="alice"
    DOCKER_SSH_CIDRS="10.0.0.0/8"

    sshd() {
      if [[ "$1" == "-T" && "${2:-}" != "-C" ]]; then
        cat <<SSHD
permitrootlogin no
passwordauthentication no
pubkeyauthentication yes
permitemptypasswords no
compression no
ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com
macs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
kexalgorithms sntrup761x25519-sha512@openssh.com,curve25519-sha256
hostkeyalgorithms ssh-ed25519,rsa-sha2-512,rsa-sha2-256
allowusers alice
SSHD
        return 0
      fi

      if [[ "$1" == "-T" && "$2" == "-C" && "$3" == "addr=127.0.0.1,user=root,host=localhost,laddr=127.0.0.1" ]]; then
        cat <<LOCAL
permitrootlogin prohibit-password
allowusers alice root
LOCAL
        return 0
      fi

      if [[ "$1" == "-T" && "$2" == "-C" && "$3" == "addr=203.0.113.1,user=root,host=example.com,laddr=0.0.0.0" ]]; then
        cat <<EXT
permitrootlogin yes
allowusers alice
EXT
        return 0
      fi

      return 1
    }

    ssh_check
  '
  assert_success
  assert_output --partial "[FAIL]"
  assert_output --partial "ssh: external root login"
}

@test "docker_user_check: fails when wan-drop rule is missing" {
  run bash -c '
    source "'"${VALIDATE_SCRIPT}"'"
    PASS_COUNT=0
    FAIL_COUNT=0
    INFO_COUNT=0
    RESULTS=()
    JSON_MODE="false"
    TUNNEL_MODE="false"
    DOCKER_RULES_APPLIED="true"

    command() {
      if [[ "$1" == "-v" ]]; then
        case "$2" in
          iptables|docker|systemctl) return 0 ;;
        esac
      fi
      builtin command "$@"
    }

    docker() {
      if [[ "$1" == "info" ]]; then
        cat <<INFO
Server:
 Containers: 1
INFO
        return 0
      fi
      return 0
    }

    systemctl() { return 0; }

    iptables() {
      if [[ "$1" == "-t" && "$2" == "filter" && "$3" == "-S" && "$4" == "DOCKER-USER" ]]; then
        cat <<RULES
-N DOCKER-USER
-A DOCKER-USER -m comment --comment coolify-hardening-bridge-docker0 -j RETURN
RULES
        return 0
      fi
      return 0
    }

    docker_user_check
  '
  assert_success
  assert_output --partial "[FAIL]"
  assert_output --partial "docker-user: IPv4 wan-drop"
}

@test "docker_user_check: fails in tunnel mode when wan-web rule exists" {
  run bash -c '
    source "'"${VALIDATE_SCRIPT}"'"
    PASS_COUNT=0
    FAIL_COUNT=0
    INFO_COUNT=0
    RESULTS=()
    JSON_MODE="false"
    TUNNEL_MODE="true"
    DOCKER_RULES_APPLIED="true"

    command() {
      if [[ "$1" == "-v" ]]; then
        case "$2" in
          iptables|docker|systemctl) return 0 ;;
        esac
      fi
      builtin command "$@"
    }

    docker() {
      if [[ "$1" == "info" ]]; then
        echo "iptables: true"
        return 0
      fi
      return 0
    }

    systemctl() { return 0; }

    iptables() {
      if [[ "$1" == "-t" && "$2" == "filter" && "$3" == "-S" && "$4" == "DOCKER-USER" ]]; then
        cat <<RULES
-N DOCKER-USER
-A DOCKER-USER -m comment --comment coolify-hardening-wan-drop -j DROP
-A DOCKER-USER -m comment --comment coolify-hardening-bridge-docker0 -j RETURN
-A DOCKER-USER -m comment --comment coolify-hardening-wan-web -p tcp --dport 8000 -j ACCEPT
RULES
        return 0
      fi
      return 0
    }

    docker_user_check
  '
  assert_success
  assert_output --partial "[FAIL]"
  assert_output --partial "docker-user: tunnel-mode no wan-web"
}

@test "sysctl_check: fails when hardened value deviates from expected" {
  run bash -c '
    source "'"${VALIDATE_SCRIPT}"'"
    PASS_COUNT=0
    FAIL_COUNT=0
    INFO_COUNT=0
    RESULTS=()
    JSON_MODE="false"
    IS_CONTAINER="false"

    sysctl() {
      if [[ "$1" == "-n" ]]; then
        case "$2" in
          net.ipv4.ip_forward) echo 0 ;;
          net.ipv4.conf.all.rp_filter) echo 2 ;;
          net.ipv4.tcp_max_syn_backlog) echo 2048 ;;
          net.ipv4.tcp_synack_retries) echo 2 ;;
          fs.suid_dumpable) echo 0 ;;
          kernel.unprivileged_bpf_disabled) echo 2 ;;
          kernel.kexec_load_disabled) echo 1 ;;
          kernel.sysrq) echo 4 ;;
          kernel.randomize_va_space) echo 2 ;;
          kernel.kptr_restrict) echo 2 ;;
          kernel.perf_event_paranoid) echo 3 ;;
          kernel.yama.ptrace_scope) echo 1 ;;
          vm.swappiness) echo 10 ;;
          net.ipv4.tcp_congestion_control) echo bbr ;;
          net.core.default_qdisc) echo fq ;;
          *) echo 1 ;;
        esac
        return 0
      fi
      return 0
    }

    sysctl_check
  '
  assert_success
  assert_output --partial "[FAIL]"
  assert_output --partial "sysctl: net.ipv4.ip_forward"
}

@test "auditd_check: fails when max_log_file_action is not keep_logs" {
  run bash -c '
    source "'"${VALIDATE_SCRIPT}"'"
    PASS_COUNT=0
    FAIL_COUNT=0
    INFO_COUNT=0
    RESULTS=()
    JSON_MODE="false"
    IS_CONTAINER="false"

    tmp_auditd_conf="$(mktemp)"
    cat > "${tmp_auditd_conf}" <<CONF
max_log_file_action = rotate
disk_full_action = suspend
disk_error_action = suspend
space_left = 100
space_left_action = syslog
admin_space_left = 50
admin_space_left_action = suspend
CONF
    AUDITD_CONF="${tmp_auditd_conf}"

    systemctl() { return 0; }
    auditctl() {
      if [[ "$1" == "-l" ]]; then
        cat <<RULES
-a always,exit -F arch=b64 -S sethostname -k identity
-a always,exit -F arch=b64 -S chmod -k sudoers-change
-a always,exit -F arch=b64 -S init_module -k kernel-module
-a always,exit -F arch=b64 -S execve -k user_commands
RULES
        return 0
      fi
      if [[ "$1" == "-s" ]]; then
        cat <<STATUS
lost 0
backlog 0
STATUS
        return 0
      fi
      return 1
    }

    auditd_check
    rm -f "${tmp_auditd_conf}"
  '
  assert_success
  assert_output --partial "[FAIL]"
  assert_output --partial "auditd: max_log_file_action"
}

@test "auditd_check: fails when queue loss exceeds threshold" {
  run bash -c '
    source "'"${VALIDATE_SCRIPT}"'"
    PASS_COUNT=0
    FAIL_COUNT=0
    INFO_COUNT=0
    RESULTS=()
    JSON_MODE="false"
    IS_CONTAINER="false"

    tmp_auditd_conf="$(mktemp)"
    cat > "${tmp_auditd_conf}" <<CONF
max_log_file_action = keep_logs
disk_full_action = suspend
disk_error_action = suspend
space_left = 100
space_left_action = syslog
admin_space_left = 50
admin_space_left_action = suspend
CONF
    AUDITD_CONF="${tmp_auditd_conf}"

    systemctl() { return 0; }
    auditctl() {
      if [[ "$1" == "-l" ]]; then
        cat <<RULES
-a always,exit -F arch=b64 -S sethostname -k identity
-a always,exit -F arch=b64 -S chmod -k sudoers-change
-a always,exit -F arch=b64 -S init_module -k kernel-module
-a always,exit -F arch=b64 -S execve -k user_commands
RULES
        return 0
      fi
      if [[ "$1" == "-s" ]]; then
        cat <<STATUS
lost 101
backlog 7
STATUS
        return 0
      fi
      return 1
    }

    auditd_check
    rm -f "${tmp_auditd_conf}"
  '
  assert_success
  assert_output --partial "[FAIL]"
  assert_output --partial "auditd: queue loss"
}

@test "admin_sudo_check: fails when configured admin user does not exist" {
  run bash -c '
    source "'"${VALIDATE_SCRIPT}"'"
    PASS_COUNT=0
    FAIL_COUNT=0
    INFO_COUNT=0
    RESULTS=()
    JSON_MODE="false"
    ADMIN_USER="missingadmin"

    id() {
      if [[ "$1" == "missingadmin" ]]; then
        return 1
      fi
      command id "$@"
    }

    admin_sudo_check
  '
  assert_success
  assert_output --partial "[FAIL]"
  assert_output --partial "admin: user"
}

@test "apparmor_check: fails when aa-status is unavailable outside container" {
  run bash -c '
    source "'"${VALIDATE_SCRIPT}"'"
    PASS_COUNT=0
    FAIL_COUNT=0
    INFO_COUNT=0
    RESULTS=()
    JSON_MODE="false"
    IS_CONTAINER="false"

    command() {
      if [[ "$1" == "-v" && "$2" == "aa-status" ]]; then
        return 1
      fi
      builtin command "$@"
    }

    apparmor_check
  '
  assert_success
  assert_output --partial "[FAIL]"
  assert_output --partial "apparmor: aa-status"
}

@test "banner_check: fails when AUTHORIZED marker is missing" {
  run bash -c '
    source "'"${VALIDATE_SCRIPT}"'"
    PASS_COUNT=0
    FAIL_COUNT=0
    INFO_COUNT=0
    RESULTS=()
    JSON_MODE="false"

    grep() { return 1; }

    banner_check
  '
  assert_success
  assert_output --partial "[FAIL]"
  assert_output --partial "banner: /etc/issue.net"
}

@test "cloudflared_check: fails when service is installed but inactive" {
  run bash -c '
    source "'"${VALIDATE_SCRIPT}"'"
    PASS_COUNT=0
    FAIL_COUNT=0
    INFO_COUNT=0
    RESULTS=()
    JSON_MODE="false"

    command() {
      if [[ "$1" == "-v" && "$2" == "cloudflared" ]]; then
        return 0
      fi
      builtin command "$@"
    }

    systemctl() {
      if [[ "$1" == "list-unit-files" ]]; then
        echo "cloudflared.service enabled"
        return 0
      fi
      if [[ "$1" == "is-active" && "$2" == "--quiet" && "$3" == "cloudflared" ]]; then
        return 1
      fi
      if [[ "$1" == "is-active" && "$2" == "cloudflared" ]]; then
        echo "inactive"
        return 3
      fi
      return 0
    }

    cloudflared_check
  '
  assert_success
  assert_output --partial "[FAIL]"
  assert_output --partial "cloudflared: service active"
}

@test "coolify_binding_check: fails when dashboard binding is enabled but ufw is missing" {
  run bash -c '
    source "'"${VALIDATE_SCRIPT}"'"
    PASS_COUNT=0
    FAIL_COUNT=0
    INFO_COUNT=0
    RESULTS=()
    JSON_MODE="false"
    BIND_DASHBOARD_TO_TAILSCALE="true"

    command() {
      if [[ "$1" == "-v" && "$2" == "ufw" ]]; then
        return 1
      fi
      builtin command "$@"
    }

    coolify_binding_check
  '
  assert_success
  assert_output --partial "[FAIL]"
  assert_output --partial "coolify: ufw"
}

@test "coolify_container_check: skips cleanly when Coolify data directory is absent" {
  run bash -c '
    source "'"${VALIDATE_SCRIPT}"'"
    PASS_COUNT=0
    FAIL_COUNT=0
    INFO_COUNT=0
    RESULTS=()
    JSON_MODE="false"

    command() {
      if [[ "$1" == "-v" && "$2" == "docker" ]]; then
        return 0
      fi
      builtin command "$@"
    }

    coolify_container_check
    [[ "${PASS_COUNT}" -eq 0 ]]
    [[ "${FAIL_COUNT}" -eq 0 ]]
    [[ "${INFO_COUNT}" -eq 0 ]]
  '
  assert_success
}

@test "coolify_ssh_check: no-ops when Coolify ssh key directory is absent" {
  run bash -c '
    source "'"${VALIDATE_SCRIPT}"'"
    PASS_COUNT=0
    FAIL_COUNT=0
    INFO_COUNT=0
    RESULTS=()
    JSON_MODE="false"

    coolify_ssh_check
    [[ "${PASS_COUNT}" -eq 0 ]]
    [[ "${FAIL_COUNT}" -eq 0 ]]
    [[ "${INFO_COUNT}" -eq 0 ]]
  '
  assert_success
}

@test "disabled_services_check: fails when rpcbind service is enabled" {
  run bash -c '
    source "'"${VALIDATE_SCRIPT}"'"
    PASS_COUNT=0
    FAIL_COUNT=0
    INFO_COUNT=0
    RESULTS=()
    JSON_MODE="false"

    systemctl() {
      if [[ "$1" == "is-enabled" ]]; then
        case "$2" in
          rpcbind.service) echo "enabled"; return 0 ;;
          *) echo "masked"; return 0 ;;
        esac
      fi
      return 0
    }

    disabled_services_check
  '
  assert_success
  assert_output --partial "[FAIL]"
  assert_output --partial "disabled: rpcbind"
}

@test "docker_daemon_check: fails when Docker is installed but daemon.json is missing" {
  run bash -c '
    source "'"${VALIDATE_SCRIPT}"'"
    PASS_COUNT=0
    FAIL_COUNT=0
    INFO_COUNT=0
    RESULTS=()
    JSON_MODE="false"

    command() {
      if [[ "$1" == "-v" && "$2" == "docker" ]]; then
        return 0
      fi
      builtin command "$@"
    }

    docker_daemon_check
  '
  assert_success
  assert_output --partial "[FAIL]"
  assert_output --partial "docker-daemon: daemon.json"
}

@test "docker_trust_boundary_check: records INFO when docker socket is absent" {
  run bash -c '
    source "'"${VALIDATE_SCRIPT}"'"
    PASS_COUNT=0
    FAIL_COUNT=0
    INFO_COUNT=0
    RESULTS=()
    JSON_MODE="false"

    command() {
      if [[ "$1" == "-v" && "$2" == "docker" ]]; then
        return 0
      fi
      builtin command "$@"
    }

    docker_trust_boundary_check
  '
  assert_success
  assert_output --partial "[INFO]"
  assert_output --partial "docker-trust: socket"
}

@test "docker_user_lifecycle_check: fails when docker-user-hardening unit is missing" {
  run bash -c '
    source "'"${VALIDATE_SCRIPT}"'"
    PASS_COUNT=0
    FAIL_COUNT=0
    INFO_COUNT=0
    RESULTS=()
    JSON_MODE="false"

    command() {
      if [[ "$1" == "-v" && "$2" == "docker" ]]; then
        return 0
      fi
      builtin command "$@"
    }

    docker_user_lifecycle_check
  '
  assert_success
  assert_output --partial "[FAIL]"
  assert_output --partial "docker-user: unit file"
}

@test "fail2ban_check: fails when fail2ban service is inactive" {
  run bash -c '
    source "'"${VALIDATE_SCRIPT}"'"
    PASS_COUNT=0
    FAIL_COUNT=0
    INFO_COUNT=0
    RESULTS=()
    JSON_MODE="false"

    systemctl() { return 1; }

    fail2ban_check
  '
  assert_success
  assert_output --partial "[FAIL]"
  assert_output --partial "fail2ban: active"
}

@test "journald_check: fails when persistent drop-in is missing" {
  run bash -c '
    source "'"${VALIDATE_SCRIPT}"'"
    PASS_COUNT=0
    FAIL_COUNT=0
    INFO_COUNT=0
    RESULTS=()
    JSON_MODE="false"
    JOURNALD_DROPIN="/tmp/nonexistent-journald-dropin.conf"

    journald_check
  '
  assert_success
  assert_output --partial "[FAIL]"
  assert_output --partial "journald: persistent storage config"
}

@test "swap_check: fails when swap is expected but inactive" {
  run bash -c '
    source "'"${VALIDATE_SCRIPT}"'"
    PASS_COUNT=0
    FAIL_COUNT=0
    INFO_COUNT=0
    RESULTS=()
    JSON_MODE="false"
    IS_CONTAINER="false"
    swap_size="2G"

    swapon() { return 0; }

    swap_check
  '
  assert_success
  assert_output --partial "[FAIL]"
  assert_output --partial "swap: active"
}

@test "tailscale_check: fails when BackendState is not Running" {
  run bash -c '
    source "'"${VALIDATE_SCRIPT}"'"
    PASS_COUNT=0
    FAIL_COUNT=0
    INFO_COUNT=0
    RESULTS=()
    JSON_MODE="false"
    TAILSCALE_IFACE="tailscale0"

    ip() {
      if [[ "$1" == "link" && "$2" == "show" && "$3" == "tailscale0" ]]; then
        return 0
      fi
      return 1
    }

    command() {
      if [[ "$1" == "-v" && "$2" == "tailscale" ]]; then
        return 0
      fi
      builtin command "$@"
    }

    tailscale() {
      if [[ "$1" == "status" && "$2" == "--json" ]]; then
        cat <<TS
{"BackendState":"Stopped","Peer":[]}
TS
        return 0
      fi
      if [[ "$1" == "ip" && "$2" == "-4" ]]; then
        return 0
      fi
      return 0
    }

    tailscale_check
  '
  assert_success
  assert_output --partial "[FAIL]"
  assert_output --partial "tailscale: BackendState"
}

@test "timesync_check: fails when NTP is inactive outside container" {
  run bash -c '
    source "'"${VALIDATE_SCRIPT}"'"
    PASS_COUNT=0
    FAIL_COUNT=0
    INFO_COUNT=0
    RESULTS=()
    JSON_MODE="false"
    IS_CONTAINER="false"

    timedatectl() {
      if [[ "$1" == "show" && "$2" == "--property=NTP" ]]; then
        echo no
        return 0
      fi
      if [[ "$1" == "show" && "$2" == "--property=NTPSynchronized" ]]; then
        echo no
        return 0
      fi
      return 0
    }

    timesync_check
  '
  assert_success
  assert_output --partial "[FAIL]"
  assert_output --partial "timesync: NTP"
}

@test "unattended_upgrades_check: records a fail outcome when validation preconditions are not met" {
  run bash -c '
    source "'"${VALIDATE_SCRIPT}"'"
    PASS_COUNT=0
    FAIL_COUNT=0
    INFO_COUNT=0
    RESULTS=()
    JSON_MODE="false"

    # Guarantee timer-related failures if local config exists; still fail fast if config is absent.
    systemctl() { return 1; }

    unattended_upgrades_check
    [[ "${FAIL_COUNT}" -ge 1 ]]
  '
  assert_success
}

@test "validate_timer_check: fails when timer is installed but inactive" {
  run bash -c '
    source "'"${VALIDATE_SCRIPT}"'"
    PASS_COUNT=0
    FAIL_COUNT=0
    INFO_COUNT=0
    RESULTS=()
    JSON_MODE="false"

    systemctl() {
      if [[ "$1" == "is-active" && "$2" == "--quiet" && "$3" == "hardening-validate.timer" ]]; then
        return 1
      fi
      if [[ "$1" == "list-unit-files" ]]; then
        echo "hardening-validate.timer enabled"
        return 0
      fi
      return 1
    }

    validate_timer_check
  '
  assert_success
  assert_output --partial "[FAIL]"
  assert_output --partial "validate-timer: active"
}
