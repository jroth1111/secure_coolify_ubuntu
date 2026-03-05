#!/usr/bin/env bats
# Additional behavior tests to close function coverage gaps in bootstrap_hardening.sh

load '../helpers'

setup() {
  source_script
  systemctl() { return 0; }
  augenrules() { return 0; }
  ufw() { return 0; }
  journalctl() { return 0; }
}

@test "require_root: fails when uid is not root" {
  id() {
    if [[ "$1" == "-u" ]]; then
      echo 1000
      return 0
    fi
    command id "$@"
  }

  run require_root
  assert_failure
  assert_output --partial "Run as root."
}

@test "require_root: passes when uid is root" {
  id() {
    if [[ "$1" == "-u" ]]; then
      echo 0
      return 0
    fi
    command id "$@"
  }

  run require_root
  assert_success
}

@test "warn_on_state_version_mismatch: warns when state version differs" {
  local state
  state="$(mktemp)"
  printf 'state_version=0.0.0\n' > "${state}"

  STATE_FILE="${state}"
  SCRIPT_VERSION="1.2.3"

  run warn_on_state_version_mismatch
  assert_success
  assert_output --partial "WARN"

  rm -f "${state}"
}

@test "detect_os: passes when source reports ubuntu and FORCE bypasses version check" {
  FORCE="true"
  source() {
    ID="ubuntu"
    VERSION_ID="22.04"
    return 0
  }

  run detect_os
  assert_success
}

@test "detect_os: fails when source reports non-ubuntu distro" {
  FORCE="true"
  source() {
    ID="debian"
    VERSION_ID="12"
    return 0
  }

  run detect_os
  assert_failure
  assert_output --partial "Expected Ubuntu"
}

@test "configure_coolify_binding_watchdog: dry-run emits planned timer install" {
  DRY_RUN="true"
  BIND_DASHBOARD_TO_TAILSCALE="true"
  local tmpdir
  tmpdir="$(mktemp -d)"
  COOLIFY_BINDING_GUARD_SCRIPT="${tmpdir}/coolify-binding-guard.sh"
  COOLIFY_BINDING_GUARD_SERVICE="${tmpdir}/coolify-binding-guard.service"
  COOLIFY_BINDING_GUARD_TIMER="${tmpdir}/coolify-binding-guard.timer"

  run configure_coolify_binding_watchdog
  assert_success
  assert_output --partial "DRY-RUN"
  [ ! -f "${COOLIFY_BINDING_GUARD_SCRIPT}" ]
  [ ! -f "${COOLIFY_BINDING_GUARD_SERVICE}" ]
  [ ! -f "${COOLIFY_BINDING_GUARD_TIMER}" ]
  rm -rf "${tmpdir}"
}

@test "ensure_timesync: dry-run executes without host mutation" {
  DRY_RUN="true"
  local marker
  marker="$(mktemp)"
  rm -f "${marker}"
  timedatectl() { echo called > "${marker}"; return 0; }

  run ensure_timesync
  assert_success
  assert_output --partial "DRY-RUN"
  [ ! -f "${marker}" ]
}

@test "configure_timezone: dry-run executes without timedatectl mutation" {
  DRY_RUN="true"
  TIMEZONE="Australia/Melbourne"
  local marker
  marker="$(mktemp)"
  rm -f "${marker}"
  timedatectl() { echo called > "${marker}"; return 0; }

  run configure_timezone
  assert_success
  assert_output --partial "DRY-RUN"
  [ ! -f "${marker}" ]
}

@test "disable_unused_services: dry-run logs service disable actions" {
  DRY_RUN="true"
  local marker
  marker="$(mktemp)"
  rm -f "${marker}"
  systemctl() { echo called > "${marker}"; return 0; }

  run disable_unused_services
  assert_success
  assert_output --partial "DRY-RUN"
  [ ! -f "${marker}" ]
}

@test "configure_banner: dry-run logs banner file write" {
  DRY_RUN="true"
  local before after
  before="$(sha256sum /etc/issue.net 2>/dev/null || true)"

  run configure_banner
  assert_success
  assert_output --partial "/etc/issue.net"
  after="$(sha256sum /etc/issue.net 2>/dev/null || true)"
  [ "${before}" = "${after}" ]
}

@test "discover_docker_ssh_cidrs: collects CIDRs from docker/ip providers" {
  DRY_RUN="true"
  STRICT_DOCKER_SSH_CIDRS="true"
  DOCKER_SSH_CIDRS=()

  docker() {
    if [[ "$1" == "network" && "$2" == "ls" ]]; then
      printf 'net-a\n'
      return 0
    fi
    if [[ "$1" == "network" && "$2" == "inspect" ]]; then
      printf '172.20.0.0/16\n'
      return 0
    fi
    return 0
  }

  ip() {
    printf '7: docker0    inet 172.17.0.1/16\n'
  }

  discover_docker_ssh_cidrs
  [[ "${DOCKER_SSH_CIDRS[*]}" == *"172.20.0.0/16"* ]]
  [[ "${DOCKER_SSH_CIDRS[*]}" == *"172.17.0.1/16"* ]]
}

@test "configure_ssh: dry-run builds hardened config with docker CIDR match" {
  DRY_RUN="true"
  ADMIN_USER="coolifyadmin"
  SSH_PORT="22"
  DOCKER_SSH_CIDRS=("10.42.0.0/16")
  SSH_DROPIN_FILE="$(mktemp)"
  rm -f "${SSH_DROPIN_FILE}"

  run configure_ssh
  assert_success
  assert_output --partial "DRY-RUN"
  [ ! -f "${SSH_DROPIN_FILE}" ]
}

@test "install_docker_user_assets: dry-run logs docker-user asset writes" {
  DRY_RUN="true"
  local tmpdir
  tmpdir="$(mktemp -d)"
  DOCKER_USER_SCRIPT="${tmpdir}/docker-user-hardening.sh"
  DOCKER_USER_ENV_FILE="${tmpdir}/docker-user-hardening.env"
  DOCKER_USER_UNIT_FILE="${tmpdir}/docker-user-hardening.service"

  run install_docker_user_assets
  assert_success
  assert_output --partial "docker-user"
  [ ! -f "${DOCKER_USER_SCRIPT}" ]
  [ ! -f "${DOCKER_USER_ENV_FILE}" ]
  [ ! -f "${DOCKER_USER_UNIT_FILE}" ]
  rm -rf "${tmpdir}"
}

@test "detect_docker: marks Docker present when docker command exists with iptables backend" {
  DOCKER_PRESENT="false"

  docker() {
    if [[ "$1" == "info" ]]; then
      printf 'Server:\n Firewall: iptables\n iptables: true\n'
      return 0
    fi
    return 0
  }

  detect_docker
  [ "${DOCKER_PRESENT}" = "true" ]
}

@test "detect_docker: fails when docker reports nftables backend" {
  run bash -c '
    source "'"${SCRIPT}"'"
    docker() {
      if [[ "$1" == "info" ]]; then
        printf "Server:\n firewall: nftables\n"
        return 0
      fi
      return 0
    }
    detect_docker
  '
  assert_failure
  assert_output --partial "nftables backend detected"
}

@test "configure_docker_user: dry-run installs/enables service without failure" {
  DRY_RUN="true"
  DOCKER_PRESENT="false"
  local tmpdir
  tmpdir="$(mktemp -d)"
  DOCKER_USER_SCRIPT="${tmpdir}/docker-user-hardening.sh"
  DOCKER_USER_ENV_FILE="${tmpdir}/docker-user-hardening.env"
  DOCKER_USER_UNIT_FILE="${tmpdir}/docker-user-hardening.service"

  run configure_docker_user
  assert_success
  assert_output --partial "docker-user"
  [ ! -f "${DOCKER_USER_SCRIPT}" ]
  [ ! -f "${DOCKER_USER_ENV_FILE}" ]
  [ ! -f "${DOCKER_USER_UNIT_FILE}" ]
  rm -rf "${tmpdir}"
}

@test "configure_auditd_policy: updates auditd.conf keys" {
  local conf
  conf="$(mktemp)"
  printf 'max_log_file_action = rotate\n' > "${conf}"

  AUDITD_CONF_FILE="${conf}"
  DRY_RUN="false"

  configure_auditd_policy

  run grep -q '^max_log_file_action = keep_logs$' "${conf}"
  assert_success
  run grep -q '^space_left = 100$' "${conf}"
  assert_success

  rm -f "${conf}"
}

@test "configure_auditd: dry-run renders rules and logs planned actions" {
  DRY_RUN="true"
  AUDIT_RULES_FILE="$(mktemp)"
  rm -f "${AUDIT_RULES_FILE}"

  run configure_auditd
  assert_success
  assert_output --partial "DRY-RUN"
  [ ! -f "${AUDIT_RULES_FILE}" ]
}

@test "generate_report: dry-run exits cleanly without writing report file" {
  DRY_RUN="true"
  REPORT_FILE="$(mktemp)"
  rm -f "${REPORT_FILE}"

  run generate_report
  assert_success
  assert_output --partial "DRY-RUN"
  [ ! -f "${REPORT_FILE}" ]
}

@test "is_container_runtime: returns success when container env is docker" {
  container="docker"

  run is_container_runtime
  assert_success
}

@test "configure_docker_ssh_cidr_sync_timer: dry-run reports timer install" {
  DRY_RUN="true"
  STRICT_DOCKER_SSH_CIDRS="true"
  local tmpdir
  tmpdir="$(mktemp -d)"
  DOCKER_SSH_CIDR_SYNC_SCRIPT="${tmpdir}/docker-ssh-cidr-sync.sh"
  DOCKER_SSH_CIDR_SYNC_SERVICE="${tmpdir}/docker-ssh-cidr-sync.service"
  DOCKER_SSH_CIDR_SYNC_TIMER="${tmpdir}/docker-ssh-cidr-sync.timer"

  run configure_docker_ssh_cidr_sync_timer
  assert_success
  assert_output --partial "docker-ssh-cidr-sync.timer"
  [ ! -f "${DOCKER_SSH_CIDR_SYNC_SCRIPT}" ]
  [ ! -f "${DOCKER_SSH_CIDR_SYNC_SERVICE}" ]
  [ ! -f "${DOCKER_SSH_CIDR_SYNC_TIMER}" ]
  rm -rf "${tmpdir}"
}

@test "configure_swap: dry-run logs swap provisioning actions" {
  DRY_RUN="true"
  SWAP_SIZE="2G"
  swapoff() { return 0; }

  run configure_swap
  assert_success
  assert_output --partial "DRY-RUN"
  [ ! -f /swapfile ]
}

@test "configure_sysctl: dry-run logs sysctl drop-in write" {
  DRY_RUN="true"
  SYSCTL_DROPIN_FILE="$(mktemp)"
  rm -f "${SYSCTL_DROPIN_FILE}"

  run configure_sysctl
  assert_success
  assert_output --partial "sysctl"
  [ ! -f "${SYSCTL_DROPIN_FILE}" ]
}

@test "configure_ufw: dry-run logs firewall rule reconciliation" {
  DRY_RUN="true"
  SSH_PORT="22"
  TAILSCALE_IFACE="tailscale0"
  WAN_IFACE="eth0"
  TUNNEL_MODE="false"
  TAILSCALE_DIRECT_WAN="false"
  DOCKER_SSH_CIDRS=("10.0.0.0/8")
  local marker
  marker="$(mktemp)"
  rm -f "${marker}"
  ufw() { echo called > "${marker}"; return 0; }

  run configure_ufw
  assert_success
  assert_output --partial "DRY-RUN"
  [ ! -f "${marker}" ]
}

@test "configure_fail2ban: dry-run logs jail configuration and service action" {
  DRY_RUN="true"
  SSH_PORT="22"
  TAILSCALE_CIDR="100.64.0.0/10"
  FAIL2BAN_JAIL_FILE="$(mktemp)"
  rm -f "${FAIL2BAN_JAIL_FILE}"

  run configure_fail2ban
  assert_success
  assert_output --partial "DRY-RUN"
  assert_output --partial "fail2ban"
  [ ! -f "${FAIL2BAN_JAIL_FILE}" ]
}

@test "configure_journald: dry-run logs journald configuration changes" {
  DRY_RUN="true"
  JOURNALD_DROPIN_FILE="$(mktemp)"
  rm -f "${JOURNALD_DROPIN_FILE}"

  run configure_journald
  assert_success
  assert_output --partial "DRY-RUN"
  [ ! -f "${JOURNALD_DROPIN_FILE}" ]
}

@test "ensure_logrotate_create_directive: inserts create line once and remains idempotent" {
  DRY_RUN="false"
  local conf
  conf="$(mktemp)"
  cat > "${conf}" <<'EOF'
/var/log/example.log
{
	rotate 4
	weekly
	delaycompress
	sharedscripts
}
EOF

  run ensure_logrotate_create_directive "${conf}" "adm"
  assert_success
  run grep -c "create 640 syslog adm" "${conf}"
  assert_success
  assert_output "1"

  ensure_logrotate_create_directive "${conf}" "adm"
  run grep -c "create 640 syslog adm" "${conf}"
  assert_success
  assert_output "1"

  rm -f "${conf}"
}

@test "configure_rsyslog_targets: dry-run reports planned remediation and skips systemctl execution" {
  DRY_RUN="true"
  rsyslog_collect_log_targets() {
    printf '%s\n' "/var/log/ufw.log" "/var/log/mail.log"
  }
  ensure_logrotate_create_directive() {
    echo "patched $1"
  }
  getent() { return 0; }

  local marker
  marker="$(mktemp)"
  rm -f "${marker}"
  systemctl() { echo called > "${marker}"; return 0; }

  run configure_rsyslog_targets
  assert_success
  assert_output --partial "DRY-RUN: ensure /var/log is root:syslog mode 0770"
  assert_output --partial "DRY-RUN: ensure /var/log/ufw.log exists (0640 syslog:adm)"
  assert_output --partial "patched /etc/logrotate.d/ufw"
  [ ! -f "${marker}" ]
}

@test "configure_docker_daemon: skips when Docker absent" {
  DRY_RUN="true"
  DOCKER_PRESENT="false"

  run configure_docker_daemon
  assert_success
  assert_output --partial "Docker not present"
}

@test "run_post_checks: dry-run bypasses live host assertions" {
  DRY_RUN="true"
  die() { echo "unexpected-die"; return 99; }

  run run_post_checks
  assert_success
  assert_output --partial "post-apply checks skipped"
  refute_output --partial "unexpected-die"
}

@test "on_err: reports failing command context" {
  run on_err 123 "failing-command"
  assert_failure
  assert_output --partial "line 123"
  assert_output --partial "failing-command"
}

@test "main: executes orchestration with stubbed phase functions" {
  run bash -c '
    source "'"${SCRIPT}"'"
    parse_args() { :; }
    require_root() { :; }
    setup_logging() { :; }
    warn_on_state_version_mismatch() { :; }
    validate_inputs() { :; }
    detect_os() { :; }
    check_disk_space() { :; }
    configure_timezone() { :; }
    ensure_timesync() { :; }
    detect_wan_iface() { :; }
    ssh_session_safety_gate() { :; }
    ensure_packages() { :; }
    require_commands() { :; }
    verify_tailscale_iface() { :; }
    detect_docker() { :; }
    discover_docker_ssh_cidrs() { :; }
    configure_swap() { :; }
    disable_unused_services() { :; }
    configure_banner() { :; }
    ensure_admin_access() { :; }
    configure_ssh() { :; }
    configure_auditd() { :; }
    configure_sysctl() { :; }
    configure_ufw() { :; }
    configure_rsyslog_targets() { :; }
    configure_docker_daemon() { :; }
    configure_docker_user() { :; }
    configure_fail2ban() { :; }
    configure_journald() { :; }
    configure_unattended_upgrades() { :; }
    configure_hardening_validation_timer() { :; }
    write_state() { :; }
    configure_docker_ssh_cidr_sync_timer() { :; }
    run_post_checks() { :; }
    generate_report() { :; }
    get_tailscale_ip() { DETECTED_TAILSCALE_IP=\"100.64.0.10\"; return 0; }
    tailscale() { [[ \"$1\" == \"ip\" && \"$2\" == \"-4\" ]] && echo \"100.64.0.10\"; }
    main
  '
  assert_success
  assert_output --partial "HARDEN_RESULT_TAILSCALE_IP=100.64.0.10"
}
