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

@test "configure_coolify_binding_watchdog: generated guard skips host-local public IP probing" {
  DRY_RUN="false"
  BIND_DASHBOARD_TO_TAILSCALE="true"
  local tmpdir
  tmpdir="$(mktemp -d)"
  COOLIFY_BINDING_GUARD_SCRIPT="${tmpdir}/coolify-binding-guard.sh"
  COOLIFY_BINDING_GUARD_SERVICE="${tmpdir}/coolify-binding-guard.service"
  COOLIFY_BINDING_GUARD_TIMER="${tmpdir}/coolify-binding-guard.timer"
  systemctl() { return 0; }

  run configure_coolify_binding_watchdog
  assert_success
  run grep -q 'public IP' "${COOLIFY_BINDING_GUARD_SCRIPT}"
  assert_failure
  run grep -q 'nc -z -w2' "${COOLIFY_BINDING_GUARD_SCRIPT}"
  assert_failure

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

@test "normalize_private_hosts_file: removes private dashboard loopback overrides and keeps short hostname alias" {
  local hosts_file
  hosts_file="$(mktemp)"
  cat > "${hosts_file}" <<'EOF'
127.0.0.1 localhost vps.example.com ws.vps.example.com

# The following lines are desirable for IPv6 capable hosts
::1 ip6-localhost ip6-loopback
EOF

  HOSTS_FILE="${hosts_file}"
  DOMAIN="vps.example.com"
  DRY_RUN="false"
  hostname() {
    if [[ "${1:-}" == "-s" ]]; then
      echo "vps"
      return 0
    fi
    echo "vps.example.com"
  }

  run normalize_private_hosts_file
  assert_success
  run grep -q '^127\.0\.0\.1 localhost$' "${hosts_file}"
  assert_success
  run grep -q '^127\.0\.1\.1 vps$' "${hosts_file}"
  assert_success
  run grep -q 'vps\.example\.com' "${hosts_file}"
  assert_failure

  rm -f "${hosts_file}"
}

@test "configure_networkd_wait_online: dry-run disables stray networkd units when ifupdown is authoritative" {
  DRY_RUN="true"
  NETWORKD_WAIT_ONLINE_DROPIN="$(mktemp)"
  rm -f "${NETWORKD_WAIT_ONLINE_DROPIN}"
  trap 'rm -f "${NETWORKD_WAIT_ONLINE_DROPIN}"' RETURN

  unit_available() { return 0; }
  ifupdown_is_authoritative() { return 0; }

  run configure_networkd_wait_online
  assert_success
  assert_output --partial "systemd-networkd-wait-online"
  assert_output --partial "systemctl stop systemd-networkd.socket systemd-networkd.service networkd-dispatcher.service"
  assert_output --partial "systemctl disable systemd-networkd.socket systemd-networkd.service networkd-dispatcher.service"
  assert_output --partial "ifupdown is authoritative"
  [ ! -f "${NETWORKD_WAIT_ONLINE_DROPIN}" ]
}

@test "write_state: persists domain for later validation" {
  local tmpdir
  tmpdir="$(mktemp -d)"
  STATE_DIR="${tmpdir}"
  STATE_FILE="${tmpdir}/state"
  ADMIN_USER="coolifyadmin"
  DOMAIN="vps.example.com"
  WAN_IFACE="eth0"
  SSH_PORT="22"
  TAILSCALE_CIDR="100.64.0.0/10"
  TUNNEL_MODE="true"
  SWAP_SIZE="2G"
  JOURNAL_RETENTION="3month"
  UPDATE_PROFILE="security-only"
  TIMEZONE="UTC"
  STRICT_DOCKER_SSH_CIDRS="true"
  DOCKER_SSH_CIDRS=("172.20.0.0/16")
  DOCKER_NPROC_HARD="8192"
  DOCKER_NPROC_SOFT="4096"
  ALLOWED_PRIVILEGED_CONTAINERS=""
  TAILSCALE_DIRECT_WAN="false"
  BIND_DASHBOARD_TO_TAILSCALE="false"
  INSTALL_TAILSCALE="true"
  DRY_RUN="false"

  write_state
  run grep -q '^domain=vps\.example\.com$' "${STATE_FILE}"
  assert_success

  rm -rf "${tmpdir}"
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

@test "configure_ssh: successful apply prunes stale backup artifacts" {
  DRY_RUN="false"
  ADMIN_USER="coolifyadmin"
  SSH_PORT="22"
  DOCKER_SSH_CIDRS=("10.42.0.0/16")
  local tmpdir
  tmpdir="$(mktemp -d)"
  SSH_DROPIN_FILE="${tmpdir}/00-coolify-hardening.conf"
  printf 'old ssh config\n' > "${SSH_DROPIN_FILE}"

  install() {
    if [[ "${1:-}" == "-d" && "${4:-}" == "/run/sshd" ]]; then
      return 0
    fi
    command install "$@"
  }
  sshd() { return 0; }
  assert_sshd_effective() { return 0; }
  assert_sshd_match_localhost() { return 0; }
  reload_ssh_service() { return 0; }

  run configure_ssh
  assert_success
  run compgen -G "${SSH_DROPIN_FILE}.bak.*"
  assert_failure

  rm -rf "${tmpdir}"
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

@test "configure_docker_ssh_cidr_sync_timer: installed script prunes stale ssh backup artifacts" {
  DRY_RUN="false"
  STRICT_DOCKER_SSH_CIDRS="true"
  local tmpdir
  tmpdir="$(mktemp -d)"
  DOCKER_SSH_CIDR_SYNC_SCRIPT="${tmpdir}/docker-ssh-cidr-sync.sh"
  DOCKER_SSH_CIDR_SYNC_SERVICE="${tmpdir}/docker-ssh-cidr-sync.service"
  DOCKER_SSH_CIDR_SYNC_TIMER="${tmpdir}/docker-ssh-cidr-sync.timer"
  systemctl() { return 0; }

  run configure_docker_ssh_cidr_sync_timer
  assert_success
  run grep -F 'rm -f "${SSH_DROPIN_FILE}".bak.*' "${DOCKER_SSH_CIDR_SYNC_SCRIPT}"
  assert_success
  run grep -F 'ufw --force delete allow in proto tcp from "${old_cidr}" to any port "${ssh_port}" comment "${RULE_COMMENT}"' "${DOCKER_SSH_CIDR_SYNC_SCRIPT}"
  assert_success
  run grep -F 'ufw allow in proto tcp from "${cidr}" to any port "${ssh_port}" comment "${RULE_COMMENT}"' "${DOCKER_SSH_CIDR_SYNC_SCRIPT}"
  assert_success

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
  assert_output --partial 'ufw allow in proto tcp from 10.0.0.0/8 to any port 22 comment coolify-hardening-ssh-docker-bridge'
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

@test "configure_rsyslog_targets: does not reset /var/log mode while ensuring target directories" {
  DRY_RUN="false"
  rsyslog_collect_log_targets() {
    printf '%s\n' "/var/log/ufw.log" "/var/log/mail.log"
  }
  ensure_logrotate_create_directive() { :; }
  getent() { return 0; }

  local install_log
  install_log="$(mktemp)"

  install() { printf '%s\n' "$*" >> "${install_log}"; return 0; }
  touch() { :; }
  chown() { :; }
  chmod() { :; }
  systemctl() { return 1; }

  run configure_rsyslog_targets
  assert_success

  run grep -F -- "-d -m 0770 -o root -g syslog /var/log" "${install_log}"
  assert_success
  run grep -F -- "-d -m 0755 /var/log" "${install_log}"
  assert_failure

  rm -f "${install_log}"
}

@test "configure_docker_daemon: skips when Docker absent" {
  DRY_RUN="true"
  DOCKER_PRESENT="false"

  run configure_docker_daemon
  assert_success
  assert_output --partial "Docker not present"
}

@test "configure_docker_daemon: successful merge prunes stale backup artifacts when restart is not deferred" {
  DRY_RUN="false"
  DOCKER_PRESENT="true"
  DOCKER_NPROC_HARD="8192"
  DOCKER_NPROC_SOFT="4096"
  local tmpdir
  tmpdir="$(mktemp -d)"
  DOCKER_DAEMON_JSON="${tmpdir}/daemon.json"
  cat > "${DOCKER_DAEMON_JSON}" <<'EOF'
{"debug":false}
EOF

  systemctl() { return 1; }

  run configure_docker_daemon
  assert_success
  run compgen -G "${DOCKER_DAEMON_JSON}.bak.*"
  assert_failure

  rm -rf "${tmpdir}"
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
    ensure_bootloader_embed_safety() { :; }
    configure_networkd_wait_online() { :; }
    configure_cron_extra_opts() { :; }
    ensure_power_group() { :; }
    apply_system_package_updates() { :; }
    require_commands() { :; }
    ensure_tailscaled_notify_access() { :; }
    verify_tailscale_iface() { :; }
    ensure_tailscale_ssh_disabled() { :; }
    detect_docker() { :; }
    discover_docker_ssh_cidrs() { :; }
    configure_swap() { :; }
    disable_unused_services() { :; }
    configure_banner() { :; }
    ensure_admin_access() { :; }
    configure_ssh() { :; }
    configure_auditd() { :; }
    configure_apport() { :; }
    configure_sysctl() { :; }
    configure_ufw() { :; }
    configure_rsyslog_targets() { :; }
    configure_docker_daemon() { :; }
    configure_docker_user() { :; }
    configure_fail2ban() { :; }
    configure_journald() { :; }
    configure_unattended_upgrades() { :; }
    configure_hardening_validation_timer() { :; }
    configure_coolify_binding() { :; }
    configure_coolify_binding_watchdog() { :; }
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

@test "apply_system_package_updates: dry-run reports full-upgrade plan" {
  run bash -c '
    source "'"${SCRIPT}"'"
    DRY_RUN="true"
    apply_system_package_updates
  '
  assert_success
  assert_output --partial "apt-get full-upgrade"
  assert_output --partial "autoremove --purge"
}

@test "configure_apport: dry-run updates apport defaults and service state" {
  run bash -c '
    source "'"${SCRIPT}"'"
    DRY_RUN="true"
    APPORT_DEFAULT_FILE="$(mktemp)"
    printf "enabled=1\n" > "${APPORT_DEFAULT_FILE}"
    unit_available() { return 0; }
    configure_apport
    rm -f "${APPORT_DEFAULT_FILE}"
  '
  assert_success
  assert_output --partial "apport"
  assert_output --partial "DRY-RUN"
}

@test "configure_cron_extra_opts: dry-run normalizes cron environment" {
  run bash -c '
    source "'"${SCRIPT}"'"
    DRY_RUN="true"
    CRON_EXTRA_OPTS_DROPIN="$(mktemp)"
    rm -f "${CRON_EXTRA_OPTS_DROPIN}"
    unit_available() { return 0; }
    configure_cron_extra_opts
  '
  assert_success
  assert_output --partial "EXTRA_OPTS"
  assert_output --partial "DRY-RUN"
}

@test "emit_filtered_package_output: strips noisy package-manager warnings" {
  run bash -c '
    source "'"${SCRIPT}"'"
    printf "%s\n" \
      "SyntaxWarning: invalid escape sequence" \
      "dpkg: warning: while removing x directory y not empty so not removed" \
      "Service restarts being deferred:" \
      "No containers need to be restarted." \
      "keep-this-line" \
      | emit_filtered_package_output
  '
  assert_success
  assert_output "keep-this-line"
}

@test "ensure_bootloader_embed_safety: callable under non-gpt layouts" {
  run bash -c '
    source "'"${SCRIPT}"'"
    findmnt() { echo /dev/vda1; }
    lsblk() {
      if [[ "$1" == "-no" && "$2" == "PKNAME" ]]; then
        echo vda
      elif [[ "$1" == "-dn" && "$2" == "-o" && "$3" == "PTTYPE" ]]; then
        echo dos
      else
        return 0
      fi
    }
    ensure_bootloader_embed_safety || true
  '
  assert_success
}

@test "ensure_system_group: dry-run logs missing system group creation" {
  run bash -c '
    source "'"${SCRIPT}"'"
    DRY_RUN="true"
    getent() { return 1; }
    ensure_system_group "power"
  '
  assert_success
  assert_output --partial "missing system group"
}

@test "ensure_power_group: delegates to power system group" {
  run bash -c '
    source "'"${SCRIPT}"'"
    DRY_RUN="true"
    getent() { return 1; }
    ensure_power_group
  '
  assert_success
  assert_output --partial "power"
}

@test "ensure_tailscaled_notify_access: dry-run prepares NotifyAccess restart" {
  run bash -c '
    source "'"${SCRIPT}"'"
    DRY_RUN="true"
    TAILSCALED_NOTIFY_DROPIN="$(mktemp)"
    rm -f "${TAILSCALED_NOTIFY_DROPIN}"
    unit_available() { return 0; }
    systemctl() {
      if [[ "$1" == "show" ]]; then
        echo main
        return 0
      fi
      return 0
    }
    ensure_tailscaled_notify_access
  '
  assert_success
  assert_output --partial "NotifyAccess"
  assert_output --partial "DRY-RUN"
}

@test "ifupdown_is_authoritative: callable when networking.service is present" {
  run bash -c '
    source "'"${SCRIPT}"'"
    unit_available() { return 0; }
    ifupdown_is_authoritative || true
  '
  assert_success
}

@test "retry_apt_noninteractive: retries until apt command succeeds" {
  run bash -c '
    source "'"${SCRIPT}"'"
    attempts=0
    sleep() { :; }
    run_apt_command() {
      attempts=$((attempts + 1))
      (( attempts < 3 )) && return 1
      return 0
    }
    retry_apt_noninteractive "apt-get full-upgrade" full-upgrade
    [[ "${attempts}" -eq 3 ]]
  '
  assert_success
}

@test "run_apt_command: streams filtered output and preserves exit status" {
  run bash -c '
    source "'"${SCRIPT}"'"
    DRY_RUN="false"
    run_apt_command printf "%s\n" \
      "SyntaxWarning: invalid escape sequence" \
      "keep-this-line" \
      "No containers need to be restarted."
  '
  assert_success
  assert_output "keep-this-line"
}

@test "tailscale_runssh_pref_value: returns parsed RunSSH preference" {
  run bash -c '
    source "'"${SCRIPT}"'"
    tailscale() {
      if [[ "$1" == "debug" && "$2" == "prefs" ]]; then
        echo "{\"RunSSH\":false}"
        return 0
      fi
      return 1
    }
    tailscale_runssh_pref_value 1 0
  '
  assert_success
  assert_output "false"
}
