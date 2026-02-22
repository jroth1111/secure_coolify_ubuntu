#!/usr/bin/env bats
# Tier 2: Full integration tests (standard mode)
# Requires: --privileged Docker container with systemd as PID 1.
# setup_file runs the script once; individual tests assert outcomes.

load '../helpers'

TEST_PUBKEY="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestKeyDataForFullRunTests test@bats"
TEST_USER="testadmin"
TEST_PORT="2222"
TEST_WAN="eth0"

SSH_DROPIN="/etc/ssh/sshd_config.d/00-coolify-hardening.conf"
SYSCTL_DROPIN="/etc/sysctl.d/60-coolify-hardening.conf"
FAIL2BAN_JAIL="/etc/fail2ban/jail.d/coolify-hardening.local"
JOURNALD_DROPIN="/etc/systemd/journald.conf.d/60-persistent.conf"
STATE_FILE="/var/lib/bootstrap-hardening/state"
REPORT_FILE="/var/log/bootstrap-hardening-report.json"
AUDIT_RULES="/etc/audit/rules.d/60-coolify-baseline.rules"
APT_LOCAL_FILE="/etc/apt/apt.conf.d/52unattended-upgrades-local"

setup_file() {
  # Create dummy tailscale0 interface
  ip link add tailscale0 type dummy 2>/dev/null || true
  ip addr add 100.64.0.1/32 dev tailscale0 2>/dev/null || true
  ip link set tailscale0 up 2>/dev/null || true

  # Ensure WAN interface exists (may already be eth0/default)
  ip link add "${TEST_WAN}" type dummy 2>/dev/null || true
  ip link set "${TEST_WAN}" up 2>/dev/null || true

  # Wait for systemd to reach a stable state
  local retries=10
  while true; do
    local state
    state="$(systemctl is-system-running 2>/dev/null || true)"
    if [[ "${state}" == "running" || "${state}" == "degraded" ]]; then
      break
    fi
    retries=$((retries - 1))
    if [[ ${retries} -le 0 ]]; then
      echo "WARNING: systemd not fully ready (state=${state}), proceeding anyway" >&2
      break
    fi
    sleep 1
  done

  # Run the script once in standard mode
  bash "${SCRIPT}" \
    --admin-user "${TEST_USER}" \
    --admin-pubkey "${TEST_PUBKEY}" \
    --ssh-port "${TEST_PORT}" \
    --wan-iface "${TEST_WAN}" \
    --force
}

teardown_file() {
  ip link del tailscale0 2>/dev/null || true
}

# ── SSH ──────────────────────────────────────────────────────────────────────

@test "ssh: drop-in config file exists" {
  [ -f "${SSH_DROPIN}" ]
}

@test "ssh: sshd -T shows correct port" {
  run sshd -T
  assert_success
  assert_output --partial "port ${TEST_PORT}"
}

@test "ssh: sshd -T shows permitrootlogin no (default context)" {
  run sshd -T
  assert_success
  assert_output --partial "permitrootlogin no"
}

@test "ssh: sshd -T -C localhost shows permitrootlogin prohibit-password (or synonym)" {
  run sshd -T -C addr=127.0.0.1,user=root,host=localhost,laddr=127.0.0.1
  assert_success
  # OpenSSH outputs either "prohibit-password" or legacy synonym "without-password"
  echo "${output}" | grep -qE "permitrootlogin (prohibit-password|without-password)"
}

@test "ssh: sshd -T -C localhost shows allowusers includes root" {
  run sshd -T -C addr=127.0.0.1,user=root,host=localhost,laddr=127.0.0.1
  assert_success
  assert_output --partial "root"
}

@test "ssh: sshd -T -C external address shows permitrootlogin no" {
  run sshd -T -C addr=203.0.113.1,user=root,host=example.com,laddr=0.0.0.0
  assert_success
  assert_output --partial "permitrootlogin no"
}

@test "ssh: sshd -T shows passwordauthentication no" {
  run sshd -T
  assert_success
  assert_output --partial "passwordauthentication no"
}

@test "ssh: sshd -T shows allowusers includes test user" {
  run sshd -T
  assert_success
  assert_output --partial "allowusers ${TEST_USER}"
}

@test "ssh: sshd -T shows chacha20 cipher" {
  run sshd -T
  assert_success
  assert_output --partial "chacha20-poly1305@openssh.com"
}

@test "ssh: sshd -T shows hardened MAC list" {
  run sshd -T
  assert_success
  assert_output --partial "hmac-sha2-512-etm@openssh.com"
}

@test "ssh: sshd -T shows hardened KEX list" {
  run sshd -T
  assert_success
  assert_output --partial "sntrup761x25519-sha512@openssh.com"
  assert_output --partial "curve25519-sha256@libssh.org"
}

@test "ssh: sshd -T shows hardened host key algorithms" {
  run sshd -T
  assert_success
  assert_output --partial "hostkeyalgorithms ssh-ed25519,rsa-sha2-512,rsa-sha2-256"
}

# ── Admin User ───────────────────────────────────────────────────────────────

@test "admin: user exists" {
  run id "${TEST_USER}"
  assert_success
}

@test "admin: user is in sudo group" {
  run id -nG "${TEST_USER}"
  assert_success
  assert_output --partial "sudo"
}

@test "admin: authorized_keys contains test key" {
  local home_dir
  home_dir="$(getent passwd "${TEST_USER}" | cut -d: -f6)"
  run cat "${home_dir}/.ssh/authorized_keys"
  assert_success
  assert_output --partial "${TEST_PUBKEY}"
}

@test "admin: authorized_keys has 0600 permissions" {
  local home_dir
  home_dir="$(getent passwd "${TEST_USER}" | cut -d: -f6)"
  local perms
  perms="$(stat -c '%a' "${home_dir}/.ssh/authorized_keys")"
  [ "${perms}" = "600" ]
}

# ── Admin Edge Cases ──────────────────────────────────────────────────────────

@test "admin: .ssh directory has 0700 permissions" {
  local home_dir
  home_dir="$(getent passwd "${TEST_USER}" | cut -d: -f6)"
  local perms
  perms="$(stat -c '%a' "${home_dir}/.ssh")"
  [ "${perms}" = "700" ]
}

@test "admin: home directory exists" {
  local home_dir
  home_dir="$(getent passwd "${TEST_USER}" | cut -d: -f6)"
  [ -d "${home_dir}" ]
}

@test "admin: shell is /bin/bash" {
  local shell
  shell="$(getent passwd "${TEST_USER}" | cut -d: -f7)"
  [ "${shell}" = "/bin/bash" ]
}

# ── UFW ──────────────────────────────────────────────────────────────────────

@test "ufw: is active" {
  run ufw status
  assert_success
  assert_output --partial "Status: active"
}

@test "ufw: SSH allowed on tailscale0" {
  run ufw status verbose
  assert_success
  assert_output --partial "${TEST_PORT}/tcp"
  assert_output --partial "tailscale0"
}

@test "ufw: HTTP (80) allowed on WAN" {
  run ufw status verbose
  assert_success
  assert_output --partial "80/tcp"
}

@test "ufw: HTTPS (443) allowed on WAN" {
  run ufw status verbose
  assert_success
  assert_output --partial "443/tcp"
}

@test "ufw: SSH not allowed on WAN interface" {
  local output
  output="$(ufw status verbose)"
  # Should NOT match SSH port on the WAN interface
  if echo "${output}" | grep -E "${TEST_PORT}/tcp.*on ${TEST_WAN}.*ALLOW IN"; then
    return 1
  fi
  return 0
}

@test "ufw: tailscale direct UDP rule is present on WAN" {
  run ufw status verbose
  assert_success
  assert_output --partial "41641/udp"
}

# ── Sysctl ───────────────────────────────────────────────────────────────────

@test "sysctl: tcp_syncookies is 1" {
  local val
  val="$(sysctl -n net.ipv4.tcp_syncookies 2>/dev/null)"
  [ "${val}" = "1" ]
}

@test "sysctl: ip_forward is 1" {
  local val
  val="$(sysctl -n net.ipv4.ip_forward 2>/dev/null)"
  [ "${val}" = "1" ]
}

@test "sysctl: drop-in file exists" {
  [ -f "${SYSCTL_DROPIN}" ]
}

# ── fail2ban ─────────────────────────────────────────────────────────────────

@test "fail2ban: service is active" {
  run systemctl is-active fail2ban
  assert_success
  assert_output "active"
}

@test "fail2ban: jail config exists" {
  [ -f "${FAIL2BAN_JAIL}" ]
}

@test "fail2ban: jail config has correct port" {
  run cat "${FAIL2BAN_JAIL}"
  assert_success
  assert_output --partial "port = ${TEST_PORT}"
}

# ── iptables / DOCKER-USER ──────────────────────────────────────────────────

@test "iptables: DOCKER-USER chain exists" {
  run iptables -t filter -L DOCKER-USER -n
  assert_success
}

@test "iptables: DOCKER-USER includes managed comments" {
  run iptables -t filter -S DOCKER-USER
  assert_success
  assert_output --partial "coolify-hardening-bridge-docker0"
  assert_output --partial "coolify-hardening-wan-web"
  assert_output --partial "coolify-hardening-wan-drop"
}

@test "iptables: DOCKER-USER managed rule order is correct" {
  local rules
  local tailscale_n
  local bridge_n
  local wan_web_n
  local wan_drop_n
  rules="$(iptables -t filter -S DOCKER-USER)"

  tailscale_n="$(grep -n "coolify-hardening-tailscale" <<< "${rules}" | head -1 | cut -d: -f1)"
  bridge_n="$(grep -n "coolify-hardening-bridge-docker0" <<< "${rules}" | head -1 | cut -d: -f1)"
  wan_web_n="$(grep -n "coolify-hardening-wan-web" <<< "${rules}" | head -1 | cut -d: -f1)"
  wan_drop_n="$(grep -n "coolify-hardening-wan-drop" <<< "${rules}" | head -1 | cut -d: -f1)"

  [[ -n "${tailscale_n}" && -n "${bridge_n}" && -n "${wan_web_n}" && -n "${wan_drop_n}" ]]
  (( tailscale_n < bridge_n ))
  (( bridge_n < wan_web_n ))
  (( wan_web_n < wan_drop_n ))
}

# ── Docker daemon.json ────────────────────────────────────────────────────────

@test "docker-daemon: daemon.json exists if Docker present" {
  if ! command -v docker >/dev/null 2>&1; then
    skip "Docker not installed"
  fi
  [ -f /etc/docker/daemon.json ]
}

@test "docker-daemon: log-driver is local" {
  if ! command -v docker >/dev/null 2>&1; then
    skip "Docker not installed"
  fi
  [ -f /etc/docker/daemon.json ] || skip "daemon.json not present"
  run cat /etc/docker/daemon.json
  assert_success
  assert_output --partial '"log-driver"'
  assert_output --partial '"local"'
}

@test "docker-daemon: live-restore enabled" {
  if ! command -v docker >/dev/null 2>&1; then
    skip "Docker not installed"
  fi
  [ -f /etc/docker/daemon.json ] || skip "daemon.json not present"
  run cat /etc/docker/daemon.json
  assert_success
  assert_output --partial '"live-restore"'
  assert_output --partial 'true'
}

# ── Journald ─────────────────────────────────────────────────────────────────

@test "journald: drop-in has Storage=persistent" {
  [ -f "${JOURNALD_DROPIN}" ]
  run cat "${JOURNALD_DROPIN}"
  assert_success
  assert_output --partial "Storage=persistent"
  assert_output --partial "MaxRetentionSec=3month"
}

# ── Unattended Upgrades ─────────────────────────────────────────────────────

@test "upgrades: auto-upgrade config present" {
  run cat /etc/apt/apt.conf.d/20auto-upgrades
  assert_success
  assert_output --partial 'Unattended-Upgrade "1"'
}

@test "upgrades: local policy has reboot and cleanup settings" {
  run cat "${APT_LOCAL_FILE}"
  assert_success
  assert_output --partial 'Unattended-Upgrade::Automatic-Reboot "true";'
  assert_output --partial 'Unattended-Upgrade::Automatic-Reboot-Time "03:30";'
  assert_output --partial 'Unattended-Upgrade::Remove-Unused-Dependencies "true";'
}

# ── Banner ───────────────────────────────────────────────────────────────────

@test "banner: /etc/issue.net contains AUTHORIZED" {
  run cat /etc/issue.net
  assert_success
  assert_output --partial "AUTHORIZED"
}

# ── State & Report ───────────────────────────────────────────────────────────

@test "state: state file written with correct values" {
  [ -f "${STATE_FILE}" ]
  run cat "${STATE_FILE}"
  assert_success
  assert_output --partial "admin_user=${TEST_USER}"
  assert_output --partial "ssh_port=${TEST_PORT}"
  assert_output --partial "wan_iface=${TEST_WAN}"
  assert_output --partial "tunnel_mode=false"
}

@test "state: JSON report written" {
  [ -f "${REPORT_FILE}" ]
  run cat "${REPORT_FILE}"
  assert_success
  assert_output --partial '"admin_user": "'
  assert_output --partial '"ssh_port": '
}

# ── Services ─────────────────────────────────────────────────────────────────

@test "services: rpcbind masked or not found" {
  local status
  status="$(systemctl is-enabled rpcbind.service 2>/dev/null)" || true
  [[ "${status}" == "masked" || "${status}" == "not-found" ]]
}

@test "services: avahi-daemon masked or not found" {
  local status
  status="$(systemctl is-enabled avahi-daemon.service 2>/dev/null)" || true
  [[ "${status}" == "masked" || "${status}" == "not-found" ]]
}

@test "services: avahi-daemon.socket masked or not found" {
  local status
  status="$(systemctl is-enabled avahi-daemon.socket 2>/dev/null)" || true
  [[ "${status}" == "masked" || "${status}" == "not-found" ]]
}

@test "services: cups masked or not found" {
  local status
  status="$(systemctl is-enabled cups.service 2>/dev/null)" || true
  [[ "${status}" == "masked" || "${status}" == "not-found" ]]
}

# ── Audit ────────────────────────────────────────────────────────────────────

@test "audit: rules file exists" {
  [ -f "${AUDIT_RULES}" ]
}

@test "audit: rules include identity watch" {
  run auditctl -l
  assert_success
  assert_output --partial "identity"
}

@test "audit: rules include sudoers watch" {
  run auditctl -l
  assert_success
  assert_output --partial "sudoers-change"
}

@test "docker-user: service is enabled" {
  run systemctl is-enabled docker-user-hardening.service
  assert_success
  assert_output "enabled"
}

# ── BBR / SYN Backlog ────────────────────────────────────────────────────

@test "sysctl: tcp_max_syn_backlog is 2048" {
  local val
  val="$(sysctl -n net.ipv4.tcp_max_syn_backlog 2>/dev/null)"
  [ "${val}" = "2048" ]
}

@test "sysctl: tcp_synack_retries is 2" {
  local val
  val="$(sysctl -n net.ipv4.tcp_synack_retries 2>/dev/null)"
  [ "${val}" = "2" ]
}

@test "sysctl: BBR congestion control active (if kernel supports)" {
  local val
  val="$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo "?")"
  # BBR depends on kernel module; skip if not available
  if ! modinfo tcp_bbr &>/dev/null; then
    skip "tcp_bbr kernel module not available"
  fi
  [ "${val}" = "bbr" ]
}

@test "sysctl: default_qdisc is fq (if BBR active)" {
  if ! modinfo tcp_bbr &>/dev/null; then
    skip "tcp_bbr kernel module not available"
  fi
  local val
  val="$(sysctl -n net.core.default_qdisc 2>/dev/null)"
  [ "${val}" = "fq" ]
}

@test "sysctl: drop-in contains SYN backlog parameters" {
  run cat "${SYSCTL_DROPIN}"
  assert_success
  assert_output --partial "net.ipv4.tcp_max_syn_backlog = 2048"
  assert_output --partial "net.ipv4.tcp_synack_retries = 2"
}

# ── Swap ──────────────────────────────────────────────────────────────────

@test "swap: swap is active" {
  local swap_out
  swap_out="$(swapon --show --noheadings 2>/dev/null || true)"
  [ -n "${swap_out}" ]
}

@test "swap: /swapfile exists with 0600 permissions when /swapfile backend is used" {
  if [ ! -f /swapfile ]; then
    skip "Swap backend is not /swapfile in this environment"
  fi

  [ -f /swapfile ]
  local perms
  perms="$(stat -c '%a' /swapfile)"
  [ "${perms}" = "600" ]
}

@test "swap: single fstab entry for swapfile when /swapfile backend is used" {
  if [ ! -f /swapfile ]; then
    skip "Swap backend is not /swapfile in this environment"
  fi

  local count
  count="$(grep -cxF '/swapfile none swap sw 0 0' /etc/fstab || true)"
  [ "${count}" -eq 1 ]
}

@test "swap: vm.swappiness is 10" {
  local val
  val="$(sysctl -n vm.swappiness 2>/dev/null)"
  [ "${val}" = "10" ]
}

@test "state: state file includes swap_size" {
  run cat "${STATE_FILE}"
  assert_success
  assert_output --partial "swap_size="
}

# ── NTP ───────────────────────────────────────────────────────────────────

@test "timesync: NTP is active when supported by container runtime" {
  local ntp_val
  ntp_val="$(timedatectl show --property=NTP --value 2>/dev/null || echo "?")"

  if [ "${ntp_val}" != "yes" ]; then
    skip "NTP control is unavailable in this container runtime"
  fi

  [ "${ntp_val}" = "yes" ]
}

# ── Report ────────────────────────────────────────────────────────────────

@test "report: JSON includes new check fields" {
  run cat "${REPORT_FILE}"
  assert_success
  assert_output --partial '"sysctl_bbr":'
  assert_output --partial '"timesync_ntp":'
  assert_output --partial '"swap_active":'
  assert_output --partial '"swap_size":'
}

# ── Sysctl Spot-Checks ───────────────────────────────────────────────────────

@test "sysctl: rp_filter is 2 (loose mode for Docker)" {
  run sysctl -n net.ipv4.conf.all.rp_filter
  assert_success
  assert_output "2"
}

@test "sysctl: accept_redirects is 0" {
  run sysctl -n net.ipv4.conf.all.accept_redirects
  assert_success
  assert_output "0"
}

@test "sysctl: protected_hardlinks is 1" {
  run sysctl -n fs.protected_hardlinks
  [ "${status}" -eq 0 ] || skip "sysctl unavailable in container"
  assert_output "1"
}

@test "sysctl: icmp_echo_ignore_broadcasts is 1" {
  run sysctl -n net.ipv4.icmp_echo_ignore_broadcasts
  assert_success
  assert_output "1"
}

@test "sysctl: suid_dumpable is 0" {
  run sysctl -n fs.suid_dumpable
  [ "${status}" -eq 0 ] || skip "sysctl unavailable in container"
  assert_output "0"
}

# ── Docker daemon.json Idempotency ───────────────────────────────────────────

@test "docker-daemon: pre-existing daemon.json is not overwritten on re-run" {
  command -v docker >/dev/null 2>&1 || skip "Docker not installed"
  local daemon_json="/etc/docker/daemon.json"
  [ -f "${daemon_json}" ] || skip "daemon.json not present"

  # Inject a custom marker
  local marker="__test_preserve_marker__"
  sed -i 's/}$/,"test-marker": "'"${marker}"'"}/' "${daemon_json}"

  # Re-run the script
  bash "${SCRIPT}" \
    --admin-user "${TEST_USER}" \
    --admin-pubkey "${TEST_PUBKEY}" \
    --ssh-port "${TEST_PORT}" \
    --wan-iface "${TEST_WAN}" \
    --force

  run cat "${daemon_json}"
  assert_output --partial "${marker}"
}

# ── DOCKER-USER IPv6 ─────────────────────────────────────────────────────────

@test "iptables: DOCKER-USER IPv6 chain has wan-drop6 rule" {
  command -v ip6tables >/dev/null 2>&1 || skip "ip6tables unavailable"
  run ip6tables -t filter -S DOCKER-USER
  assert_success
  assert_output --partial "coolify-hardening-wan-drop6"
}

# ── Audit Container-Runtime ──────────────────────────────────────────────────

@test "audit: rules include container-runtime watch" {
  run auditctl -l
  assert_success
  assert_output --partial "container-runtime"
}
