#!/usr/bin/env bats
# Tier 1: Dry-run integration tests
# Runs in a plain Docker container (no systemd required).
# Tests the --dry-run pipeline to verify no system changes are made.

load '../helpers'

TEST_PUBKEY="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestKeyDataForDryRunTests test@bats"
SSH_DROPIN="/etc/ssh/sshd_config.d/00-coolify-hardening.conf"
SYSCTL_DROPIN="/etc/sysctl.d/60-coolify-hardening.conf"
FAIL2BAN_JAIL="/etc/fail2ban/jail.d/coolify-hardening.local"
JOURNALD_DROPIN="/etc/systemd/journald.conf.d/60-persistent.conf"
AUDIT_RULES="/etc/audit/rules.d/60-coolify-baseline.rules"
DOCKER_USER_SCRIPT="/usr/local/sbin/docker-user-hardening.sh"
DOCKER_USER_ENV="/etc/default/docker-user-hardening"
DOCKER_USER_UNIT="/etc/systemd/system/docker-user-hardening.service"
APT_LOCAL_FILE="/etc/apt/apt.conf.d/52unattended-upgrades-local"
STATE_FILE="/var/lib/bootstrap-hardening/state"
REPORT_FILE="/var/log/bootstrap-hardening-report.json"

run_dry_run() {
  bash "${SCRIPT}" \
    --admin-user testadmin \
    --admin-pubkey "${TEST_PUBKEY}" \
    --ssh-port 2222 \
    --wan-iface eth0 \
    --dry-run \
    --force
}

setup_file() {
  # Create a dummy tailscale0 interface for the script to detect
  ip link add tailscale0 type dummy 2>/dev/null || true
  ip addr add 100.64.0.1/32 dev tailscale0 2>/dev/null || true
  ip link set tailscale0 up 2>/dev/null || true
}

teardown_file() {
  ip link del tailscale0 2>/dev/null || true
}

@test "dry-run: exits 0 with valid args" {
  run run_dry_run
  assert_success
}

@test "dry-run: logs DRY-RUN prefix" {
  run run_dry_run
  assert_success
  assert_output --partial "DRY-RUN: write"
}

@test "dry-run: does not create SSH drop-in" {
  run run_dry_run
  assert_success
  [ ! -f "${SSH_DROPIN}" ]
}

@test "dry-run: does not create sysctl drop-in" {
  run run_dry_run
  assert_success
  [ ! -f "${SYSCTL_DROPIN}" ]
}

@test "dry-run: does not create managed custom files" {
  run run_dry_run
  assert_success
  [ ! -f "${FAIL2BAN_JAIL}" ]
  [ ! -f "${JOURNALD_DROPIN}" ]
  [ ! -f "${AUDIT_RULES}" ]
  [ ! -f "${DOCKER_USER_SCRIPT}" ]
  [ ! -f "${DOCKER_USER_ENV}" ]
  [ ! -f "${DOCKER_USER_UNIT}" ]
  [ ! -f "${APT_LOCAL_FILE}" ]
  [ ! -f "${STATE_FILE}" ]
  [ ! -f "${REPORT_FILE}" ]
}

@test "dry-run: logs every major phase" {
  run run_dry_run
  assert_success
  assert_output --partial "Verifying NTP time synchronization."
  assert_output --partial "Configuring swap."
  assert_output --partial "Disabling unused network services."
  assert_output --partial "Applying account and SSH hardening."
  assert_output --partial "Applying UFW baseline."
  assert_output --partial "Applying sysctl kernel hardening."
  assert_output --partial "Applying fail2ban."
  assert_output --partial "Applying DOCKER-USER hardening assets."
  assert_output --partial "Applying Docker daemon log rotation."
  assert_output --partial "Applying journald persistence."
  assert_output --partial "Applying auditd baseline."
  assert_output --partial "Applying unattended-upgrades policy."
  assert_output --partial "Applying login banner."
  assert_output --partial "Running post-apply checks."
}

@test "dry-run: does not create swap file" {
  run run_dry_run
  assert_success
  [ ! -f /swapfile ]
}

@test "dry-run: --swap-size 0 logs skip message" {
  run bash "${SCRIPT}" \
    --admin-user testadmin \
    --admin-pubkey "${TEST_PUBKEY}" \
    --ssh-port 2222 \
    --wan-iface eth0 \
    --swap-size 0 \
    --dry-run \
    --force
  assert_success
  assert_output --partial "Swap creation disabled"
}

@test "dry-run: tunnel-mode logs skip message" {
  run bash "${SCRIPT}" \
    --admin-user testadmin \
    --admin-pubkey "${TEST_PUBKEY}" \
    --ssh-port 2222 \
    --wan-iface eth0 \
    --tunnel-mode \
    --dry-run \
    --force
  assert_success
  assert_output --partial "Tunnel mode: skipping"
}

@test "dry-run: rejects missing admin-user" {
  run bash "${SCRIPT}" \
    --admin-pubkey "${TEST_PUBKEY}" \
    --ssh-port 2222 \
    --wan-iface eth0 \
    --dry-run \
    --force
  assert_failure
  assert_output --partial "Missing ADMIN_USER"
}

@test "dry-run: rejects non-root execution" {
  run runuser -u nobody -- bash -c "bash ${SCRIPT} \
    --admin-user testadmin \
    --admin-pubkey '${TEST_PUBKEY}' \
    --ssh-port 2222 \
    --wan-iface eth0 \
    --dry-run \
    --force"
  assert_failure
  assert_output --partial "Run as root"
}

@test "dry-run: fails when tailscale0 interface is missing" {
  ip link del tailscale0 2>/dev/null || true

  run run_dry_run
  assert_failure
  assert_output --partial "Interface tailscale0 not found"

  ip link add tailscale0 type dummy 2>/dev/null || true
  ip addr add 100.64.0.1/32 dev tailscale0 2>/dev/null || true
  ip link set tailscale0 up 2>/dev/null || true
}
