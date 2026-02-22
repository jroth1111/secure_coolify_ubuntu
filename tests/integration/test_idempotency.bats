#!/usr/bin/env bats
# Tier 2 idempotency tests for bootstrap_hardening.sh.

load '../helpers'

TEST_PUBKEY="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestKeyDataForIdempotencyTests test@bats"
TEST_USER="idempotentadmin"
TEST_PORT="2222"
TEST_WAN="eth0"
STATE_FILE="/var/lib/bootstrap-hardening/state"

setup_file() {
  ip link add tailscale0 type dummy 2>/dev/null || true
  ip addr add 100.64.0.1/32 dev tailscale0 2>/dev/null || true
  ip link set tailscale0 up 2>/dev/null || true

  ip link add "${TEST_WAN}" type dummy 2>/dev/null || true
  ip link set "${TEST_WAN}" up 2>/dev/null || true

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
}

teardown_file() {
  ip link del tailscale0 2>/dev/null || true
}

@test "idempotency: repeated run keeps single managed entries and healthy state" {
  run bash "${SCRIPT}" \
    --admin-user "${TEST_USER}" \
    --admin-pubkey "${TEST_PUBKEY}" \
    --ssh-port "${TEST_PORT}" \
    --wan-iface "${TEST_WAN}" \
    --force
  assert_success

  local first_applied_at
  first_applied_at="$(grep '^applied_at=' "${STATE_FILE}" | cut -d= -f2-)"
  [ -n "${first_applied_at}" ]

  run bash "${SCRIPT}" \
    --admin-user "${TEST_USER}" \
    --admin-pubkey "${TEST_PUBKEY}" \
    --ssh-port "${TEST_PORT}" \
    --wan-iface "${TEST_WAN}" \
    --force
  assert_success

  local second_applied_at
  second_applied_at="$(grep '^applied_at=' "${STATE_FILE}" | cut -d= -f2-)"
  [ -n "${second_applied_at}" ]

  local first_epoch
  local second_epoch
  first_epoch="$(date -d "${first_applied_at}" +%s)"
  second_epoch="$(date -d "${second_applied_at}" +%s)"
  (( second_epoch >= first_epoch ))

  local home_dir
  local key_count
  home_dir="$(getent passwd "${TEST_USER}" | cut -d: -f6)"
  key_count="$(grep -Fxc "${TEST_PUBKEY}" "${home_dir}/.ssh/authorized_keys")"
  [ "${key_count}" -eq 1 ]

  local wan_drop_count
  local wan_web_count
  local bridge_count
  wan_drop_count="$(iptables -t filter -S DOCKER-USER | grep -c 'coolify-hardening-wan-drop')"
  wan_web_count="$(iptables -t filter -S DOCKER-USER | grep -c 'coolify-hardening-wan-web')"
  bridge_count="$(iptables -t filter -S DOCKER-USER | grep -c 'coolify-hardening-bridge-docker0')"
  [ "${wan_drop_count}" -eq 1 ]
  [ "${wan_web_count}" -eq 1 ]
  [ "${bridge_count}" -eq 1 ]

  # Swap fstab idempotency: only one entry after two runs
  local fstab_swap_count
  fstab_swap_count="$(grep -cxF '/swapfile none swap sw 0 0' /etc/fstab || true)"
  fstab_swap_count="${fstab_swap_count:-0}"
  if [ -f /swapfile ]; then
    [ "${fstab_swap_count}" -eq 1 ]
  else
    [ "${fstab_swap_count}" -le 1 ]
  fi

  run bash "${VALIDATE_SCRIPT}"
  assert_success
}
