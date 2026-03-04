#!/usr/bin/env bats
# Additional behavior tests for uncovered deploy/setup functions.

load '../helpers'

@test "cleanup_temp_files: removes known-host and runtime secret temp files" {
  run bash -c '
    source "'"${DEPLOY_SCRIPT}"'"
    DEPLOY_KNOWN_HOSTS="$(mktemp)"
    ADMIN_KNOWN_HOSTS="$(mktemp)"
    ROOT_PASS_RUNTIME_FILE="$(mktemp)"
    cleanup_temp_files
    [[ ! -e "${DEPLOY_KNOWN_HOSTS}" ]]
    [[ ! -e "${ADMIN_KNOWN_HOSTS}" ]]
    [[ ! -e "${ROOT_PASS_RUNTIME_FILE}" ]]
  '
  assert_success
}

@test "init_ssh_options: initializes SSH and root SSH options as arrays" {
  run bash -c '
    source "'"${DEPLOY_SCRIPT}"'"
    SERVER_IP="203.0.113.10"
    TS_IP="100.64.0.10"
    init_ssh_options
    [[ "${#SSH_OPTS[@]}" -gt 0 ]]
    [[ "${#ROOT_SSH_OPTS[@]}" -gt 0 ]]
  '
  assert_success
}

@test "init_root_password_auth: writes runtime password file and clears in-memory secret" {
  run bash -c '
    source "'"${DEPLOY_SCRIPT}"'"
    ROOT_PASS="super-secret"
    init_root_password_auth
    [[ -n "${ROOT_PASS_RUNTIME_FILE}" ]]
    [[ -f "${ROOT_PASS_RUNTIME_FILE}" ]]
    [[ -z "${ROOT_PASS}" ]]
    rm -f "${ROOT_PASS_RUNTIME_FILE}"
  '
  assert_success
}

@test "parse_args (deploy): extracts --server-timezone" {
  run bash -c '
    source "'"${DEPLOY_SCRIPT}"'"
    parse_args --server-timezone "UTC"
    [[ "${SERVER_TIMEZONE}" == "UTC" ]]
  '
  assert_success
}

@test "collect_inputs (deploy): prompts for root password only when needed" {
  run bash -c '
    source "'"${DEPLOY_SCRIPT}"'"
    collect_common_inputs() {
      SERVER_IP="203.0.113.10"
      ADMIN_USER="alice"
      PUBKEY_FILE="/tmp/id.pub"
      TAILSCALE_AUTH_KEY="tskey-auth-x"
      DEPLOY_MODE="tunnel"
      DOMAIN="vps.example.com"
      CF_API_TOKEN="token"
      SWAP_SIZE="2G"
      SERVER_TIMEZONE="UTC"
      APP_DOMAIN_MODE="apex"
    }
    prompt_secret() { ROOT_PASS="from-prompt"; }
    SKIP_HARDEN="false"
    ROOT_PASS=""
    collect_inputs
    [[ "${ROOT_PASS}" == "from-prompt" ]]
  '
  assert_success
}

@test "scp_admin: uses identity file and ssh options" {
  run bash -c '
    source "'"${DEPLOY_SCRIPT}"'"
    PRIVATE_KEY="/tmp/id_ed25519"
    SSH_OPTS=(-o StrictHostKeyChecking=accept-new)
    scp() { printf "%s\n" "$*"; }
    scp_admin a b
  '
  assert_success
  assert_output --partial "-i /tmp/id_ed25519 a b"
}

@test "ssh_root: uses sshpass file-based auth and root ssh options" {
  run bash -c '
    source "'"${DEPLOY_SCRIPT}"'"
    ROOT_PASS_RUNTIME_FILE="$(mktemp)"
    printf "pw" > "${ROOT_PASS_RUNTIME_FILE}"
    ROOT_SSH_OPTS=(-o StrictHostKeyChecking=accept-new)
    SERVER_IP="203.0.113.10"
    sshpass() { printf "%s\n" "$*"; }
    ssh_root "echo ok"
  '
  assert_success
  assert_output --partial "-f"
  assert_output --partial "root@203.0.113.10 echo ok"
}

@test "scp_root: uses sshpass file-based auth for root scp" {
  run bash -c '
    source "'"${DEPLOY_SCRIPT}"'"
    ROOT_PASS_RUNTIME_FILE="$(mktemp)"
    printf "pw" > "${ROOT_PASS_RUNTIME_FILE}"
    ROOT_SSH_OPTS=(-o StrictHostKeyChecking=accept-new)
    sshpass() { printf "%s\n" "$*"; }
    scp_root /tmp/a root@host:/tmp/b
  '
  assert_success
  assert_output --partial "-f"
  assert_output --partial "scp"
}

@test "ssh_admin: uses admin key and tailscale destination" {
  run bash -c '
    source "'"${DEPLOY_SCRIPT}"'"
    SSH_OPTS=(-o StrictHostKeyChecking=accept-new)
    PRIVATE_KEY="/tmp/id_ed25519"
    ADMIN_USER="alice"
    TS_IP="100.64.0.10"
    ssh() { printf "%s\n" "$*"; }
    ssh_admin "echo ok"
  '
  assert_success
  assert_output --partial "-i /tmp/id_ed25519 alice@100.64.0.10 echo ok"
}

@test "ssh_admin_sudo: prefixes remote command with sudo" {
  run bash -c '
    source "'"${DEPLOY_SCRIPT}"'"
    SSH_OPTS=(-o StrictHostKeyChecking=accept-new)
    PRIVATE_KEY="/tmp/id_ed25519"
    ADMIN_USER="alice"
    TS_IP="100.64.0.10"
    ssh() { printf "%s\n" "$*"; }
    ssh_admin_sudo "echo ok"
  '
  assert_success
  assert_output --partial "alice@100.64.0.10 sudo echo ok"
}

@test "sync_companion_scripts: uploads and installs all companion scripts" {
  run bash -c '
    source "'"${DEPLOY_SCRIPT}"'"
    SCRIPT_DIR="'"${PROJECT_ROOT}"'"
    ADMIN_USER="alice"
    TS_IP="100.64.0.10"
    upload_count=0
    install_count=0
    scp_admin() { upload_count=$((upload_count + 1)); return 0; }
    ssh_admin_sudo() { install_count=$((install_count + 1)); return 0; }
    sync_companion_scripts
    [[ "${upload_count}" -eq 3 ]]
    [[ "${install_count}" -eq 3 ]]
  '
  assert_success
}

@test "reconcile_docker_daemon_remote: pipes generated script over ssh_admin" {
  run bash -c '
    source "'"${DEPLOY_SCRIPT}"'"
    coolify_reconcile_docker_daemon_script() { echo "echo reconcile"; }
    ssh_admin() { cat >/dev/null; }
    reconcile_docker_daemon_remote
  '
  assert_success
}

@test "phase3_docker_coolify (deploy): executes docker/coolify reconcile flow" {
  run bash -c '
    source "'"${DEPLOY_SCRIPT}"'"
    gate_calls=0
    ssh_admin_sudo() {
      if [[ "$1" == *"bash -s"* ]]; then
        cat >/dev/null || true
      fi
      case "$1" in
        "docker version >/dev/null 2>&1") return 0 ;;
        "test -f /data/coolify/source/.env") return 0 ;;
        *) return 0 ;;
      esac
    }
    verify_docker_user_gate_remote() { gate_calls=$((gate_calls + 1)); }
    reconcile_docker_daemon_remote() { :; }
    coolify_add_coolify_root_key_script() { echo true; }
    coolify_fix_host_docker_internal_script() { echo true; }
    phase3_docker_coolify
    [[ "${gate_calls}" -ge 2 ]]
  '
  assert_success
}

@test "collect_inputs (setup): populates shared fields via common collector" {
  run bash -c '
    source "'"${SETUP_SCRIPT}"'"
    collect_common_inputs() {
      SERVER_IP="203.0.113.10"
      ADMIN_USER="alice"
      PUBKEY_FILE="/tmp/id.pub"
      TAILSCALE_AUTH_KEY="tskey-auth-x"
      DEPLOY_MODE="tunnel"
      DOMAIN="vps.example.com"
      CF_API_TOKEN="token"
      SWAP_SIZE="2G"
      SERVER_TIMEZONE="UTC"
      APP_DOMAIN_MODE="apex"
    }
    collect_inputs
    [[ "${SERVER_IP}" == "203.0.113.10" ]]
    [[ "${ADMIN_USER}" == "alice" ]]
  '
  assert_success
}

@test "reconcile_docker_daemon_local: runs generated script locally" {
  run bash -c '
    source "'"${SETUP_SCRIPT}"'"
    coolify_reconcile_docker_daemon_script() { echo "echo reconcile"; }
    reconcile_docker_daemon_local
  '
  assert_success
}

@test "phase3_docker_coolify (setup): executes local docker/coolify reconcile flow" {
  run bash -c '
    source "'"${SETUP_SCRIPT}"'"
    gate_calls=0
    docker() {
      [[ "$1" == "version" ]] && return 0
      return 0
    }
    systemctl() { return 0; }
    verify_docker_user_gate_local() { gate_calls=$((gate_calls + 1)); }
    reconcile_docker_daemon_local() { :; }
    coolify_install_coolify_script() { echo true; }
    coolify_add_coolify_root_key_script() { echo true; }
    coolify_fix_host_docker_internal_script() { echo true; }
    phase3_docker_coolify
    [[ "${gate_calls}" -ge 2 ]]
  '
  assert_success
}

@test "main (deploy): executes all deployment phases in order with stubs" {
  run bash -c '
    source "'"${DEPLOY_SCRIPT}"'"
    parse_args() { :; }
    init_root_password_auth() { :; }
    collect_inputs() { :; }
    validate_inputs() { :; }
    confirm() { :; }
    preflight() { echo preflight; }
    phase1_upload_harden() { echo phase1; }
    phase2_gates() { echo phase2; }
    phase3_docker_coolify() { echo phase3; }
    phase4_binding_dns() { echo phase4; }
    phase5_verify() { echo phase5; }
    main
  '
  assert_success
  assert_output --partial "phase5"
}

@test "pause_for_operator (setup): displays prompt and accepts enter" {
  run bash -c '
    source "'"${SETUP_SCRIPT}"'"
    printf "\n" | pause_for_operator "check gate"
  '
  assert_success
  assert_output --partial "check gate"
}

@test "main (setup): executes setup phases with stubbed actions" {
  run bash -c '
    source "'"${SETUP_SCRIPT}"'"
    parse_args() { :; }
    collect_inputs() { :; }
    validate_inputs() { :; }
    confirm() { :; }
    preflight() { echo preflight; }
    phase1_harden() { echo phase1; }
    phase2_gates() { echo phase2; }
    phase3_docker_coolify() { echo phase3; }
    phase4_binding_dns() { echo phase4; }
    phase5_verify() { echo phase5; }
    main
  '
  assert_success
  assert_output --partial "phase5"
}
