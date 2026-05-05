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

@test "sync_operator_known_host_entries: replaces stale operator known_hosts entries with verified session keys" {
  run bash -c '
    source "'"${DEPLOY_SCRIPT}"'"
    HOME="$(mktemp -d)"
    mkdir -p "${HOME}/.ssh"
    printf "100.64.0.10 ssh-ed25519 AAAAOLDKEY\n" > "${HOME}/.ssh/known_hosts"
    source_file="$(mktemp)"
    printf "100.64.0.10 ssh-ed25519 AAAANEWKEY\n" > "${source_file}"
    sync_operator_known_host_entries "${source_file}" "100.64.0.10"
    ! grep -q "AAAAOLDKEY" "${HOME}/.ssh/known_hosts"
    grep -q "AAAANEWKEY" "${HOME}/.ssh/known_hosts"
  '
  assert_success
}

@test "deploy_exit_trap: best-effort cleans remote deploy env then local temp files" {
  run bash -c '
    source "'"${DEPLOY_SCRIPT}"'"
    DEPLOY_ENV_REMOTE_PENDING="true"
    REMOTE_DEPLOY_ENV_PATH="/root/deploy.env"
    TS_IP="100.64.0.10"
    ADMIN_USER="alice"
    PRIVATE_KEY="/tmp/id_ed25519"
    SSH_OPTS=(-o StrictHostKeyChecking=accept-new)
    DEPLOY_KNOWN_HOSTS="$(mktemp)"
    ADMIN_KNOWN_HOSTS="$(mktemp)"
    ROOT_PASS_RUNTIME_FILE="$(mktemp)"
    remote_rm=0
    ssh_admin_sudo() { [[ "$1" == "rm -f /root/deploy.env" ]] && remote_rm=1; return 0; }
    run_report_finalize() { :; }
    set +e
    false
    deploy_exit_trap
    [[ "${remote_rm}" -eq 1 ]]
    [[ "${DEPLOY_ENV_REMOTE_PENDING}" == "false" ]]
    [[ ! -e "${DEPLOY_KNOWN_HOSTS}" ]]
    [[ ! -e "${ADMIN_KNOWN_HOSTS}" ]]
    [[ ! -e "${ROOT_PASS_RUNTIME_FILE}" ]]
  '
  assert_success
}

@test "cleanup_remote_deploy_env: clears pending remote env via admin sudo path" {
  run bash -c '
    source "'"${DEPLOY_SCRIPT}"'"
    DEPLOY_ENV_REMOTE_PENDING="true"
    REMOTE_DEPLOY_ENV_PATH="/root/deploy.env"
    TS_IP="100.64.0.10"
    ADMIN_USER="alice"
    PRIVATE_KEY="/tmp/id_ed25519"
    SSH_OPTS=(-o StrictHostKeyChecking=accept-new)
    ssh_admin_sudo() { [[ "$1" == "rm -f /root/deploy.env" ]]; }
    cleanup_remote_deploy_env
    [[ "${DEPLOY_ENV_REMOTE_PENDING}" == "false" ]]
  '
  assert_success
}

@test "deploy helper state functions: extract bootstrap tailscale IP and validate resume state" {
  run bash -c '
    source "'"${DEPLOY_SCRIPT}"'"
    capture="$(mktemp)"
    printf "noise\nHARDEN_RESULT_TAILSCALE_IP=100.64.0.44\n" > "${capture}"
    extract_bootstrap_tailscale_ip "${capture}" > "${capture}.out"
    extracted_ip="$(cat "${capture}.out")"
    [[ "${extracted_ip}" == "100.64.0.44" ]]

    SKIP_HARDEN="true"
    DEPLOY_MODE="tunnel"
    DOMAIN="coolify.example.com"
    ssh_admin_sudo() {
      printf "coolify.example.com\ttrue\n"
    }
    assert_resume_phase1_contract_remote
  '
  assert_success
}

@test "verify_post_reboot_services_remote: accepts healthy post-reboot services" {
  run bash -c '
    source "'"${DEPLOY_SCRIPT}"'"
    ssh_admin_sudo() {
      case "$1" in
        "systemctl is-active --quiet tailscaled.service") return 0 ;;
        "ufw status 2>/dev/null | grep -q \"^Status: active$\"") return 0 ;;
        "systemctl is-active --quiet fail2ban.service") return 0 ;;
        "fail2ban-client status sshd >/dev/null 2>&1") return 0 ;;
        "test \"$(systemctl show docker.service --property=LoadState --value 2>/dev/null)\" = loaded") return 1 ;;
      esac
      return 1
    }
    verify_post_reboot_services_remote "Gate B.5"
  '
  assert_success
  assert_output --partial "tailscaled.service is active"
}

@test "phase5_fetch_validate_json (deploy): requests remote validator json via sudo" {
  run bash -c '
    source "'"${DEPLOY_SCRIPT}"'"
    ssh_admin_sudo() {
      [[ "$1" == "/root/validate_hardening.sh --json" ]]
      echo "{\"fail\":0,\"checks\":[]}"
    }
    phase5_fetch_validate_json
  '
  assert_success
  assert_output --partial '"fail":0'
}

@test "phase5_noop_operator_confirm (deploy): returns success" {
  run bash -c '
    source "'"${DEPLOY_SCRIPT}"'"
    phase5_noop_operator_confirm
  '
  assert_success
}

@test "setup_exit_trap: removes pending deploy env file" {
  run bash -c '
    source "'"${SETUP_SCRIPT}"'"
    pending="$(mktemp)"
    PENDING_DEPLOY_ENV_FILE="${pending}"
    run_report_finalize() { :; }
    set +e
    false
    setup_exit_trap
    [[ ! -e "${pending}" ]]
    [[ -z "${PENDING_DEPLOY_ENV_FILE}" ]]
  '
  assert_success
}

@test "setup reboot marker helpers: return overridable file paths" {
  run bash -c '
    source "'"${SETUP_SCRIPT}"'"
    REBOOT_REQUIRED_FILE="/tmp/reboot-required.test"
    REBOOT_REQUIRED_PKGS_FILE="/tmp/reboot-required.pkgs.test"
    setup_reboot_required_file > /tmp/setup-reboot-required-file.out
    setup_reboot_required_pkgs_file > /tmp/setup-reboot-required-pkgs-file.out
    reboot_file="$(cat /tmp/setup-reboot-required-file.out)"
    reboot_pkgs_file="$(cat /tmp/setup-reboot-required-pkgs-file.out)"
    [[ "${reboot_file}" == "/tmp/reboot-required.test" ]]
    [[ "${reboot_pkgs_file}" == "/tmp/reboot-required.pkgs.test" ]]
  '
  assert_success
}

@test "phase5_fetch_validate_json (setup): executes local validator with --json" {
  run bash -c '
    source "'"${SETUP_SCRIPT}"'"
    tmpdir="$(mktemp -d)"
    SCRIPT_DIR="${tmpdir}"
    cat > "${tmpdir}/validate_hardening.sh" <<EOF
#!/usr/bin/env bash
echo "{\"fail\":0,\"checks\":[]}"
EOF
    chmod +x "${tmpdir}/validate_hardening.sh"
    phase5_fetch_validate_json
  '
  assert_success
  assert_output --partial '"fail":0'
}

@test "init_ssh_options: initializes SSH and root SSH options as arrays" {
  run bash -c '
    source "'"${DEPLOY_SCRIPT}"'"
    SERVER_IP="203.0.113.10"
    TS_IP="100.64.0.10"
    init_ssh_options
    [[ "${#SSH_OPTS[@]}" -gt 0 ]]
    [[ "${#ROOT_SSH_OPTS[@]}" -gt 0 ]]
    [[ " ${ROOT_SSH_OPTS[*]} " == *" PubkeyAuthentication=no "* ]]
    [[ " ${ROOT_SSH_OPTS[*]} " == *" NumberOfPasswordPrompts=1 "* ]]
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
    ROOT_SSH_HOST="203.0.113.10"
    ROOT_SSH_OPTS=(-o StrictHostKeyChecking=accept-new)
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

@test "retry_root_transport: retries ssh 255 failures and then succeeds" {
  run bash -c '
    source "'"${DEPLOY_SCRIPT}"'"
    tmpdir="$(mktemp -d)"
    trap "rm -rf \"${tmpdir}\"" EXIT
    counter_file="${tmpdir}/attempts"
    echo 0 > "${counter_file}"
    flaky_root_cmd() {
      attempt="$(cat "${counter_file}")"
      attempt=$((attempt + 1))
      echo "${attempt}" > "${counter_file}"
      if (( attempt == 1 )); then
        return 255
      fi
      echo ok
      return 0
    }
    sleep() { :; }
    retry_root_transport "upload test" flaky_root_cmd
    [[ "$(cat "${counter_file}")" -eq 2 ]]
  '
  assert_success
  assert_output --partial "ok"
}

@test "phase1_upload_harden: retries bootstrap exec after transient ssh 255 and captures tailscale ip" {
  run bash -c '
    source "'"${DEPLOY_SCRIPT}"'"
    tmpdir="$(mktemp -d)"
    trap "rm -rf \"${tmpdir}\"" EXIT
    counter_file="${tmpdir}/bootstrap-attempts"
    echo 0 > "${counter_file}"
    SCRIPT_DIR="${tmpdir}"
    for script in bootstrap_hardening.sh validate_hardening.sh configure_coolify_binding.sh; do
      : > "${tmpdir}/${script}"
    done
    SERVER_IP="203.0.113.10"
    ADMIN_USER="alice"
    ADMIN_PUBKEY="ssh-ed25519 AAAA test@example"
    DEPLOY_MODE="tunnel"
    SWAP_SIZE="2G"
    SERVER_TIMEZONE="UTC"
    TAILSCALE_AUTH_KEY="tskey-auth-test"
    TAILSCALE_DIRECT_WAN="false"
    REMOTE_DEPLOY_ENV_PATH="/root/deploy.env"
    probe_counter="${tmpdir}/probe-attempts"
    echo 0 > "${probe_counter}"
    scp_root() { return 0; }
    ssh_root() {
      if [[ "$1" == "true" ]]; then
        count="$(cat "${probe_counter}")"
        count=$((count + 1))
        echo "${count}" > "${probe_counter}"
        return 0
      fi
      if [[ "$1" == *"/root/bootstrap_hardening.sh --env-file "* ]] && [[ "$1" == *"--install-tailscale --force"* ]]; then
        attempt="$(cat "${counter_file}")"
        attempt=$((attempt + 1))
        echo "${attempt}" > "${counter_file}"
        if [[ "${attempt}" -eq 1 ]]; then
          echo "Permission denied" >&2
          return 255
        fi
        echo "HARDEN_RESULT_TAILSCALE_IP=100.64.0.10"
        return 0
      fi
      return 0
    }
    run_with_heartbeat() { local label="$1"; shift; "$@"; }
    sleep() { :; }
    phase1_upload_harden
    [[ "$(cat "${counter_file}")" -eq 2 ]]
    [[ "$(cat "${probe_counter}")" -eq 1 ]]
    [[ "${TS_IP}" == "100.64.0.10" ]]
  '
  assert_success
}

@test "phase1_upload_harden: retries transient root upload transport failures" {
  run bash -c '
    source "'"${DEPLOY_SCRIPT}"'"
    tmpdir="$(mktemp -d)"
    trap "rm -rf \"${tmpdir}\"" EXIT
    SCRIPT_DIR="${tmpdir}"
    for script in bootstrap_hardening.sh validate_hardening.sh configure_coolify_binding.sh; do
      : > "${tmpdir}/${script}"
    done
    SERVER_IP="203.0.113.10"
    ADMIN_USER="alice"
    ADMIN_PUBKEY="ssh-ed25519 AAAA test@example"
    DEPLOY_MODE="tunnel"
    SWAP_SIZE="2G"
    SERVER_TIMEZONE="UTC"
    TAILSCALE_AUTH_KEY="tskey-auth-test"
    TAILSCALE_DIRECT_WAN="false"
    REMOTE_DEPLOY_ENV_PATH="/root/deploy.env"
    upload_counter="${tmpdir}/upload-count"
    chmod_counter="${tmpdir}/chmod-count"
    echo 0 > "${upload_counter}"
    echo 0 > "${chmod_counter}"
    scp_root() {
      count="$(cat "${upload_counter}")"
      count=$((count + 1))
      echo "${count}" > "${upload_counter}"
      if (( count == 1 )); then
        return 255
      fi
      return 0
    }
    ssh_root() {
      if [[ "$1" == "chmod +x /root/bootstrap_hardening.sh" ]]; then
        count="$(cat "${chmod_counter}")"
        count=$((count + 1))
        echo "${count}" > "${chmod_counter}"
        if (( count == 1 )); then
          return 255
        fi
      elif [[ "$1" == chmod\ +x\ /root/* ]]; then
        count="$(cat "${chmod_counter}")"
        count=$((count + 1))
        echo "${count}" > "${chmod_counter}"
      fi
      if [[ "$1" == *"/root/bootstrap_hardening.sh --env-file "* ]] && [[ "$1" == *"--install-tailscale --force"* ]]; then
        echo "HARDEN_RESULT_TAILSCALE_IP=100.64.0.10"
      fi
      return 0
    }
    run_with_heartbeat() { local label="$1"; shift; "$@"; }
    sleep() { :; }
    phase1_upload_harden
    [[ "$(cat "${upload_counter}")" -eq 5 ]]
    [[ "$(cat "${chmod_counter}")" -eq 4 ]]
    [[ "${TS_IP}" == "100.64.0.10" ]]
  '
  assert_success
}

@test "phase1_upload_harden: switches root retries to Tailscale IP after early sentinel" {
  run bash -c '
    source "'"${DEPLOY_SCRIPT}"'"
    tmpdir="$(mktemp -d)"
    trap "rm -rf \"${tmpdir}\"" EXIT
    SCRIPT_DIR="${tmpdir}"
    for script in bootstrap_hardening.sh validate_hardening.sh configure_coolify_binding.sh; do
      : > "${tmpdir}/${script}"
    done
    SERVER_IP="203.0.113.10"
    ROOT_SSH_HOST="${SERVER_IP}"
    ADMIN_USER="alice"
    ADMIN_PUBKEY="ssh-ed25519 AAAA test@example"
    DEPLOY_MODE="tunnel"
    DOMAIN="server.example.com"
    SWAP_SIZE="2G"
    SERVER_TIMEZONE="UTC"
    TAILSCALE_AUTH_KEY="tskey-auth-test"
    TAILSCALE_DIRECT_WAN="false"
    REMOTE_DEPLOY_ENV_PATH="/root/deploy.env"
    bootstrap_counter="${tmpdir}/bootstrap-count"
    echo 0 > "${bootstrap_counter}"
    scp_root() { return 0; }
    ssh_admin() { return 1; }
    ssh_root() {
      if [[ "$1" == "true" || "$1" == chmod\ +x\ /root/* || "$1" == "chmod 600 /root/deploy.env" ]]; then
        return 0
      fi
      if [[ "$1" == *"/root/bootstrap_hardening.sh --env-file "* ]] && [[ "$1" == *"--install-tailscale --force"* ]]; then
        count="$(cat "${bootstrap_counter}")"
        count=$((count + 1))
        echo "${count}" > "${bootstrap_counter}"
        if (( count == 1 )); then
          [[ "${ROOT_SSH_HOST}" == "203.0.113.10" ]]
          echo "HARDEN_RESULT_TAILSCALE_IP=100.64.0.10"
          return 255
        fi
        [[ "${ROOT_SSH_HOST}" == "100.64.0.10" ]]
        echo "HARDEN_RESULT_TAILSCALE_IP=100.64.0.10"
        return 0
      fi
      return 0
    }
    run_with_heartbeat() { local label="$1"; shift; "$@"; }
    sleep() { :; }
    phase1_upload_harden
    [[ "${TS_IP}" == "100.64.0.10" ]]
    [[ "${ROOT_SSH_HOST}" == "100.64.0.10" ]]
    [[ "$(cat "${bootstrap_counter}")" -eq 2 ]]
  '
  assert_success
}

@test "phase1_upload_harden: promotes retries to admin sudo when root transport is no longer valid" {
  run bash -c '
    source "'"${DEPLOY_SCRIPT}"'"
    tmpdir="$(mktemp -d)"
    trap "rm -rf \"${tmpdir}\"" EXIT
    SCRIPT_DIR="${tmpdir}"
    for script in bootstrap_hardening.sh validate_hardening.sh configure_coolify_binding.sh; do
      : > "${tmpdir}/${script}"
    done
    SERVER_IP="203.0.113.10"
    ROOT_SSH_HOST="${SERVER_IP}"
    ADMIN_USER="alice"
    ADMIN_PUBKEY="ssh-ed25519 AAAA test@example"
    PRIVATE_KEY="${tmpdir}/id_ed25519"
    : > "${PRIVATE_KEY}"
    TS_IP="100.64.0.10"
    DEPLOY_MODE="tunnel"
    DOMAIN="server.example.com"
    SWAP_SIZE="2G"
    SERVER_TIMEZONE="UTC"
    TAILSCALE_AUTH_KEY="tskey-auth-test"
    TAILSCALE_DIRECT_WAN="false"
    REMOTE_DEPLOY_ENV_PATH="/root/deploy.env"
    bootstrap_counter="${tmpdir}/bootstrap-count"
    admin_counter="${tmpdir}/admin-bootstrap-count"
    echo 0 > "${bootstrap_counter}"
    echo 0 > "${admin_counter}"
    scp_root() { return 0; }
    ssh_root() {
      if [[ "$1" == "true" || "$1" == chmod\ +x\ /root/* || "$1" == "chmod 600 /root/deploy.env" ]]; then
        return 0
      fi
      if [[ "$1" == *"/root/bootstrap_hardening.sh --env-file "* ]] && [[ "$1" == *"--install-tailscale --force"* ]]; then
        count="$(cat "${bootstrap_counter}")"
        count=$((count + 1))
        echo "${count}" > "${bootstrap_counter}"
        if (( count == 1 )); then
          echo "HARDEN_RESULT_TAILSCALE_IP=100.64.0.10"
          return 255
        fi
        echo "root transport should not be reused after admin promotion" >&2
        return 99
      fi
      return 0
    }
    ssh_admin() {
      if [[ "$1" == "echo ok" ]]; then
        return 0
      fi
      return 1
    }
    ssh_admin_sudo() {
      if [[ "$1" == *"/root/bootstrap_hardening.sh --env-file "* ]] && [[ "$1" == *"--install-tailscale --force"* ]]; then
        count="$(cat "${admin_counter}")"
        count=$((count + 1))
        echo "${count}" > "${admin_counter}"
        echo "HARDEN_RESULT_TAILSCALE_IP=100.64.0.10"
        return 0
      fi
      return 0
    }
    run_with_heartbeat() { local label="$1"; shift; "$@"; }
    sleep() { :; }
    phase1_upload_harden
    [[ "${TS_IP}" == "100.64.0.10" ]]
    [[ "$(cat "${bootstrap_counter}")" -eq 1 ]]
    [[ "$(cat "${admin_counter}")" -eq 1 ]]
  '
  assert_success
  assert_output --partial "switching bootstrap retries to alice@100.64.0.10 via sudo"
}

@test "phase1_upload_harden: uploads DOMAIN in bootstrap env file" {
  run bash -c '
    source "'"${DEPLOY_SCRIPT}"'"
    tmpdir="$(mktemp -d)"
    trap "rm -rf \"${tmpdir}\"" EXIT
    SCRIPT_DIR="${tmpdir}"
    for script in bootstrap_hardening.sh validate_hardening.sh configure_coolify_binding.sh; do
      : > "${tmpdir}/${script}"
    done
    captured_env="${tmpdir}/deploy.env.captured"
    SERVER_IP="203.0.113.10"
    ADMIN_USER="alice"
    ADMIN_PUBKEY="ssh-ed25519 AAAA test@example"
    DOMAIN="vps.example.com"
    DEPLOY_MODE="tunnel"
    SWAP_SIZE="2G"
    SERVER_TIMEZONE="UTC"
    TAILSCALE_AUTH_KEY="tskey-auth-test"
    TAILSCALE_DIRECT_WAN="false"
    REMOTE_DEPLOY_ENV_PATH="/root/deploy.env"
    scp_root() {
      if [[ "${2:-}" == "root@203.0.113.10:/root/deploy.env" ]]; then
        cp "${1}" "${captured_env}"
      fi
      return 0
    }
    ssh_root() {
      if [[ "$1" == *"/root/bootstrap_hardening.sh --env-file "* ]] && [[ "$1" == *"--install-tailscale --force"* ]]; then
        echo "HARDEN_RESULT_TAILSCALE_IP=100.64.0.10"
      fi
      return 0
    }
    run_with_heartbeat() { local label="$1"; shift; "$@"; }
    phase1_upload_harden
    grep -q "^DOMAIN=\\\"vps.example.com\\\"$" "${captured_env}"
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
        *"/data/coolify/source/.env"*) return 0 ;;
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

@test "phase1_harden (setup): writes DOMAIN into bootstrap env file" {
  run bash -c '
    source "'"${SETUP_SCRIPT}"'"
    tmpdir="$(mktemp -d)"
    trap "rm -rf \"${tmpdir}\"" EXIT
    SCRIPT_DIR="${tmpdir}"
    DEPLOY_ENV_FILE="${tmpdir}/deploy.env"
    captured_env="${tmpdir}/captured.env"
    SERVER_IP="203.0.113.10"
    ADMIN_USER="coolifyadmin"
    ADMIN_PUBKEY="ssh-ed25519 AAAATEST key"
    DOMAIN="vps.example.com"
    TAILSCALE_AUTH_KEY="tskey-auth-test"
    DEPLOY_MODE="tunnel"
    SWAP_SIZE="2G"
    SERVER_TIMEZONE="UTC"
    TAILSCALE_DIRECT_WAN="false"

    cat > "${tmpdir}/bootstrap_hardening.sh" <<EOF
#!/usr/bin/env bash
cp "\$2" "${captured_env}"
echo "bootstrap stub"
EOF
    chmod +x "${tmpdir}/bootstrap_hardening.sh"

    tailscale() { echo "100.64.0.44"; }

    phase1_harden
    grep -q "^DOMAIN=\"vps.example.com\"$" "${captured_env}"
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

@test "pause_for_operator (setup): AUTO_YES=true fails with operator guidance" {
  run bash -c '
    source "'"${SETUP_SCRIPT}"'"
    AUTO_YES="true"
    pause_for_operator "check gate"
  '
  assert_failure
  assert_output --partial "Operator confirmation required"
  assert_output --partial "use deploy.sh"
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
