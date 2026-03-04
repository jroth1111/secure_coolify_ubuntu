#!/usr/bin/env bats
# Tier 0: Behavior contract tests for deploy.sh workflow logic

load '../helpers'

@test "deploy: preflight phase marker exists" {
  run bash -c '
    source "'"${DEPLOY_SCRIPT}"'"
    stubbin="$(mktemp -d)"
    cat > "${stubbin}/ssh-keygen" <<'\''EOF'\''
#!/usr/bin/env bash
exit 0
EOF
    chmod +x "${stubbin}/ssh-keygen"
    PATH="${stubbin}:${PATH}"
    command() { [[ "$1" == "-v" ]] && return 0; builtin command "$@"; }
    cf_verify_token() { :; }
    cf_get_zone_id() { CF_ZONE_ID="zone123"; }
    cf_get_account_id() { :; }
    resolve_app_domain() { :; }
    ssh_probe=0
    ssh_root() { ssh_probe=1; return 0; }

    SKIP_HARDEN="false"
    SERVER_IP="203.0.113.10"
    PUBKEY_FILE="/tmp/fake.pub"
    preflight
    [[ "${ssh_probe}" -eq 1 ]]
  '
  assert_success
}

@test "deploy: phase1 upload+harden marker exists" {
  run bash -c '
    source "'"${DEPLOY_SCRIPT}"'"
    SCRIPT_DIR="'"${PROJECT_ROOT}"'"
    SERVER_IP="203.0.113.10"
    ADMIN_USER="coolifyadmin"
    ADMIN_PUBKEY="ssh-ed25519 AAAATEST key"
    TAILSCALE_AUTH_KEY="tskey-auth-test"
    DEPLOY_MODE="tunnel"
    SWAP_SIZE="2G"
    TAILSCALE_DIRECT_WAN="false"

    scp_root() { :; }
    ssh_root() {
      if [[ "$1" == *"/root/bootstrap_hardening.sh"* ]]; then
        echo "progress"
        echo "HARDEN_RESULT_TAILSCALE_IP=100.64.0.25"
      fi
      return 0
    }

    phase1_upload_harden
    [[ "${TS_IP}" == "100.64.0.25" ]]
  '
  assert_success
}

@test "deploy: hardening invocation uses env-file and tailscale install" {
  run bash -c '
    source "'"${DEPLOY_SCRIPT}"'"
    SCRIPT_DIR="'"${PROJECT_ROOT}"'"
    SERVER_IP="203.0.113.10"
    ADMIN_USER="coolifyadmin"
    ADMIN_PUBKEY="ssh-ed25519 AAAATEST key"
    TAILSCALE_AUTH_KEY="tskey-auth-test"
    DEPLOY_MODE="tunnel"
    SWAP_SIZE="2G"
    TAILSCALE_DIRECT_WAN="false"
    cmd_file="$(mktemp)"

    scp_root() { :; }
    ssh_root() {
      if [[ "$1" == *"/root/bootstrap_hardening.sh"* ]]; then
        printf "%s\n" "$1" > "${cmd_file}"
        echo "HARDEN_RESULT_TAILSCALE_IP=100.64.0.25"
      fi
      return 0
    }

    phase1_upload_harden
    grep -q -- "--env-file /root/deploy.env --install-tailscale --force" "${cmd_file}"
  '
  assert_success
}

@test "deploy: gate A checks admin SSH on tailscale" {
  run bash -c '
    source "'"${DEPLOY_SCRIPT}"'"
    TS_IP="100.64.0.25"
    ADMIN_USER="coolifyadmin"
    attempts=0
    sync_called=0

    sleep() { :; }
    ssh_admin() {
      if [[ "$1" == "echo ok" ]]; then
        attempts=$((attempts + 1))
        (( attempts < 3 )) && return 1
        echo ok
        return 0
      fi
      if [[ "$1" == "whoami" ]]; then
        echo "${ADMIN_USER}"
        return 0
      fi
      return 0
    }
    ssh_admin_sudo() {
      if [[ "$1" == *"validate_hardening.sh --json"* ]]; then
        echo "{\"fail\":0,\"checks\":[]}"
      fi
      return 0
    }
    reconcile_docker_daemon_remote() { :; }
    sync_companion_scripts() { sync_called=1; }
    report_validation_result() { :; }

    phase2_gates
    [[ "${attempts}" -eq 3 ]]
    [[ "${sync_called}" -eq 1 ]]
  '
  assert_success
}

@test "deploy: gate B verifies admin identity" {
  run bash -c '
    source "'"${DEPLOY_SCRIPT}"'"
    TS_IP="100.64.0.25"
    ADMIN_USER="coolifyadmin"

    sleep() { :; }
    ssh_admin() {
      if [[ "$1" == "echo ok" ]]; then
        echo ok
        return 0
      fi
      if [[ "$1" == "whoami" ]]; then
        echo "wronguser"
        return 0
      fi
      return 0
    }
    ssh_admin_sudo() { return 0; }
    sync_companion_scripts() { :; }
    report_validation_result() { :; }

    phase2_gates
  '
  assert_failure
  assert_output --partial "Gate B failed."
}

@test "deploy: gate C runs validate_hardening.sh json" {
  run bash -c '
    source "'"${DEPLOY_SCRIPT}"'"
    TS_IP="100.64.0.25"
    ADMIN_USER="coolifyadmin"
    validate_seen_file="$(mktemp)"
    report_seen=0

    ssh_admin() {
      [[ "$1" == "echo ok" ]] && { echo ok; return 0; }
      [[ "$1" == "whoami" ]] && { echo "${ADMIN_USER}"; return 0; }
      return 0
    }
    ssh_admin_sudo() {
      if [[ "$1" == *"validate_hardening.sh --json"* ]]; then
        printf "seen\n" > "${validate_seen_file}"
        echo "{\"fail\":0,\"checks\":[]}"
      fi
      return 0
    }
    reconcile_docker_daemon_remote() { :; }
    sync_companion_scripts() { :; }
    report_validation_result() {
      [[ "$1" == "Gate C" ]]
      [[ "$2" == *"\"fail\":0"* ]]
      report_seen=1
    }

    phase2_gates
    [[ -f "${validate_seen_file}" ]]
    [[ "${report_seen}" -eq 1 ]]
  '
  assert_success
}

@test "deploy: gate D validates service active and managed rules" {
  run bash -c '
    source "'"${DEPLOY_SCRIPT}"'"
    ssh_admin_sudo() {
      if [[ "$1" == *"systemctl is-active --quiet docker-user-hardening.service"* ]]; then
        return 1
      fi
      return 0
    }
    verify_docker_user_gate_remote "Gate D"
  '
  assert_failure
  assert_output --partial "Gate D failed: docker-user-hardening.service is not active."
}

@test "deploy: phase4 binding+dns marker exists" {
  run bash -c '
    source "'"${DEPLOY_SCRIPT}"'"
    DEPLOY_MODE="standard"
    DOMAIN="coolify.vps.example.com"
    APP_DOMAIN="vps.example.com"
    CF_ZONE_NAME="example.com"
    SERVER_IP="203.0.113.10"
    TS_IP="100.64.0.25"
    calls=""

    ssh_admin_sudo() {
      if [[ "$1" == *"bash -s"* ]]; then
        cat >/dev/null || true
      fi
      [[ "$1" == "test -f /data/coolify/source/.env" ]] && return 0
      return 0
    }
    coolify_set_wildcard_domain_script() { echo "true"; }
    coolify_reconcile_pusher_env_script() { echo "true"; }
    cf_upsert_a_record() { calls+="$1|$2|$3"$'\''\n'\''; }

    phase4_binding_dns
    grep -q "^coolify.vps.example.com|203.0.113.10|true$" <<< "${calls}"
    grep -q "^\\*.vps.example.com|203.0.113.10|true$" <<< "${calls}"
    grep -q "^\\*.example.com|203.0.113.10|true$" <<< "${calls}"
  '
  assert_success
}

@test "deploy: gate E fails when exposure checks do not pass" {
  run bash -c '
    source "'"${DEPLOY_SCRIPT}"'"
    TS_IP="100.64.0.25"
    SERVER_IP="203.0.113.10"
    DOMAIN="coolify.vps.example.com"

    sleep() { :; }
    curl() { echo "000"; return 0; }

    phase5_verify
  '
  assert_failure
  assert_output --partial "Gate E failed: dashboard not reachable via Tailscale."
}

@test "deploy: final validation is executed" {
  run bash -c '
    source "'"${DEPLOY_SCRIPT}"'"
    TS_IP="100.64.0.25"
    SERVER_IP="203.0.113.10"
    DOMAIN="coolify.vps.example.com"
    validate_seen_file="$(mktemp)"
    report_seen=0

    sleep() { :; }
    curl() {
      local url="${@: -1}"
      if [[ "${url}" == "http://${TS_IP}:8000" ]]; then
        echo "200"
      elif [[ "${url}" == "http://${SERVER_IP}:8000" ]]; then
        echo "000"
      else
        echo "302"
      fi
      return 0
    }
    ssh_admin_sudo() {
      if [[ "$1" == *"validate_hardening.sh --json"* ]]; then
        printf "seen\n" > "${validate_seen_file}"
        echo "{\"fail\":0,\"checks\":[]}"
      fi
      return 0
    }
    report_validation_result() {
      [[ "$1" == "Final validation" ]]
      [[ "$2" == *"\"fail\":0"* ]]
      report_seen=1
    }
    print_deployment_summary() { :; }

    phase5_verify
    [[ -f "${validate_seen_file}" ]]
    [[ "${report_seen}" -eq 1 ]]
  '
  assert_success
}
