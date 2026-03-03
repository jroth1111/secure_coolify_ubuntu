#!/usr/bin/env bats
# Tier 0: Behavior contract tests for setup.sh workflow logic

load '../helpers'

@test "setup: preflight phase marker exists" {
  run bash -c '
    source "'"${SETUP_SCRIPT}"'"
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

    SERVER_IP="203.0.113.10"
    PUBKEY_FILE="/tmp/fake.pub"
    preflight
  '
  assert_success
}

@test "setup: phase1 harden marker exists" {
  run bash -c '
    source "'"${SETUP_SCRIPT}"'"
    tmpdir="$(mktemp -d)"
    SCRIPT_DIR="${tmpdir}"
    DEPLOY_ENV_FILE="${tmpdir}/deploy.env"
    SERVER_IP="203.0.113.10"
    ADMIN_USER="coolifyadmin"
    ADMIN_PUBKEY="ssh-ed25519 AAAATEST key"
    TAILSCALE_AUTH_KEY="tskey-auth-test"
    DEPLOY_MODE="tunnel"
    SWAP_SIZE="2G"
    TAILSCALE_DIRECT_WAN="false"

    cat > "${tmpdir}/bootstrap_hardening.sh" <<'\''EOF'\''
#!/usr/bin/env bash
echo "bootstrap stub"
EOF
    chmod +x "${tmpdir}/bootstrap_hardening.sh"

    tailscale() { echo "100.64.0.44"; }

    phase1_harden
    [[ "${TS_IP}" == "100.64.0.44" ]]
    [[ ! -f "${DEPLOY_ENV_FILE}" ]]
  '
  assert_success
}

@test "setup: gate A requires operator laptop verification" {
  run bash -c '
    source "'"${SETUP_SCRIPT}"'"
    tmpdir="$(mktemp -d)"
    SCRIPT_DIR="${tmpdir}"
    cat > "${tmpdir}/validate_hardening.sh" <<'\''EOF'\''
#!/usr/bin/env bash
echo "{\"fail\":0,\"checks\":[]}"
EOF
    chmod +x "${tmpdir}/validate_hardening.sh"
    TS_IP="100.64.0.25"
    ADMIN_USER="coolifyadmin"

    pause_for_operator() { echo "$1"; }
    tmphome="$(mktemp -d)"
    mkdir -p "${tmphome}/.ssh"
    getent() { echo "coolifyadmin:x:1001:1001::${tmphome}:/bin/bash"; }
    report_validation_result() { :; }

    phase2_gates
  '
  assert_success
  assert_output --partial "From your LAPTOP, verify SSH: ssh"
}

@test "setup: gate B verifies admin user home and ssh directory" {
  run bash -c '
    source "'"${SETUP_SCRIPT}"'"
    tmpdir="$(mktemp -d)"
    SCRIPT_DIR="${tmpdir}"
    cat > "${tmpdir}/validate_hardening.sh" <<'\''EOF'\''
#!/usr/bin/env bash
echo "{\"fail\":0,\"checks\":[]}"
EOF
    chmod +x "${tmpdir}/validate_hardening.sh"
    TS_IP="100.64.0.25"
    ADMIN_USER="coolifyadmin"
    pause_for_operator() { :; }
    getent() { echo "coolifyadmin:x:1001:1001::/tmp/missinghome:/bin/bash"; }
    report_validation_result() { :; }

    phase2_gates
  '
  assert_failure
  assert_output --partial "Gate B failed."
}

@test "setup: gate C runs validate_hardening.sh json" {
  run bash -c '
    source "'"${SETUP_SCRIPT}"'"
    tmpdir="$(mktemp -d)"
    SCRIPT_DIR="${tmpdir}"
    cat > "${tmpdir}/validate_hardening.sh" <<EOF
#!/usr/bin/env bash
touch "${tmpdir}/validate_called"
echo "{\"fail\":0,\"checks\":[]}"
EOF
    chmod +x "${tmpdir}/validate_hardening.sh"
    TS_IP="100.64.0.25"
    ADMIN_USER="coolifyadmin"
    pause_for_operator() { :; }
    tmphome="$(mktemp -d)"
    mkdir -p "${tmphome}/.ssh"
    getent() { echo "coolifyadmin:x:1001:1001::${tmphome}:/bin/bash"; }
    report_seen=0
    report_validation_result() {
      [[ "$1" == "Gate C" ]]
      [[ "$2" == *"\"fail\":0"* ]]
      report_seen=1
    }

    phase2_gates
    [[ -f "${tmpdir}/validate_called" ]]
    [[ "${report_seen}" -eq 1 ]]
  '
  assert_success
}

@test "setup: gate D validates service active and managed rules" {
  run bash -c '
    source "'"${SETUP_SCRIPT}"'"
    systemctl() { return 1; }
    verify_docker_user_gate_local "Gate D"
  '
  assert_failure
  assert_output --partial "Gate D failed: docker-user-hardening.service is not active."
}

@test "setup: phase4 binding+dns marker exists" {
  run bash -c '
    source "'"${SETUP_SCRIPT}"'"
    DEPLOY_MODE="standard"
    DOMAIN="coolify.vps.example.com"
    APP_DOMAIN="vps.example.com"
    CF_ZONE_NAME="example.com"
    SERVER_IP="203.0.113.10"
    TS_IP="100.64.0.25"
    calls=""
    tmpdir="$(mktemp -d)"
    SCRIPT_DIR="${tmpdir}"
    cat > "${tmpdir}/configure_coolify_binding.sh" <<'\''EOF'\''
#!/usr/bin/env bash
exit 0
EOF
    chmod +x "${tmpdir}/configure_coolify_binding.sh"
    sleep() { :; }

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

@test "setup: gate E requires operator laptop verification" {
  run bash -c '
    source "'"${SETUP_SCRIPT}"'"
    tmpdir="$(mktemp -d)"
    SCRIPT_DIR="${tmpdir}"
    cat > "${tmpdir}/validate_hardening.sh" <<'\''EOF'\''
#!/usr/bin/env bash
echo "{\"fail\":0,\"checks\":[]}"
EOF
    chmod +x "${tmpdir}/validate_hardening.sh"
    TS_IP="100.64.0.25"
    SERVER_IP="203.0.113.10"
    prompt_seen=0

    pause_for_operator() { prompt_seen=1; }
    report_validation_result() { :; }
    print_deployment_summary() { :; }

    phase5_verify
    [[ "${prompt_seen}" -eq 1 ]]
  '
  assert_success
}

@test "setup: final validation is executed" {
  run bash -c '
    source "'"${SETUP_SCRIPT}"'"
    tmpdir="$(mktemp -d)"
    SCRIPT_DIR="${tmpdir}"
    cat > "${tmpdir}/validate_hardening.sh" <<EOF
#!/usr/bin/env bash
touch "${tmpdir}/validate_called"
echo "{\"fail\":0,\"checks\":[]}"
EOF
    chmod +x "${tmpdir}/validate_hardening.sh"
    TS_IP="100.64.0.25"
    SERVER_IP="203.0.113.10"
    pause_for_operator() { :; }
    report_seen=0
    report_validation_result() {
      [[ "$1" == "Final validation" ]]
      [[ "$2" == *"\"fail\":0"* ]]
      report_seen=1
    }
    print_deployment_summary() { :; }

    phase5_verify
    [[ -f "${tmpdir}/validate_called" ]]
    [[ "${report_seen}" -eq 1 ]]
  '
  assert_success
}
