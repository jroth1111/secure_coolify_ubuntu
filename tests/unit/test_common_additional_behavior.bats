#!/usr/bin/env bats
# Additional behavior tests for uncovered lib/coolify-common.sh functions.

load '../helpers'

setup() {
  source_common_lib
}

@test "confirm: AUTO_YES=true skips prompt and returns success" {
  AUTO_YES="true"
  run confirm "Continue?"
  assert_success
}

@test "prompt_value: AUTO_YES accepts default and assigns variable" {
  AUTO_YES="true"
  prompt_value TEST_VALUE "Value" "default-x"
  [ "${TEST_VALUE}" = "default-x" ]
}

@test "prompt_secret: reads secret from stdin and sets variable" {
  run bash -c '
    source "'"${COMMON_LIB}"'"
    printf "s3cr3t\n" | prompt_secret TOKEN "Token"
    [[ "${TOKEN}" == "s3cr3t" ]]
  '
  assert_success
}

@test "prompt_choice: invalid value fails validation" {
  run bash -c '
    source "'"${COMMON_LIB}"'"
    AUTO_YES="false"
    printf "invalid\n" | prompt_choice MODE "Mode" "a" "a" "b"
  '
  assert_failure
}

@test "cf_expect_success: passes for success=true and fails for success=false" {
  run cf_expect_success "action" '{"success":true}'
  assert_success

  run cf_expect_success "action" '{"success":false,"errors":[{"message":"boom"}]}'
  assert_failure
  assert_output --partial "action failed"
}

@test "coolify_install_docker_engine_script: emits apt-repo based install script" {
  run coolify_install_docker_engine_script
  assert_success
  assert_output --partial "download.docker.com/linux/ubuntu"
  assert_output --partial "apt-get install -y -qq docker-ce"
}

@test "coolify_install_coolify_script: emits downloaded-installer execution flow" {
  run coolify_install_coolify_script
  assert_success
  assert_output --partial "cdn.coollabs.io/coolify/install.sh"
  assert_output --partial "bash \"${tmp}\""
}

@test "coolify_reconcile_docker_daemon_script: emits daemon hardening merge logic" {
  run coolify_reconcile_docker_daemon_script
  assert_success
  assert_output --partial '"default-ipc-mode":"private"'
  assert_output --partial '"storage-driver":"overlay2"'
}

@test "coolify_add_coolify_root_key_script: emits idempotent authorized_keys reconciliation" {
  run coolify_add_coolify_root_key_script
  assert_success
  assert_output --partial "authorized_keys"
  assert_output --partial "Coolify key already"
}

@test "coolify_fix_host_docker_internal_script: emits gateway patch and compose recreate" {
  run coolify_fix_host_docker_internal_script
  assert_success
  assert_output --partial "host.docker.internal"
  assert_output --partial "docker compose"
}

@test "coolify_install_cloudflared_script: emits apt-first then repository fallback" {
  run coolify_install_cloudflared_script
  assert_success
  assert_output --partial "apt-get install -y -qq cloudflared"
  assert_output --partial "pkg.cloudflare.com"
}

@test "coolify_configure_cloudflared_script: emits path-based terminal ingress and service enable" {
  run coolify_configure_cloudflared_script
  assert_success
  assert_output --partial "path: /terminal/ws"
  assert_output --partial "systemctl enable --now cloudflared"
}

@test "collect_common_inputs: preserves pre-populated values without prompting" {
  SERVER_IP="203.0.113.10"
  ADMIN_USER="alice"
  PUBKEY_FILE="/tmp/id.pub"
  TAILSCALE_AUTH_KEY="tskey-auth-abc"
  DEPLOY_MODE="tunnel"
  DOMAIN="vps.example.com"
  CF_API_TOKEN="token"
  SWAP_SIZE="2G"
  APP_DOMAIN_MODE="apex"

  collect_common_inputs

  [ "${SERVER_IP}" = "203.0.113.10" ]
  [ "${APP_DOMAIN_MODE}" = "apex" ]
}

@test "cf_get_account_id: stores account id from Cloudflare API response" {
  cf_api() { echo '{"result":[{"id":"acct-123"}]}'; }
  cf_get_account_id
  [ "${CF_ACCOUNT_ID}" = "acct-123" ]
}

@test "coolify_reconcile_pusher_env_script: emits PUSHER mode reconciliation script" {
  run coolify_reconcile_pusher_env_script
  assert_success
  assert_output --partial "PUSHER_HOST=ws.${DOMAIN}"
  assert_output --partial "install -m 0600"
}

@test "coolify_set_wildcard_domain_script: emits DB update with ON_ERROR_STOP" {
  run coolify_set_wildcard_domain_script
  assert_success
  assert_output --partial "DB_PASSWORD="
  assert_output --partial "ON_ERROR_STOP=1"
}

@test "print_deployment_summary: prints completion banner and key endpoints" {
  SERVER_IP="203.0.113.10"
  TS_IP="100.64.0.10"
  ADMIN_USER="alice"
  DEPLOY_MODE="standard"
  DOMAIN="vps.example.com"
  CF_ZONE_NAME="example.com"
  APP_DOMAIN="example.com"
  TUNNEL_ID=""

  run print_deployment_summary
  assert_success
  assert_output --partial "DEPLOYMENT COMPLETE"
  assert_output --partial "http://100.64.0.10:8000"
}

@test "report_validation_result: passes when fail count is zero and fails otherwise" {
  run report_validation_result "Gate X" '{"fail":0,"checks":[]}' "boom"
  assert_success
  assert_output --partial "0 failures"

  run report_validation_result "Gate X" '{"fail":2,"checks":[{\"status\":\"FAIL\"}]}' "boom"
  assert_failure
  assert_output --partial "reported 2 failures"
}

@test "resolve_app_domain: derives app domain by selected mode" {
  APP_DOMAIN_MODE="apex"
  CF_ZONE_NAME="example.com"
  DOMAIN="vps.example.com"
  resolve_app_domain
  [ "${APP_DOMAIN}" = "example.com" ]

  APP_DOMAIN_MODE="vps"
  resolve_app_domain
  [ "${APP_DOMAIN}" = "vps.example.com" ]
}

@test "coolify_phase3_docker_coolify_shared: runs gate/reconcile flow and skips installs when already present" {
  run bash -c '
    source "'"${COMMON_LIB}"'"
    install_docker_calls=0
    install_coolify_calls=0
    verify_calls=0
    start_calls=0
    restart_calls=0
    key_calls=0
    fix_calls=0
    reconcile_calls=0

    has_docker() { return 0; }
    install_docker() { install_docker_calls=$((install_docker_calls + 1)); }
    start_docker_user() { start_calls=$((start_calls + 1)); }
    verify_docker_user() { verify_calls=$((verify_calls + 1)); [[ "$1" =~ Gate\ D ]]; }
    has_coolify_env() { return 0; }
    install_coolify() { install_coolify_calls=$((install_coolify_calls + 1)); }
    reconcile_docker_daemon() { reconcile_calls=$((reconcile_calls + 1)); }
    restart_docker_user() { restart_calls=$((restart_calls + 1)); }
    add_coolify_key() { key_calls=$((key_calls + 1)); }
    fix_host_internal() { fix_calls=$((fix_calls + 1)); }

    coolify_phase3_docker_coolify_shared \
      has_docker install_docker start_docker_user verify_docker_user \
      has_coolify_env install_coolify reconcile_docker_daemon restart_docker_user \
      add_coolify_key fix_host_internal

    [[ "${install_docker_calls}" -eq 0 ]]
    [[ "${install_coolify_calls}" -eq 0 ]]
    [[ "${verify_calls}" -eq 2 ]]
    [[ "${start_calls}" -eq 1 ]]
    [[ "${restart_calls}" -eq 1 ]]
    [[ "${reconcile_calls}" -eq 1 ]]
    [[ "${key_calls}" -eq 1 ]]
    [[ "${fix_calls}" -eq 1 ]]
  '
  assert_success
}

@test "coolify_phase4_binding_dns_shared: standard mode applies wildcard A-records without tunnel path" {
  run bash -c '
    source "'"${COMMON_LIB}"'"
    DEPLOY_MODE="standard"
    DOMAIN="coolify.vps.example.com"
    APP_DOMAIN="vps.example.com"
    CF_ZONE_NAME="example.com"
    SERVER_IP="203.0.113.10"
    wait_checks=0
    bind_calls=0
    wildcard_calls=0
    pusher_calls=0
    a_records=""

    coolify_env_exists() { wait_checks=$((wait_checks + 1)); return 0; }
    configure_binding() { bind_calls=$((bind_calls + 1)); }
    set_wildcard_domain() { wildcard_calls=$((wildcard_calls + 1)); }
    reconcile_pusher() { pusher_calls=$((pusher_calls + 1)); }
    install_cloudflared() { return 0; }
    configure_cloudflared() { return 0; }
    stop_cloudflared() { return 0; }
    cf_upsert_a_record() { a_records+="$1|$2|$3"$'"'"'\n'"'"'; }
    cf_create_tunnel() { echo "unexpected tunnel" >&2; return 1; }
    cf_upsert_cname() { echo "unexpected cname" >&2; return 1; }

    coolify_phase4_binding_dns_shared \
      coolify_env_exists configure_binding set_wildcard_domain reconcile_pusher \
      install_cloudflared configure_cloudflared stop_cloudflared

    [[ "${wait_checks}" -eq 1 ]]
    [[ "${bind_calls}" -eq 1 ]]
    [[ "${wildcard_calls}" -eq 1 ]]
    [[ "${pusher_calls}" -eq 1 ]]
    grep -q "^coolify.vps.example.com|203.0.113.10|true$" <<< "${a_records}"
    grep -q "^\\*.vps.example.com|203.0.113.10|true$" <<< "${a_records}"
    grep -q "^\\*.example.com|203.0.113.10|true$" <<< "${a_records}"
  '
  assert_success
}
