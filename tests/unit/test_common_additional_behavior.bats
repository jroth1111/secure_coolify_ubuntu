#!/usr/bin/env bats
# Additional behavior tests for uncovered lib/coolify-common.sh functions.

load '../helpers'

setup() {
  source_common_lib
}

@test "is_true (common): truthy and falsy values return expected status" {
  run is_true "true"
  assert_success

  run is_true "no"
  assert_failure
}

@test "log/warn helpers: emit expected prefixes" {
  run log "hello"
  assert_success
  assert_output --partial "hello"

  run warn "careful"
  assert_success
  assert_output --partial "WARN: careful"
}

@test "die helper: exits non-zero with fatal message" {
  run die "boom"
  assert_failure
  assert_output --partial "FATAL: boom"
}

@test "step/pass/fail helpers: print formatted status output" {
  run bash -c '
    source "'"${COMMON_LIB}"'"
    step "1/5" "phase"
    pass "ok"
    fail "bad"
  '
  assert_success
  assert_output --partial "1/5"
  assert_output --partial "PASS"
  assert_output --partial "FAIL"
}

@test "run_report lifecycle: emits structured JSON with steps and gates" {
  run bash -c '
    source "'"${COMMON_LIB}"'"
    report_path="'"${BATS_TEST_TMPDIR}"'/run-report.json"
    RUN_REPORT_FILE="${report_path}"
    run_report_init "deploy.sh"
    step "0/5" "Pre-flight checks"
    pass "Gate A: ssh ok"
    step "1/5" "Upload scripts & harden server"
    fail "Gate B: identity mismatch"
    RUN_REPORT_ROOT_CAUSE="Gate B failed."
    run_report_finalize 1
    [[ -f "${report_path}" ]]
    jq -e ".script == \"deploy.sh\"" "${report_path}" >/dev/null
    jq -e ".status == \"fail\"" "${report_path}" >/dev/null
    jq -e "(.steps | length) >= 2" "${report_path}" >/dev/null
    jq -e "(.gates | length) >= 2" "${report_path}" >/dev/null
    jq -e ".root_cause | contains(\"Gate B\")" "${report_path}" >/dev/null
  '
  assert_success
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
  assert_output --partial "DEBIAN_FRONTEND=noninteractive"
  assert_output --partial "apt-get install -y -qq cloudflared"
  assert_output --partial "pkg.cloudflare.com"
}

@test "coolify_configure_private_dashboard_routes_script: emits managed Traefik routes for dashboard and ws hosts" {
  run coolify_configure_private_dashboard_routes_script
  assert_success
  assert_output --partial "coolify-private-dashboard.yaml"
  assert_output --partial 'rule: "Host(`ws.${DOMAIN}`)"'
  assert_output --partial "http://coolify:8080"
  assert_output --partial "http://coolify-realtime:6001"
  assert_output --partial "http://coolify-realtime:6002"
}

@test "coolify_remove_private_dashboard_routes_script: emits managed route cleanup logic" {
  run coolify_remove_private_dashboard_routes_script
  assert_success
  assert_output --partial "coolify-private-dashboard.yaml"
  assert_output --partial "rm -f"
}

@test "coolify_configure_cloudflared_script: emits private-only dashboard/ws deny rules and service enable" {
  run coolify_configure_cloudflared_script
  assert_success
  assert_output --partial "hostname: ${DOMAIN}"
  assert_output --partial "hostname: ws.${DOMAIN}"
  assert_output --partial "service: http_status:404"
  assert_output --partial "service: http://localhost:80"
  [[ "${output}" != *"/terminal/ws"* ]]
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
  SERVER_TIMEZONE="UTC"
  APP_DOMAIN_MODE="apex"

  collect_common_inputs

  [ "${SERVER_IP}" = "203.0.113.10" ]
  [ "${SERVER_TIMEZONE}" = "UTC" ]
  [ "${APP_DOMAIN_MODE}" = "apex" ]
}

@test "cf_get_account_id: stores account id from Cloudflare API response" {
  cf_api() { echo '{"result":[{"id":"acct-123"}]}'; }
  cf_get_account_id
  [ "${CF_ACCOUNT_ID}" = "acct-123" ]
}

@test "finalize_cloudflare_tokens: reuses DNS token when tunnel token is omitted" {
  CF_API_TOKEN="dns-token"
  CF_TUNNEL_API_TOKEN=""
  finalize_cloudflare_tokens
  [ "${CF_TUNNEL_API_TOKEN}" = "dns-token" ]
}

@test "finalize_cloudflare_tokens: keeps explicit split tunnel token" {
  CF_API_TOKEN="dns-token"
  CF_TUNNEL_API_TOKEN="tunnel-token"
  finalize_cloudflare_tokens
  [ "${CF_API_TOKEN}" = "dns-token" ]
  [ "${CF_TUNNEL_API_TOKEN}" = "tunnel-token" ]
}

@test "cf_tunnel_api: prefers dedicated tunnel token over DNS token" {
  CF_API_TOKEN="dns-token"
  CF_TUNNEL_API_TOKEN="tunnel-token"
  cf_api_with_token() { printf '%s' "$4"; }
  run cf_tunnel_api GET /accounts/test/cfd_tunnel
  assert_success
  assert_output "tunnel-token"
}

@test "cf_verify_tunnel_token: skips tunnel permission checks in standard mode" {
  DEPLOY_MODE="standard"
  cf_tunnel_api() { echo "should-not-run"; return 1; }
  run cf_verify_tunnel_token
  assert_success
}

@test "cf_verify_tunnel_token: fails fast on auth error code 10000" {
  DEPLOY_MODE="tunnel"
  CF_ACCOUNT_ID="acct-123"
  call_count=0
  cf_tunnel_api() {
    call_count=$((call_count + 1))
    if [[ "${call_count}" -eq 1 ]]; then
      echo '{"success":false,"errors":[{"code":10000,"message":"not authorized"}]}'
      return 0
    fi
    echo '{"success":true}'
  }
  run cf_verify_tunnel_token
  assert_failure
  assert_output --partial "required permissions"
}

@test "coolify_reconcile_pusher_env_script: emits PUSHER mode reconciliation script" {
  run coolify_reconcile_pusher_env_script
  assert_success
  assert_output --partial 'PUSHER_HOST=${TS_IP}'
  assert_output --partial "PUSHER_PORT=6001"
  assert_output --partial "PUSHER_SCHEME=http"
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
    sync_calls=0
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
    sync_docker_ssh_cidrs() { sync_calls=$((sync_calls + 1)); }

    coolify_phase3_docker_coolify_shared \
      has_docker install_docker start_docker_user verify_docker_user \
      has_coolify_env install_coolify reconcile_docker_daemon restart_docker_user \
      add_coolify_key fix_host_internal sync_docker_ssh_cidrs

    [[ "${install_docker_calls}" -eq 0 ]]
    [[ "${install_coolify_calls}" -eq 0 ]]
    [[ "${verify_calls}" -eq 2 ]]
    [[ "${start_calls}" -eq 1 ]]
    [[ "${restart_calls}" -eq 1 ]]
    [[ "${reconcile_calls}" -eq 1 ]]
    [[ "${key_calls}" -eq 1 ]]
    [[ "${fix_calls}" -eq 1 ]]
    [[ "${sync_calls}" -eq 1 ]]
  '
  assert_success
}

@test "coolify_phase3_docker_coolify_shared: retries Coolify presence probe before install" {
  run bash -c '
    source "'"${COMMON_LIB}"'"
    install_coolify_calls=0
    coolify_probe_calls=0

    has_docker() { return 0; }
    install_docker() { return 0; }
    start_docker_user() { return 0; }
    verify_docker_user() { return 0; }
    has_coolify_env() {
      coolify_probe_calls=$((coolify_probe_calls + 1))
      [[ "${coolify_probe_calls}" -ge 2 ]]
    }
    install_coolify() { install_coolify_calls=$((install_coolify_calls + 1)); }
    reconcile_docker_daemon() { return 0; }
    restart_docker_user() { return 0; }
    add_coolify_key() { return 0; }
    fix_host_internal() { return 0; }
    sync_docker_ssh_cidrs() { return 0; }
    sleep() { :; }

    coolify_phase3_docker_coolify_shared \
      has_docker install_docker start_docker_user verify_docker_user \
      has_coolify_env install_coolify reconcile_docker_daemon restart_docker_user \
      add_coolify_key fix_host_internal sync_docker_ssh_cidrs

    [[ "${coolify_probe_calls}" -ge 2 ]]
    [[ "${install_coolify_calls}" -eq 0 ]]
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
    configure_private_routes_calls=0
    remove_private_routes_calls=0
    a_records=""

    coolify_env_exists() { wait_checks=$((wait_checks + 1)); return 0; }
    configure_binding() { bind_calls=$((bind_calls + 1)); }
    set_wildcard_domain() { wildcard_calls=$((wildcard_calls + 1)); }
    reconcile_pusher() { pusher_calls=$((pusher_calls + 1)); }
    install_cloudflared() { return 0; }
    configure_cloudflared() { return 0; }
    stop_cloudflared() { return 0; }
    configure_private_routes() { configure_private_routes_calls=$((configure_private_routes_calls + 1)); }
    remove_private_routes() { remove_private_routes_calls=$((remove_private_routes_calls + 1)); }
    cf_upsert_a_record() { a_records+="$1|$2|$3"$'"'"'\n'"'"'; }
    cf_create_tunnel() { echo "unexpected tunnel" >&2; return 1; }
    cf_upsert_cname() { echo "unexpected cname" >&2; return 1; }

    coolify_phase4_binding_dns_shared \
      coolify_env_exists configure_binding set_wildcard_domain reconcile_pusher \
      install_cloudflared configure_cloudflared stop_cloudflared \
      configure_private_routes remove_private_routes

    [[ "${wait_checks}" -eq 1 ]]
    [[ "${bind_calls}" -eq 1 ]]
    [[ "${wildcard_calls}" -eq 1 ]]
    [[ "${pusher_calls}" -eq 1 ]]
    [[ "${configure_private_routes_calls}" -eq 0 ]]
    [[ "${remove_private_routes_calls}" -eq 1 ]]
    grep -q "^coolify.vps.example.com|203.0.113.10|true$" <<< "${a_records}"
    grep -q "^\\*.vps.example.com|203.0.113.10|true$" <<< "${a_records}"
    grep -q "^\\*.example.com|203.0.113.10|true$" <<< "${a_records}"
  '
  assert_success
}

@test "coolify_phase4_binding_dns_shared: tunnel mode configures private host A records and wildcard CNAMEs" {
  run bash -c '
    source "'"${COMMON_LIB}"'"
    DEPLOY_MODE="tunnel"
    DOMAIN="coolify.vps.example.com"
    APP_DOMAIN="vps.example.com"
    CF_ZONE_NAME="example.com"
    TS_IP="100.64.0.25"
    TUNNEL_ID="tunnel-1234"
    wait_checks=0
    bind_calls=0
    wildcard_calls=0
    pusher_calls=0
    install_calls=0
    configure_calls=0
    stop_calls=0
    create_tunnel_calls=0
    configure_private_routes_calls=0
    remove_private_routes_calls=0
    deleted_hosts=""
    a_records=""
    cname_records=""

    coolify_env_exists() { wait_checks=$((wait_checks + 1)); return 0; }
    configure_binding() { bind_calls=$((bind_calls + 1)); }
    set_wildcard_domain() { wildcard_calls=$((wildcard_calls + 1)); }
    reconcile_pusher() { pusher_calls=$((pusher_calls + 1)); }
    install_cloudflared() { install_calls=$((install_calls + 1)); }
    configure_cloudflared() { configure_calls=$((configure_calls + 1)); }
    stop_cloudflared() { stop_calls=$((stop_calls + 1)); }
    configure_private_routes() { configure_private_routes_calls=$((configure_private_routes_calls + 1)); }
    remove_private_routes() { remove_private_routes_calls=$((remove_private_routes_calls + 1)); }
    cf_create_tunnel() { create_tunnel_calls=$((create_tunnel_calls + 1)); }
    cf_delete_host_records() { deleted_hosts+="$1"$'"'"'\n'"'"'; }
    cf_upsert_a_record() { a_records+="$1|$2|$3"$'"'"'\n'"'"'; }
    cf_upsert_cname() { cname_records+="$1|$2"$'"'"'\n'"'"'; }

    coolify_phase4_binding_dns_shared \
      coolify_env_exists configure_binding set_wildcard_domain reconcile_pusher \
      install_cloudflared configure_cloudflared stop_cloudflared \
      configure_private_routes remove_private_routes

    [[ "${wait_checks}" -eq 1 ]]
    [[ "${bind_calls}" -eq 1 ]]
    [[ "${wildcard_calls}" -eq 1 ]]
    [[ "${pusher_calls}" -eq 1 ]]
    [[ "${install_calls}" -eq 1 ]]
    [[ "${configure_calls}" -eq 1 ]]
    [[ "${create_tunnel_calls}" -eq 1 ]]
    [[ "${stop_calls}" -eq 0 ]]
    [[ "${configure_private_routes_calls}" -eq 1 ]]
    [[ "${remove_private_routes_calls}" -eq 0 ]]
    grep -q "^coolify.vps.example.com$" <<< "${deleted_hosts}"
    grep -q "^ws.coolify.vps.example.com$" <<< "${deleted_hosts}"
    grep -q "^coolify.vps.example.com|100.64.0.25|false$" <<< "${a_records}"
    grep -q "^ws.coolify.vps.example.com|100.64.0.25|false$" <<< "${a_records}"
    grep -q "^\\*.vps.example.com|tunnel-1234.cfargotunnel.com$" <<< "${cname_records}"
    grep -q "^\\*.example.com|tunnel-1234.cfargotunnel.com$" <<< "${cname_records}"
  '
  assert_success
}
