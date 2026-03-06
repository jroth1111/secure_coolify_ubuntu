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

@test "run_with_heartbeat: emits begin/end markers and preserves command output" {
  run bash -c '
    source "'"${COMMON_LIB}"'"
    HEARTBEAT_INTERVAL_SECONDS=20
    run_with_heartbeat "quick-step" bash -c "echo heartbeat-ok"
  '
  assert_success
  assert_output --partial "BEGIN: quick-step"
  assert_output --partial "END: quick-step"
  assert_output --partial "heartbeat-ok"
}

@test "run_with_heartbeat: propagates command failure with failed marker" {
  run bash -c '
    source "'"${COMMON_LIB}"'"
    HEARTBEAT_INTERVAL_SECONDS=20
    run_with_heartbeat "failing-step" bash -c "exit 7"
  '
  assert_failure
  assert_output --partial "FAILED: failing-step (exit=7"
}

@test "stream_command_output: writes capture file and streams output" {
  run bash -c '
    source "'"${COMMON_LIB}"'"
    capture="'"${BATS_TEST_TMPDIR}"'/capture.log"
    stream_command_output "${capture}" bash -c "echo stream-ok"
    [[ -f "${capture}" ]]
    grep -q "stream-ok" "${capture}"
  '
  assert_success
  assert_output --partial "stream-ok"
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

@test "run report internals and time helpers: step/gate bookkeeping is callable" {
  run bash -c '
    source "'"${COMMON_LIB}"'"
    RUN_REPORT_ACTIVE="true"
    RUN_REPORT_STEPS_JSON=""
    RUN_REPORT_GATES_JSON=""
    run_report_step_start "0/5" "Pre-flight checks"
    run_report_record_gate "pass" "Gate A: ok"
    run_report_close_current_step "pass" ""
    [[ "${RUN_REPORT_STEPS_JSON}" == *"\"id\":\"0/5\""* ]]
    [[ "${RUN_REPORT_GATES_JSON}" == *"\"gate\":\"Gate A\""* ]]
    utc_now >/dev/null
    local_tz_offset >/dev/null
    [[ "$(local_tz_offset)" =~ ^[+-][0-9]{2}:[0-9]{2}$ ]]
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

@test "read_secret_file and load_cloudflare_tokens_from_files: read secure token files" {
  run bash -c '
    source "'"${COMMON_LIB}"'"
    api_file="$(mktemp)"
    tunnel_file="$(mktemp)"
    printf "dns-token\n" > "${api_file}"
    printf "tunnel-token\n" > "${tunnel_file}"
    chmod 600 "${api_file}" "${tunnel_file}"
    read_secret_file "${api_file}" "Cloudflare API token" >/dev/null
    [[ "$(read_secret_file "${api_file}" "Cloudflare API token")" == "dns-token" ]]
    CF_API_TOKEN_FILE="${api_file}"
    CF_TUNNEL_API_TOKEN_FILE="${tunnel_file}"
    load_cloudflare_tokens_from_files
    [[ "${CF_API_TOKEN}" == "dns-token" ]]
    [[ "${CF_TUNNEL_API_TOKEN}" == "tunnel-token" ]]
    rm -f "${api_file}" "${tunnel_file}"
  '
  assert_success
}

@test "cf_expect_success: passes for success=true and fails for success=false" {
  run cf_expect_success "action" '{"success":true}'
  assert_success

  run cf_expect_success "action" '{"success":false,"errors":[{"message":"boom"}]}'
  assert_failure
  assert_output --partial "action failed"
}

@test "Cloudflare helper probes: tokened API wrapper and auth/validation checks" {
  run bash -c '
    source "'"${COMMON_LIB}"'"
    curl() { echo "{\"success\":true}"; }
    cf_api_with_token GET /zones "" token-123 >/dev/null
    resp="$(cf_api_with_token GET /zones "" token-123)"
    [[ "${resp}" == *"\"success\":true"* ]]
    cf_expect_probe_authorized_or_validation_error \
      "dns probe" "{\"success\":false,\"errors\":[{\"code\":9000,\"message\":\"bad payload\"}]}" "9000,1004"
    CF_ZONE_ID="zone-123"
    cf_api() { echo "{\"success\":false,\"errors\":[{\"code\":9000,\"message\":\"bad payload\"}]}"; }
    cf_expect_probe_authorized_or_validation_error() { return 0; }
    cf_verify_dns_write_token
  '
  assert_success
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
  assert_output --partial "coolify-private-dashboard-http:"
  assert_output --partial "coolify-private-dashboard-https:"
  assert_output --partial "main: \${DOMAIN}"
  assert_output --partial "- ws.\${DOMAIN}"
  assert_output --partial "coolify-private-realtime-http:"
  assert_output --partial "coolify-private-realtime-https:"
  assert_output --partial "coolify-private-terminal-http:"
  assert_output --partial "coolify-private-terminal-https:"
  assert_output --partial "tls: {}"
  assert_output --partial 'rule: "Host(`ws.${DOMAIN}`)"'
  assert_output --partial "http://coolify:8080"
  assert_output --partial "http://coolify-realtime:6001"
  assert_output --partial "http://coolify-realtime:6002"
  [[ "$(grep -Fc 'certResolver: ${PRIVATE_TLS_RESOLVER}' <<< "${output}")" -eq 1 ]]
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

@test "coolify_install_binding_guard_script: emits guard timer install and enable flow" {
  run coolify_install_binding_guard_script
  assert_success
  assert_output --partial "/usr/local/sbin/coolify-binding-guard.sh"
  assert_output --partial "delete_non_tailscale_rule_numbers() {"
  assert_output --partial 'ufw --force delete "${rule_number}"'
  assert_output --partial "coolify-binding-guard.timer"
  assert_output --partial "systemctl enable --now coolify-binding-guard.timer"
}

@test "coolify_tunnel_name: incorporates full domain and deterministic hash" {
  run bash -c '
    source "'"${COMMON_LIB}"'"
    DOMAIN="vps1.internal.example.org"
    coolify_tunnel_name >/dev/null
    name="$(coolify_tunnel_name)"
    printf "%s\n" "${name}"
    [[ "${#name}" -le 63 ]]
  '
  assert_success
  assert_regex '^coolify-vps1-internal-example-org-[0-9a-f]{12}$'
}

@test "coolify_http_code_is_success_or_redirect: accepts success and redirect codes only" {
  run bash -c '
    source "'"${COMMON_LIB}"'"
    coolify_http_code_is_success_or_redirect 200
    coolify_http_code_is_success_or_redirect 303
    ! coolify_http_code_is_success_or_redirect 404
  '
  assert_success
}

@test "coolify_dashboard_http_code_is_healthy: rejects auth-only and missing-route responses" {
  run bash -c '
    source "'"${COMMON_LIB}"'"
    coolify_dashboard_http_code_is_healthy 200
    coolify_dashboard_http_code_is_healthy 302
    ! coolify_dashboard_http_code_is_healthy 401
    ! coolify_dashboard_http_code_is_healthy 403
    ! coolify_dashboard_http_code_is_healthy 404
    ! coolify_dashboard_http_code_is_healthy 500
  '
  assert_success
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

@test "DNS record helpers: delete conflicting host records and validate private A records" {
  run bash -c '
    source "'"${COMMON_LIB}"'"
    CF_ZONE_ID="zone-123"
    cf_expect_success() { :; }
    deleted=""
    cf_api() {
      local method="$1" endpoint="$2"
      if [[ "${method}" == "DELETE" ]]; then
        deleted+="${endpoint}"$'\''\n'\''
        echo "{\"success\":true}"
        return 0
      fi
      if [[ "${method}" == "GET" && "${endpoint}" == *"dns_records?type=A"* ]]; then
        echo "{\"success\":true,\"result\":[{\"id\":\"a1\",\"content\":\"100.64.0.10\",\"proxied\":false}]}"
        return 0
      fi
      if [[ "${method}" == "GET" ]]; then
        echo "{\"success\":true,\"result\":[{\"id\":\"x1\"}]}"
        return 0
      fi
      echo "{\"success\":true}"
    }
    cf_delete_conflicting_host_records "app.example.com"
    cf_assert_private_tailscale_a_record "app.example.com" "100.64.0.10"
    grep -q '/zones/zone-123/dns_records/x1' <<< "${deleted}"
    ! grep -q '/zones/zone-123/dns_records/a1' <<< "${deleted}"
  '
  assert_success
}

@test "coolify_reconcile_pusher_env_script: emits PUSHER mode reconciliation script" {
  run coolify_reconcile_pusher_env_script
  assert_success
  assert_output --partial ': "${DOMAIN:?DOMAIN is required for tunnel mode}"'
  assert_output --partial 'PUSHER_HOST=ws.${DOMAIN}'
  assert_output --partial "PUSHER_PORT=443"
  assert_output --partial "PUSHER_SCHEME=https"
  assert_output --partial "install -m 0600"
}

@test "coolify_set_wildcard_domain_script: emits DB update with ON_ERROR_STOP" {
  run coolify_set_wildcard_domain_script
  assert_success
  assert_output --partial "DB_PASSWORD="
  assert_output --partial "SELECT COUNT(*) INTO targeted_rows FROM server_settings WHERE server_id = 0;"
  assert_output --partial "Unable to identify a unique Coolify server_settings row"
  assert_output --partial "ON_ERROR_STOP=1"
}

@test "coolify_reconcile_instance_settings_script: emits fqdn and registration reconciliation" {
  run coolify_reconcile_instance_settings_script
  assert_success
  assert_output --partial ': "${DOMAIN:?DOMAIN is required}"'
  assert_output --partial ': "${DEPLOY_MODE:?DEPLOY_MODE is required}"'
  assert_output --partial "is_registration_enabled = false"
  assert_output --partial 'if [[ "${DEPLOY_MODE}" == "tunnel" ]]; then'
  assert_output --partial "SELECT COUNT(*) INTO total_rows FROM instance_settings;"
  assert_output --partial "Expected exactly one instance_settings row"
  assert_output --partial "WHERE id = (SELECT id FROM instance_settings ORDER BY id LIMIT 1);"
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
    mark_binding_state_calls=0
    wildcard_calls=0
    instance_settings_calls=0
    pusher_calls=0
    configure_private_tls_calls=0
    configure_private_routes_calls=0
    remove_private_routes_calls=0
    a_records=""

    coolify_env_exists() { wait_checks=$((wait_checks + 1)); return 0; }
    configure_binding() { bind_calls=$((bind_calls + 1)); }
    mark_binding_state() { mark_binding_state_calls=$((mark_binding_state_calls + 1)); }
    set_wildcard_domain() { wildcard_calls=$((wildcard_calls + 1)); }
    reconcile_instance_settings() { instance_settings_calls=$((instance_settings_calls + 1)); }
    reconcile_pusher() { pusher_calls=$((pusher_calls + 1)); }
    install_cloudflared() { return 0; }
    configure_cloudflared() { return 0; }
    stop_cloudflared() { return 0; }
    configure_private_routes() { configure_private_routes_calls=$((configure_private_routes_calls + 1)); }
    configure_private_tls() { configure_private_tls_calls=$((configure_private_tls_calls + 1)); }
    remove_private_routes() { remove_private_routes_calls=$((remove_private_routes_calls + 1)); }
    cf_upsert_a_record() { a_records+="$1|$2|$3"$'"'"'\n'"'"'; }
    cf_create_tunnel() { echo "unexpected tunnel" >&2; return 1; }
    cf_upsert_cname() { echo "unexpected cname" >&2; return 1; }

    coolify_phase4_binding_dns_shared \
      coolify_env_exists configure_binding mark_binding_state set_wildcard_domain reconcile_instance_settings reconcile_pusher \
      install_cloudflared configure_cloudflared stop_cloudflared \
      configure_private_routes configure_private_tls remove_private_routes

    [[ "${wait_checks}" -eq 1 ]]
    [[ "${bind_calls}" -eq 1 ]]
    [[ "${mark_binding_state_calls}" -eq 1 ]]
    [[ "${wildcard_calls}" -eq 1 ]]
    [[ "${instance_settings_calls}" -eq 1 ]]
    [[ "${pusher_calls}" -eq 1 ]]
    [[ "${configure_private_tls_calls}" -eq 0 ]]
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
    mark_binding_state_calls=0
    wildcard_calls=0
    instance_settings_calls=0
    pusher_calls=0
    install_calls=0
    configure_calls=0
    stop_calls=0
    create_tunnel_calls=0
    configure_private_tls_calls=0
    configure_private_routes_calls=0
    remove_private_routes_calls=0
    conflicting_hosts=""
    a_records=""
    cname_records=""

    coolify_env_exists() { wait_checks=$((wait_checks + 1)); return 0; }
    configure_binding() { bind_calls=$((bind_calls + 1)); }
    mark_binding_state() { mark_binding_state_calls=$((mark_binding_state_calls + 1)); }
    set_wildcard_domain() { wildcard_calls=$((wildcard_calls + 1)); }
    reconcile_instance_settings() { instance_settings_calls=$((instance_settings_calls + 1)); }
    reconcile_pusher() { pusher_calls=$((pusher_calls + 1)); }
    install_cloudflared() { install_calls=$((install_calls + 1)); }
    configure_cloudflared() { configure_calls=$((configure_calls + 1)); }
    stop_cloudflared() { stop_calls=$((stop_calls + 1)); }
    configure_private_routes() { configure_private_routes_calls=$((configure_private_routes_calls + 1)); }
    configure_private_tls() { configure_private_tls_calls=$((configure_private_tls_calls + 1)); }
    remove_private_routes() { remove_private_routes_calls=$((remove_private_routes_calls + 1)); }
    cf_create_tunnel() { create_tunnel_calls=$((create_tunnel_calls + 1)); }
    cf_delete_conflicting_host_records() { conflicting_hosts+="$1"$'"'"'\n'"'"'; }
    cf_upsert_a_record() { a_records+="$1|$2|$3"$'"'"'\n'"'"'; }
    cf_upsert_cname() { cname_records+="$1|$2"$'"'"'\n'"'"'; }

    coolify_phase4_binding_dns_shared \
      coolify_env_exists configure_binding mark_binding_state set_wildcard_domain reconcile_instance_settings reconcile_pusher \
      install_cloudflared configure_cloudflared stop_cloudflared \
      configure_private_routes configure_private_tls remove_private_routes

    [[ "${wait_checks}" -eq 1 ]]
    [[ "${bind_calls}" -eq 1 ]]
    [[ "${mark_binding_state_calls}" -eq 1 ]]
    [[ "${wildcard_calls}" -eq 1 ]]
    [[ "${instance_settings_calls}" -eq 1 ]]
    [[ "${pusher_calls}" -eq 1 ]]
    [[ "${install_calls}" -eq 1 ]]
    [[ "${configure_calls}" -eq 1 ]]
    [[ "${create_tunnel_calls}" -eq 1 ]]
    [[ "${stop_calls}" -eq 0 ]]
    [[ "${configure_private_routes_calls}" -eq 1 ]]
    [[ "${configure_private_tls_calls}" -eq 1 ]]
    [[ "${remove_private_routes_calls}" -eq 0 ]]
    grep -q "^coolify.vps.example.com$" <<< "${conflicting_hosts}"
    grep -q "^ws.coolify.vps.example.com$" <<< "${conflicting_hosts}"
    grep -q "^coolify.vps.example.com|100.64.0.25|false$" <<< "${a_records}"
    grep -q "^ws.coolify.vps.example.com|100.64.0.25|false$" <<< "${a_records}"
    grep -q "^\\*.vps.example.com|tunnel-1234.cfargotunnel.com$" <<< "${cname_records}"
    grep -q "^\\*.example.com|tunnel-1234.cfargotunnel.com$" <<< "${cname_records}"
  '
  assert_success
}

@test "coolify_phase5_verify_shared: runs standard verification flow with callback fetcher" {
  run bash -c '
    source "'"${COMMON_LIB}"'"
    DEPLOY_MODE="standard"
    TS_IP="100.64.0.10"
    SERVER_IP="203.0.113.10"
    DOMAIN="vps.example.com"
    sleep() { :; }
    curl() { echo "200"; }
    coolify_phase5_fetch_pusher_app_key() { echo "pusher-key"; }
    coolify_phase5_probe_websocket_code() { echo "101"; }
    fetch_validate_json() { echo "{\"fail\":0,\"checks\":[]}"; }
    operator_confirm() { :; }
    print_deployment_summary() { :; }
    coolify_phase5_verify_shared fetch_validate_json operator operator_confirm
  '
  assert_success
}

@test "coolify_phase5_verify_shared: rejects auth-only dashboard HTTP codes on Tailscale" {
  run bash -c '
    source "'"${COMMON_LIB}"'"
    DEPLOY_MODE="standard"
    TS_IP="100.64.0.10"
    SERVER_IP="203.0.113.10"
    DOMAIN="vps.example.com"
    sleep() { :; }
    curl() {
      local url="${@: -1}"
      if [[ "${url}" == "http://${TS_IP}:8000" ]]; then
        echo "401"
      else
        echo "000"
      fi
    }
    coolify_phase5_fetch_pusher_app_key() { echo "pusher-key"; }
    coolify_phase5_probe_websocket_code() { echo "101"; }
    fetch_validate_json() { echo "{\"fail\":0,\"checks\":[]}"; }
    operator_confirm() { :; }
    print_deployment_summary() { :; }

    coolify_phase5_verify_shared fetch_validate_json operator operator_confirm
  '
  assert_failure
  assert_output --partial "Gate E failed: dashboard not reachable via Tailscale."
}

@test "coolify_phase5_verify_shared: tunnel mode fails when private WSS handshake is not 101" {
  run bash -c '
    source "'"${COMMON_LIB}"'"
    DEPLOY_MODE="tunnel"
    TS_IP="100.64.0.10"
    SERVER_IP="203.0.113.10"
    DOMAIN="vps.example.com"

    sleep() { :; }
    curl() {
      local url="${@: -1}"
      if [[ "${url}" == "http://${TS_IP}:8000" ]]; then
        echo "200"
      elif [[ "${url}" == "http://${SERVER_IP}:8000" ]]; then
        echo "000"
      elif [[ "${url}" == "http://${DOMAIN}" ]]; then
        echo "302"
      elif [[ "${url}" == "http://ws.${DOMAIN}" ]]; then
        echo "302"
      elif [[ "${url}" == "https://${DOMAIN}" ]]; then
        echo "200"
      elif [[ "${url}" == "http://${SERVER_IP}" ]]; then
        echo "000"
      elif [[ "${url}" == "https://${SERVER_IP}" ]]; then
        echo "000"
      else
        echo "404"
      fi
    }
    coolify_phase5_fetch_pusher_app_key() { echo "pusher-key"; }
    coolify_phase5_probe_websocket_code() {
      case "$1" in
        "ws://${TS_IP}:6001/"*) echo "101" ;;
        "ws://${SERVER_IP}:6001/"*) echo "000" ;;
        "wss://ws.${DOMAIN}/"*) echo "404" ;;
        *) echo "000" ;;
      esac
    }
    cf_assert_private_tailscale_a_record() { :; }
    fetch_validate_json() { echo "{\"fail\":0,\"checks\":[]}"; }
    print_deployment_summary() { :; }

    coolify_phase5_verify_shared fetch_validate_json external :
  '
  assert_failure
  assert_output --partial "Gate F: private dashboard HTTP redirects to HTTPS"
  assert_output --partial "Gate F: private websocket HTTP redirects to HTTPS"
  refute_output --partial "Gate F: private dashboard HTTP did not redirect to HTTPS"
  refute_output --partial "Gate F: private websocket HTTP did not redirect to HTTPS"
  assert_output --partial "Gate F: private websocket WSS handshake failed"
}

@test "coolify_phase5_verify_shared: tunnel mode accepts 303 private redirects" {
  run bash -c '
    source "'"${COMMON_LIB}"'"
    DEPLOY_MODE="tunnel"
    TS_IP="100.64.0.10"
    SERVER_IP="203.0.113.10"
    DOMAIN="vps.example.com"

    sleep() { :; }
    curl() {
      local url="${@: -1}"
      case "${url}" in
        "http://${TS_IP}:8000") echo "200" ;;
        "http://${SERVER_IP}:8000") echo "000" ;;
        "http://${DOMAIN}") echo "303" ;;
        "http://ws.${DOMAIN}") echo "303" ;;
        "https://${DOMAIN}") echo "200" ;;
        "http://${SERVER_IP}") echo "000" ;;
        "https://${SERVER_IP}") echo "000" ;;
        *) echo "404" ;;
      esac
    }
    coolify_phase5_fetch_pusher_app_key() { echo "pusher-key"; }
    coolify_phase5_probe_websocket_code() {
      case "$1" in
        "ws://${TS_IP}:6001/"*) echo "101" ;;
        "ws://${SERVER_IP}:6001/"*) echo "000" ;;
        "wss://ws.${DOMAIN}/"*) echo "101" ;;
        *) echo "000" ;;
      esac
    }
    cf_assert_private_tailscale_a_record() { :; }
    fetch_validate_json() { echo "{\"fail\":0,\"checks\":[]}"; }
    print_deployment_summary() { :; }

    coolify_phase5_verify_shared fetch_validate_json external :
  '
  assert_success
  assert_output --partial "Gate F: private dashboard HTTP redirects to HTTPS (http://vps.example.com → HTTP 303)"
  assert_output --partial "Gate F: private websocket HTTP redirects to HTTPS (http://ws.vps.example.com → HTTP 303)"
}

@test "print_deployment_summary: tunnel mode prefers private HTTPS guidance" {
  run bash -c '
    source "'"${COMMON_LIB}"'"
    DEPLOY_MODE="tunnel"
    DOMAIN="vps.example.com"
    APP_DOMAIN="example.com"
    CF_ZONE_NAME="example.com"
    SERVER_IP="203.0.113.10"
    TS_IP="100.64.0.10"
    ADMIN_USER="coolifyadmin"
    TUNNEL_ID="tunnel-1234"
    SERVER_TIMEZONE="UTC"
    log() { printf "%s\n" "$*"; }

    print_deployment_summary
  '
  assert_success
  assert_output --partial "Dashboard URL    : https://vps.example.com"
  assert_output --partial "Open https://vps.example.com and create your Coolify admin account."
  assert_output --partial "Private dashboard/websocket TLS is already configured for https://vps.example.com and wss://ws.vps.example.com."
  refute_output --partial "fallback http://100.64.0.10:8000"
  refute_output --partial "Cloudflare SSL mode"
}

@test "coolify_mark_bind_dashboard_state_script: emits state reconciliation for bind flag" {
  run coolify_mark_bind_dashboard_state_script
  assert_success
  assert_output --partial "bind_dashboard_to_tailscale=true"
  assert_output --partial 'install -m 0640'
}

@test "coolify_phase5_fetch_pusher_app_key: returns the last non-empty PUSHER_APP_KEY" {
  run bash -c '
    source "'"${COMMON_LIB}"'"
    ssh_admin_sudo() {
      cat <<EOF
APP_ENV=production

PUSHER_APP_KEY=old-key
PUSHER_APP_KEY=new-key
EOF
    }
    coolify_phase5_fetch_pusher_app_key
  '
  assert_success
  assert_output "new-key"
}

@test "coolify_phase5_websocket_url: builds the expected websocket endpoint" {
  run coolify_phase5_websocket_url "wss://ws.example.com" "pusher-key"
  assert_success
  assert_output "wss://ws.example.com/app/pusher-key?protocol=7&client=js&version=8.4.0&flash=false"
}

@test "coolify_phase5_probe_websocket_code: returns 000 for invalid websocket schemes" {
  run coolify_phase5_probe_websocket_code "https://ws.example.com" 1
  assert_success
  assert_output "000"
}

@test "coolify_configure_private_tls_dns_script: emits private TLS DNS-01 reconciliation" {
  run coolify_configure_private_tls_dns_script
  assert_success
  assert_output --partial "CF_DNS_API_TOKEN is required"
  assert_output --partial "/data/coolify/proxy/.env"
  assert_output --partial "certificatesResolvers.${PRIVATE_TLS_RESOLVER}.acme.dnsChallenge.provider=cloudflare"
  assert_output --partial "reconcile_private_tls_compose() {"
  assert_output --partial 'service_match = re.search(r"(?ms)^  traefik:\n(?P<body>(?:    .*\n|\n)*)", text)'
  assert_output --partial "Traefik service block not found in docker-compose.yml"
  assert_output --partial 'default_redirect_file="${dynamic_dir}/default_redirect_503.yaml"'
  assert_output --partial 'coolify_dynamic_file="${dynamic_dir}/coolify.yaml"'
  assert_output --partial 'scrub_default_redirect_public_resolver() {'
  assert_output --partial 'scrub_coolify_public_https_routers() {'
  assert_output --partial 'for router_name in ("coolify-https", "coolify-realtime-wss", "coolify-terminal-wss"):'
  assert_output --partial 'text = text.replace("      tls:\n        certResolver: letsencrypt\n", "")'
  assert_output --partial 'for _ in $(seq 1 30); do'
  assert_output --partial 'Public Coolify HTTPS routers remained in ${coolify_dynamic_file}'
  assert_output --partial 'Public letsencrypt resolver remained in ${default_redirect_file}'
  assert_output --partial "--api.insecure=false"
}
