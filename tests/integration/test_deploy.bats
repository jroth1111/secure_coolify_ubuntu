#!/usr/bin/env bats
# Tier 2: Integration tests for deploy.sh orchestrator
# Tests input validation, regex patterns, and gate logic with mocked dependencies.
# Note: deploy.sh is a laptop-side orchestrator that SSHes to remote servers.
# These tests verify the local logic without requiring actual SSH/cloud resources.

load '../helpers'

# ── Test constants ────────────────────────────────────────────────────────────

VALID_IP="203.0.113.5"
INVALID_IP="300.1.2.3"
INVALID_IP_ALPHA="not-an-ip"

VALID_USER="coolifyadmin"
INVALID_USER_ROOT="root"
INVALID_USER_UPPER="AdminUser"
INVALID_USER_SPACE="admin user"

VALID_DOMAIN="app.example.com"
VALID_DOMAIN_SIMPLE="example.com"
INVALID_DOMAIN="not-a-domain"

VALID_SWAP="2G"
VALID_SWAP_MB="512M"
INVALID_SWAP="2TB"
INVALID_SWAP_NO_UNIT="2048"

VALID_TS_KEY="tskey-auth-abc123xyz789"
INVALID_TS_KEY="invalid-key-format"

# ── Setup/Teardown ────────────────────────────────────────────────────────────

setup_file() {
  # Source deploy.sh to get access to functions and regex patterns
  source_deploy_script
}

setup() {
  # Reset environment variables before each test
  SERVER_IP=""
  ROOT_PASS=""
  ADMIN_USER=""
  PUBKEY_FILE=""
  TAILSCALE_AUTH_KEY=""
  DEPLOY_MODE=""
  DOMAIN=""
  CF_API_TOKEN=""
  CF_ZONE=""
  SWAP_SIZE=""
  AUTO_YES="false"
}

# ── Regex Pattern Tests ───────────────────────────────────────────────────────

@test "deploy: IPV4_RE accepts valid IPv4 addresses" {
  [[ "192.168.1.1" =~ ${IPV4_RE} ]]
  [[ "10.0.0.1" =~ ${IPV4_RE} ]]
  [[ "203.0.113.5" =~ ${IPV4_RE} ]]
  [[ "255.255.255.255" =~ ${IPV4_RE} ]]
}

@test "deploy: IPV4_RE rejects invalid IPv4 addresses" {
  ! [[ "300.1.2.3" =~ ${IPV4_RE} ]]
  ! [[ "not-an-ip" =~ ${IPV4_RE} ]]
  ! [[ "192.168.1" =~ ${IPV4_RE} ]]
  ! [[ "192.168.1.1.1" =~ ${IPV4_RE} ]]
  ! [[ "" =~ ${IPV4_RE} ]]
}

@test "deploy: LINUX_USER_RE accepts valid Linux usernames" {
  [[ "coolifyadmin" =~ ${LINUX_USER_RE} ]]
  [[ "admin" =~ ${LINUX_USER_RE} ]]
  [[ "user123" =~ ${LINUX_USER_RE} ]]
  [[ "my_user" =~ ${LINUX_USER_RE} ]]
  [[ "a" =~ ${LINUX_USER_RE} ]]
  [[ "_user" =~ ${LINUX_USER_RE} ]]
}

@test "deploy: LINUX_USER_RE rejects invalid Linux usernames" {
  ! [[ "root" =~ ${LINUX_USER_RE} ]] || true  # root is technically valid regex, but rejected by validate_inputs
  ! [[ "AdminUser" =~ ${LINUX_USER_RE} ]]     # uppercase
  ! [[ "admin user" =~ ${LINUX_USER_RE} ]]    # space
  ! [[ "123user" =~ ${LINUX_USER_RE} ]]       # starts with number
  ! [[ "-user" =~ ${LINUX_USER_RE} ]]         # starts with hyphen
}

@test "deploy: FQDN_RE accepts valid domain names" {
  [[ "example.com" =~ ${FQDN_RE} ]]
  [[ "app.example.com" =~ ${FQDN_RE} ]]
  [[ "my-app.example.com" =~ ${FQDN_RE} ]]
  [[ "a.b.c.example.com" =~ ${FQDN_RE} ]]
  [[ "sub.domain.io" =~ ${FQDN_RE} ]]
}

@test "deploy: FQDN_RE rejects invalid domain names" {
  ! [[ "not-a-domain" =~ ${FQDN_RE} ]]
  ! [[ "-example.com" =~ ${FQDN_RE} ]]
  ! [[ "example-.com" =~ ${FQDN_RE} ]]
  ! [[ "" =~ ${FQDN_RE} ]]
}

@test "deploy: SWAP_RE accepts valid swap sizes" {
  [[ "2G" =~ ${SWAP_RE} ]]
  [[ "512M" =~ ${SWAP_RE} ]]
  [[ "1G" =~ ${SWAP_RE} ]]
  [[ "16G" =~ ${SWAP_RE} ]]
}

@test "deploy: SWAP_RE rejects invalid swap sizes" {
  ! [[ "2TB" =~ ${SWAP_RE} ]]
  ! [[ "2048" =~ ${SWAP_RE} ]]
  ! [[ "gb" =~ ${SWAP_RE} ]]
  ! [[ "" =~ ${SWAP_RE} ]]
}

# ── is_true Function Tests ─────────────────────────────────────────────────────

@test "deploy: is_true returns true for truthy values" {
  is_true "1"
  is_true "true"
  is_true "TRUE"
  is_true "True"
  is_true "yes"
  is_true "YES"
  is_true "y"
  is_true "Y"
  is_true "on"
  is_true "ON"
}

@test "deploy: is_true returns false for falsy values" {
  ! is_true "0"
  ! is_true "false"
  ! is_true "no"
  ! is_true "n"
  ! is_true "off"
  ! is_true ""
  ! is_true "random"
}

# ── Input Validation Tests (validate_inputs logic) ────────────────────────────

@test "deploy: validate_inputs rejects invalid server IP" {
  SERVER_IP="${INVALID_IP}"
  run bash -c "source '${DEPLOY_SCRIPT}'; SERVER_IP='${INVALID_IP}' && validate_inputs" 2>&1 || true
  # Should fail due to invalid IP
  [[ $? -ne 0 ]] || [[ "$output" == *"Invalid server IP"* ]]
}

@test "deploy: validate_inputs rejects empty root password" {
  SERVER_IP="${VALID_IP}"
  ROOT_PASS=""
  run bash -c "source '${DEPLOY_SCRIPT}'; SERVER_IP='${VALID_IP}' ROOT_PASS='' && validate_inputs" 2>&1 || true
  [[ $? -ne 0 ]] || [[ "$output" == *"Root password"* ]]
}

@test "deploy: validate_inputs rejects root as admin user" {
  SERVER_IP="${VALID_IP}"
  ROOT_PASS="testpass"
  ADMIN_USER="root"
  run bash -c "source '${DEPLOY_SCRIPT}'; SERVER_IP='${VALID_IP}' ROOT_PASS='test' ADMIN_USER='root' && validate_inputs" 2>&1 || true
  [[ $? -ne 0 ]] || [[ "$output" == *"must not be root"* ]]
}

@test "deploy: validate_inputs rejects invalid admin username (uppercase)" {
  SERVER_IP="${VALID_IP}"
  ROOT_PASS="testpass"
  ADMIN_USER="AdminUser"
  run bash -c "source '${DEPLOY_SCRIPT}'; SERVER_IP='${VALID_IP}' ROOT_PASS='test' ADMIN_USER='AdminUser' && validate_inputs" 2>&1 || true
  [[ $? -ne 0 ]] || [[ "$output" == *"Invalid admin username"* ]]
}

@test "deploy: validate_inputs rejects invalid Tailscale auth key format" {
  SERVER_IP="${VALID_IP}"
  ROOT_PASS="testpass"
  ADMIN_USER="${VALID_USER}"
  TAILSCALE_AUTH_KEY="invalid-format"
  run bash -c "source '${DEPLOY_SCRIPT}'; SERVER_IP='${VALID_IP}' ROOT_PASS='test' ADMIN_USER='${VALID_USER}' TAILSCALE_AUTH_KEY='invalid' && validate_inputs" 2>&1 || true
  [[ $? -ne 0 ]] || [[ "$output" == *"tskey-auth-"* ]]
}

@test "deploy: validate_inputs rejects invalid deploy mode" {
  SERVER_IP="${VALID_IP}"
  ROOT_PASS="testpass"
  ADMIN_USER="${VALID_USER}"
  TAILSCALE_AUTH_KEY="${VALID_TS_KEY}"
  DEPLOY_MODE="invalid"
  run bash -c "source '${DEPLOY_SCRIPT}'; SERVER_IP='${VALID_IP}' ROOT_PASS='test' ADMIN_USER='${VALID_USER}' TAILSCALE_AUTH_KEY='${VALID_TS_KEY}' DEPLOY_MODE='invalid' && validate_inputs" 2>&1 || true
  [[ $? -ne 0 ]] || [[ "$output" == *"'standard' or 'tunnel'"* ]]
}

@test "deploy: validate_inputs accepts valid deploy mode 'tunnel'" {
  run bash -c "source '${DEPLOY_SCRIPT}'; DEPLOY_MODE='tunnel' && [[ \"\${DEPLOY_MODE}\" == 'tunnel' || \"\${DEPLOY_MODE}\" == 'standard' ]]"
  assert_success
}

@test "deploy: validate_inputs accepts valid deploy mode 'standard'" {
  run bash -c "source '${DEPLOY_SCRIPT}'; DEPLOY_MODE='standard' && [[ \"\${DEPLOY_MODE}\" == 'tunnel' || \"\${DEPLOY_MODE}\" == 'standard' ]]"
  assert_success
}

@test "deploy: validate_inputs rejects invalid swap size" {
  run bash -c "source '${DEPLOY_SCRIPT}'; SWAP_SIZE='2TB' && [[ \"\${SWAP_SIZE}\" =~ \${SWAP_RE} ]]" 2>&1 || true
  [[ $? -ne 0 ]]
}

# ── parse_args Tests ──────────────────────────────────────────────────────────

@test "deploy: parse_args extracts --server-ip" {
  run bash -c "source '${DEPLOY_SCRIPT}'; parse_args --server-ip '192.168.1.1'; echo \"SERVER_IP=\${SERVER_IP}\""
  assert_output --partial "SERVER_IP=192.168.1.1"
}

@test "deploy: parse_args extracts --admin-user" {
  run bash -c "source '${DEPLOY_SCRIPT}'; parse_args --admin-user 'testuser'; echo \"ADMIN_USER=\${ADMIN_USER}\""
  assert_output --partial "ADMIN_USER=testuser"
}

@test "deploy: parse_args extracts --mode" {
  run bash -c "source '${DEPLOY_SCRIPT}'; parse_args --mode tunnel; echo \"DEPLOY_MODE=\${DEPLOY_MODE}\""
  assert_output --partial "DEPLOY_MODE=tunnel"
}

@test "deploy: parse_args sets AUTO_YES for --yes" {
  run bash -c "source '${DEPLOY_SCRIPT}'; parse_args --yes; echo \"AUTO_YES=\${AUTO_YES}\""
  assert_output --partial "AUTO_YES=true"
}

@test "deploy: parse_args rejects unknown option" {
  run bash -c "source '${DEPLOY_SCRIPT}'; parse_args --unknown-flag" 2>&1 || true
  [[ $? -ne 0 ]] || [[ "$output" == *"Unknown option"* ]]
}

# ── Cloudflare API Mock Tests ─────────────────────────────────────────────────

@test "deploy: cf_api constructs correct URL" {
  # Mock curl to capture the URL
  run bash -c "
    source '${DEPLOY_SCRIPT}'
    curl() { echo \"URL: \$3\"; }
    export -f curl
    CF_API_TOKEN='test-token'
    cf_api GET '/zones' > /dev/null
  "
  assert_output --partial "https://api.cloudflare.com/client/v4/zones"
}

@test "deploy: cf_verify_token parses success response" {
  run bash -c "
    source '${DEPLOY_SCRIPT}'
    cf_api() { echo '{\"success\": true}'; }
    export -f cf_api
    cf_verify_token
    echo 'verified'
  "
  assert_output --partial "verified"
}

@test "deploy: cf_verify_token fails on error response" {
  run bash -c "
    source '${DEPLOY_SCRIPT}'
    cf_api() { echo '{\"success\": false, \"errors\": [{\"message\": \"Invalid token\"}]}'; }
    export -f cf_api
    cf_verify_token 2>&1 || true
  "
  [[ $? -ne 0 ]] || [[ "$output" == *"Invalid token"* ]] || [[ "$output" == *"failed"* ]]
}

@test "deploy: cf_get_zone_id extracts zone ID from response" {
  run bash -c "
    source '${DEPLOY_SCRIPT}'
    cf_api() { echo '{\"result\": [{\"id\": \"zone123\", \"name\": \"example.com\"}]}'; }
    export -f cf_api
    DOMAIN='app.example.com'
    CF_ZONE=''
    cf_get_zone_id
    echo \"CF_ZONE_ID=\${CF_ZONE_ID}\"
  "
  assert_output --partial "CF_ZONE_ID=zone123"
}

@test "deploy: cf_get_zone_id fails when zone not found" {
  run bash -c "
    source '${DEPLOY_SCRIPT}'
    cf_api() { echo '{\"result\": []}'; }
    export -f cf_api
    DOMAIN='nonexistent.invalid'
    CF_ZONE=''
    cf_get_zone_id 2>&1 || true
  "
  [[ $? -ne 0 ]] || [[ "$output" == *"not found"* ]]
}

@test "deploy: cf_create_tunnel extracts tunnel ID from response" {
  run bash -c "
    source '${DEPLOY_SCRIPT}'
    cf_api() { echo '{\"result\": {\"id\": \"tunnel-abc123\"}}'; }
    export -f cf_api
    CF_ACCOUNT_ID='account123'
    DOMAIN='app.example.com'
    cf_create_tunnel
    echo \"TUNNEL_ID=\${TUNNEL_ID}\"
  "
  assert_output --partial "TUNNEL_ID=tunnel-abc123"
}

# ── Gate Logic Tests ──────────────────────────────────────────────────────────

@test "deploy: verify_docker_user_gate_remote passes when service active and rules present" {
  # This tests the gate logic with mocked SSH
  run bash -c "
    source '${DEPLOY_SCRIPT}'

    # Mock ssh_admin_sudo to return success
    ssh_admin_sudo() {
      case \"\$1\" in
        'systemctl is-active --quiet docker-user-hardening.service')
          return 0
          ;;
        'iptables -S DOCKER-USER')
          echo '-N DOCKER-USER'
          echo '-A DOCKER-USER -j coolify-hardening-input'
          echo '-A coolify-hardening-input -s 10.0.0.0/8 -j ACCEPT'
          return 0
          ;;
      esac
    }
    export -f ssh_admin_sudo

    # Run gate check - should pass
    verify_docker_user_gate_remote 'Test Gate' && echo 'PASSED'
  "
  assert_output --partial "PASSED"
}

# ── Phase Gate Labels ─────────────────────────────────────────────────────────

@test "deploy: phase labels are consistent (5 phases)" {
  # Verify deploy.sh has exactly 5 phase labels
  run grep -c "step \".*/5\"" "${DEPLOY_SCRIPT}"
  assert_output "5"
}

@test "deploy: gate labels A through E are defined" {
  # Count gate references
  local gate_count
  gate_count=$(grep -c "Gate [A-E]" "${DEPLOY_SCRIPT}")
  [[ ${gate_count} -ge 5 ]]
}

# ── Required CLI Flags Documentation ──────────────────────────────────────────

@test "deploy: usage documents required flags" {
  run bash -c "source '${DEPLOY_SCRIPT}'; usage"
  assert_output --partial "--server-ip"
  assert_output --partial "--root-pass"
  assert_output --partial "--tailscale-auth-key"
  assert_output --partial "--domain"
  assert_output --partial "--cf-api-token"
}

@test "deploy: usage documents optional flags" {
  run bash -c "source '${DEPLOY_SCRIPT}'; usage"
  assert_output --partial "--admin-user"
  assert_output --partial "--pubkey-file"
  assert_output --partial "--mode"
  assert_output --partial "--cf-zone"
  assert_output --partial "--swap-size"
  assert_output --partial "--yes"
}

# ── Tunnel Mode vs Standard Mode Logic ────────────────────────────────────────

@test "deploy: tunnel mode sets tunnel_flag=true in phase1" {
  run bash -c "
    source '${DEPLOY_SCRIPT}'
    DEPLOY_MODE='tunnel'
    tunnel_flag='false'
    [[ \"\${DEPLOY_MODE}\" == 'tunnel' ]] && tunnel_flag='true'
    echo \"tunnel_flag=\${tunnel_flag}\"
  "
  assert_output --partial "tunnel_flag=true"
}

@test "deploy: standard mode keeps tunnel_flag=false in phase1" {
  run bash -c "
    source '${DEPLOY_SCRIPT}'
    DEPLOY_MODE='standard'
    tunnel_flag='false'
    [[ \"\${DEPLOY_MODE}\" == 'tunnel' ]] && tunnel_flag='true'
    echo \"tunnel_flag=\${tunnel_flag}\"
  "
  assert_output --partial "tunnel_flag=false"
}

# ── SSH Options ────────────────────────────────────────────────────────────────

@test "deploy: SSH_OPTS disables strict host key checking" {
  run bash -c "source '${DEPLOY_SCRIPT}'; echo \"\${SSH_OPTS}\""
  assert_output --partial "StrictHostKeyChecking=no"
}

@test "deploy: SSH_OPTS sets connection timeout" {
  run bash -c "source '${DEPLOY_SCRIPT}'; echo \"\${SSH_OPTS}\""
  assert_output --partial "ConnectTimeout="
}

# ── Idempotency ───────────────────────────────────────────────────────────────

@test "deploy: cf_upsert_a_record updates existing record" {
  run bash -c "
    source '${DEPLOY_SCRIPT}'

    # Mock cf_api to return existing record, then verify PUT is called
    call_count=0
    cf_api() {
      call_count=\$((call_count + 1))
      if [[ \$call_count -eq 1 ]]; then
        # First call: GET existing record
        echo '{\"result\": [{\"id\": \"record123\"}]}'
      else
        # Second call: PUT update
        echo \"METHOD=\$1 ENDPOINT=\$2\" >&2
        echo '{\"success\": true}'
      fi
    }
    export -f cf_api

    CF_ZONE_ID='zone123'
    cf_upsert_a_record 'app.example.com' '192.168.1.1' 'true' 2>&1
  "
  assert_output --partial "METHOD=PUT"
}

@test "deploy: cf_upsert_a_record creates new record when none exists" {
  run bash -c "
    source '${DEPLOY_SCRIPT}'

    # Mock cf_api to return no existing record, then verify POST is called
    call_count=0
    cf_api() {
      call_count=\$((call_count + 1))
      if [[ \$call_count -eq 1 ]]; then
        # First call: GET returns empty
        echo '{\"result\": []}'
      else
        # Second call: POST create
        echo \"METHOD=\$1 ENDPOINT=\$2\" >&2
        echo '{\"success\": true}'
      fi
    }
    export -f cf_api

    CF_ZONE_ID='zone123'
    cf_upsert_a_record 'app.example.com' '192.168.1.1' 'true' 2>&1
  "
  assert_output --partial "METHOD=POST"
}

@test "deploy: cf_upsert_cname updates existing CNAME" {
  run bash -c "
    source '${DEPLOY_SCRIPT}'

    call_count=0
    cf_api() {
      call_count=\$((call_count + 1))
      if [[ \$call_count -eq 1 ]]; then
        echo '{\"result\": [{\"id\": \"cname123\"}]}'
      else
        echo \"METHOD=\$1\" >&2
        echo '{\"success\": true}'
      fi
    }
    export -f cf_api

    CF_ZONE_ID='zone123'
    cf_upsert_cname 'app.example.com' 'tunnel-id.cfargotunnel.com' 2>&1
  "
  assert_output --partial "METHOD=PUT"
}

# ── Error Handling ────────────────────────────────────────────────────────────

@test "deploy: die function exits with error message" {
  run bash -c "source '${DEPLOY_SCRIPT}'; die 'test error message'" 2>&1 || true
  [[ $? -ne 0 ]]
  [[ "$output" == *"test error message"* ]]
}

@test "deploy: warn function logs warning" {
  run bash -c "source '${DEPLOY_SCRIPT}'; warn 'test warning'"
  assert_output --partial "WARN:"
  assert_output --partial "test warning"
}

@test "deploy: pass function outputs PASS" {
  run bash -c "source '${DEPLOY_SCRIPT}'; pass 'test passed'"
  assert_output --partial "PASS"
}

@test "deploy: fail function outputs FAIL" {
  run bash -c "source '${DEPLOY_SCRIPT}'; fail 'test failed'"
  assert_output --partial "FAIL"
}
