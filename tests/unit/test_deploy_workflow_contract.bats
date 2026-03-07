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
    cf_verify_dns_write_token() { :; }
    cf_get_account_id() { :; }
    cf_verify_tunnel_token() { :; }
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
    SERVER_TIMEZONE="UTC"
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

@test "deploy: phase1 skipped marker exists for --ts-ip resumes" {
  run bash -c '
    source "'"${DEPLOY_SCRIPT}"'"
    TS_IP="100.64.0.25"
    phase1_skipped
  '
  assert_success
  assert_output --partial "1/5"
  assert_output --partial "skipped"
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
    SERVER_TIMEZONE="UTC"
    TAILSCALE_DIRECT_WAN="false"
    cmd_file="$(mktemp)"

    scp_root() { :; }
    ssh_root() {
      printf "%s\n" "$1" >> "${cmd_file}"
      if [[ "$1" == *"/root/bootstrap_hardening.sh"* && "$1" == *"/root/deploy.env"* && "$1" == *"--install-tailscale --force"* ]]; then
        echo "HARDEN_RESULT_TAILSCALE_IP=100.64.0.25"
      fi
      return 0
    }

    phase1_upload_harden
    grep -q -- "--env-file" "${cmd_file}"
    grep -q -- "--install-tailscale --force" "${cmd_file}"
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
    known_hosts_sync=0

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
      if [[ "$1" == "test -f /run/reboot-required" ]]; then
        return 1
      fi
      if [[ "$1" == "docker version >/dev/null 2>&1" ]]; then
        return 1
      fi
      if [[ "$1" == *"validate_hardening.sh --json"* ]]; then
        echo "{\"fail\":0,\"checks\":[]}"
      fi
      return 0
    }
    sync_operator_known_host_entries() { [[ "$2" == "100.64.0.25" ]]; known_hosts_sync=1; }
    reconcile_docker_daemon_remote() { :; }
    sync_companion_scripts() { sync_called=1; }
    report_validation_result() { :; }

    phase2_gates
    [[ "${attempts}" -eq 3 ]]
    [[ "${sync_called}" -eq 1 ]]
    [[ "${known_hosts_sync}" -eq 1 ]]
  '
  assert_success
}

@test "deploy: gate B.5 reboots before Gate C when reboot-required exists" {
  run bash -c '
    source "'"${DEPLOY_SCRIPT}"'"
    TS_IP="100.64.0.25"
    ADMIN_USER="coolifyadmin"
    echo_ok_calls=0
    reboot_check_calls=0
    reboot_cmd_seen=0

    sleep() { :; }
    ssh_admin() {
      if [[ "$1" == "echo ok" ]]; then
        echo_ok_calls=$((echo_ok_calls + 1))
        if (( echo_ok_calls == 2 )); then
          return 1
        fi
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
      if [[ "$1" == "test -f /run/reboot-required" ]]; then
        return 0
      fi
      if [[ "$1" == "tr '\''\\n'\'' '\'','\'' < /run/reboot-required.pkgs 2>/dev/null | sed '\''s/,$//'\''" ]]; then
        echo "linux-image"
        return 0
      fi
      if [[ "$1" == "nohup bash -c \"sleep 1; systemctl reboot\" >/dev/null 2>&1 &" ]]; then
        reboot_cmd_seen=1
        return 0
      fi
      if [[ "$1" == "test ! -f /run/reboot-required" ]]; then
        reboot_check_calls=$((reboot_check_calls + 1))
        (( reboot_check_calls >= 1 )) && return 0
        return 1
      fi
      if [[ "$1" == "systemctl is-active --quiet docker-user-hardening.service" ]]; then
        return 0
      fi
      if [[ "$1" == "iptables -S DOCKER-USER" ]]; then
        printf "%s\n" "-A DOCKER-USER -m comment --comment coolify-hardening-return -j RETURN"
        return 0
      fi
      if [[ "$1" == "docker version >/dev/null 2>&1" ]]; then
        return 1
      fi
      if [[ "$1" == *"validate_hardening.sh --json"* ]]; then
        echo "{\"fail\":0,\"checks\":[]}"
        return 0
      fi
      return 0
    }
    sync_companion_scripts() { :; }
    report_validation_result() { :; }

    phase2_gates
    [[ "${reboot_cmd_seen}" -eq 1 ]]
    [[ "${reboot_check_calls}" -eq 1 ]]
  '
  assert_success
  assert_output --partial "Gate B.5: Reboot completed and reboot-required cleared"
}

@test "deploy: --ts-ip resume rejects domain drift from phase1 state" {
  run bash -c '
    source "'"${DEPLOY_SCRIPT}"'"
    TS_IP="100.64.0.25"
    ADMIN_USER="coolifyadmin"
    DOMAIN="new.example.com"
    DEPLOY_MODE="tunnel"
    SKIP_HARDEN="true"

    sleep() { :; }
    ssh_admin() {
      case "$1" in
        "echo ok") echo ok; return 0 ;;
        "whoami") echo "${ADMIN_USER}"; return 0 ;;
        *) return 0 ;;
      esac
    }
    ssh_admin_sudo() {
      if [[ "$1" == "bash -ceu "* ]]; then
        printf "old.example.com\ttrue\n"
        return 0
      fi
      return 1
    }
    sync_operator_known_host_entries() { :; }
    report_validation_result() { :; }

    phase2_gates
  '
  assert_failure
  assert_output --partial "Resume contract failed: --domain new.example.com does not match phase 1 state (old.example.com)"
}

@test "deploy: --ts-ip resume rejects mode drift from phase1 state" {
  run bash -c '
    source "'"${DEPLOY_SCRIPT}"'"
    TS_IP="100.64.0.25"
    ADMIN_USER="coolifyadmin"
    DOMAIN="vps.example.com"
    DEPLOY_MODE="standard"
    SKIP_HARDEN="true"

    sleep() { :; }
    ssh_admin() {
      case "$1" in
        "echo ok") echo ok; return 0 ;;
        "whoami") echo "${ADMIN_USER}"; return 0 ;;
        *) return 0 ;;
      esac
    }
    ssh_admin_sudo() {
      if [[ "$1" == "bash -ceu "* ]]; then
        printf "vps.example.com\ttrue\n"
        return 0
      fi
      return 1
    }
    sync_operator_known_host_entries() { :; }
    report_validation_result() { :; }

    phase2_gates
  '
  assert_failure
  assert_output --partial "Resume contract failed: --mode standard does not match phase 1 state (tunnel)"
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
      if [[ "$1" == "test -f /run/reboot-required" ]]; then
        return 1
      fi
      if [[ "$1" == "docker version >/dev/null 2>&1" ]]; then
        return 1
      fi
      if [[ "$1" == *"validate_hardening.sh --json"* ]]; then
        printf "seen\n" > "${validate_seen_file}"
        echo "{\"fail\":0,\"checks\":[]}"
        return 0
      fi
      return 1
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

@test "deploy: gate C waits for timesync before validation" {
  run bash -c '
    source "'"${DEPLOY_SCRIPT}"'"
    TS_IP="100.64.0.25"
    ADMIN_USER="coolifyadmin"
    timesync_file="$(mktemp)"
    echo 0 > "${timesync_file}"
    validate_file="$(mktemp)"
    echo 0 > "${validate_file}"

    sleep() { :; }
    ssh_admin() {
      [[ "$1" == "echo ok" ]] && { echo ok; return 0; }
      [[ "$1" == "whoami" ]] && { echo "${ADMIN_USER}"; return 0; }
      return 0
    }
    ssh_admin_sudo() {
      if [[ "$1" == "test -f /run/reboot-required" ]]; then
        return 1
      fi
      if [[ "$1" == "docker version >/dev/null 2>&1" ]]; then
        return 1
      fi
      if [[ "$1" == "timedatectl show --property=NTPSynchronized --value 2>/dev/null || true" ]]; then
        attempt="$(cat "${timesync_file}")"
        attempt=$((attempt + 1))
        echo "${attempt}" > "${timesync_file}"
        if (( attempt < 2 )); then
          echo no
        else
          echo yes
        fi
        return 0
      fi
      if [[ "$1" == *"validate_hardening.sh --json"* ]]; then
        validate_calls="$(cat "${validate_file}")"
        validate_calls=$((validate_calls + 1))
        echo "${validate_calls}" > "${validate_file}"
        echo "{\"fail\":0,\"checks\":[]}"
        return 0
      fi
      return 0
    }
    sync_companion_scripts() { :; }
    report_validation_result() { :; }

    phase2_gates
    [[ "$(cat "${timesync_file}")" -eq 2 ]]
    [[ "$(cat "${validate_file}")" -eq 1 ]]
  '
  assert_success
  assert_output --partial "Gate C pre-check: waiting for system clock synchronization..."
  assert_output --partial "Gate C pre-check: timesync synchronized"
}

@test "deploy: wait_for_gate_c_timesync_remote waits for synchronized clock" {
  run bash -c '
    source "'"${DEPLOY_SCRIPT}"'"
    timesync_file="$(mktemp)"
    echo 0 > "${timesync_file}"

    sleep() { :; }
    ssh_admin_sudo() {
      if [[ "$1" == "timedatectl show --property=NTPSynchronized --value 2>/dev/null || true" ]]; then
        attempt="$(cat "${timesync_file}")"
        attempt=$((attempt + 1))
        echo "${attempt}" > "${timesync_file}"
        if (( attempt < 2 )); then
          echo no
        else
          echo yes
        fi
        return 0
      fi
      return 0
    }

    wait_for_gate_c_timesync_remote 3 1
    [[ "$(cat "${timesync_file}")" -eq 2 ]]
  '
  assert_success
  assert_output --partial "Gate C pre-check: waiting for system clock synchronization..."
  assert_output --partial "Gate C pre-check: timesync synchronized"
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
    coolify_reconcile_instance_settings_script() { echo "true"; }
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
    DEPLOY_MODE="tunnel"
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
    DEPLOY_MODE="tunnel"
    TS_IP="100.64.0.25"
    SERVER_IP="203.0.113.10"
    DOMAIN="coolify.vps.example.com"
    validate_seen_file="$(mktemp)"
    report_seen=0
    dns_assert_calls=0

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
      elif [[ "${url}" == "https://${DOMAIN}/api/v1/health" ]]; then
        echo "200"
      elif [[ "${url}" == "http://${SERVER_IP}" ]]; then
        echo "000"
      elif [[ "${url}" == "https://${SERVER_IP}" ]]; then
        echo "000"
      else
        echo "404"
      fi
      return 0
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
    cf_assert_private_tailscale_a_record() {
      [[ "$2" == "${TS_IP}" ]]
      dns_assert_calls=$((dns_assert_calls + 1))
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
    [[ "${dns_assert_calls}" -eq 2 ]]
  '
  assert_success
}

@test "deploy: wait_for_admin_ssh_or_die retries until ssh responds" {
  run bash -c '
    source "'"${DEPLOY_SCRIPT}"'"
    attempts=0
    sleep() { :; }
    ssh_admin() {
      if [[ "$1" == "echo ok" ]]; then
        attempts=$((attempts + 1))
        (( attempts < 3 )) && return 1
        echo ok
        return 0
      fi
      return 0
    }

    wait_for_admin_ssh_or_die "Gate A" 4 1
    [[ "${attempts}" -eq 3 ]]
  '
  assert_success
}

@test "deploy: gate_c_failures_are_transient only accepts timesync-only failures" {
  run bash -c '
    source "'"${DEPLOY_SCRIPT}"'"
    gate_c_failures_are_transient '\''{"checks":[{"check":"timesync: NTPSynchronized","status":"FAIL"}]}'\''
  '
  assert_success

  run bash -c '
    source "'"${DEPLOY_SCRIPT}"'"
    gate_c_failures_are_transient '\''{"checks":[{"check":"timesync: NTPSynchronized","status":"FAIL"},{"check":"ufw: active","status":"FAIL"}]}'\''
  '
  assert_failure
}
