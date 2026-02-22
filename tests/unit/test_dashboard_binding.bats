#!/usr/bin/env bats
# Unit tests for Coolify split-horizon dashboard binding functionality
# Tests --bind-dashboard-to-tailscale feature

load '../helpers'

setup() {
  source_script
}

# ── Input validation for dashboard binding ──────────────────────────────────────

@test "validate_inputs: accepts BIND_DASHBOARD_TO_TAILSCALE=true in dry-run" {
  ADMIN_USER="testadmin"
  ADMIN_PUBKEY="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeKeyForTesting test@example.com"
  BIND_DASHBOARD_TO_TAILSCALE="true"
  DRY_RUN="true"

  run validate_inputs
  assert_success
}

@test "validate_inputs: requires Coolify .env when BIND_DASHBOARD_TO_TAILSCALE=true (non-dry-run)" {
  ADMIN_USER="testadmin"
  ADMIN_PUBKEY="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeKeyForTesting test@example.com"
  BIND_DASHBOARD_TO_TAILSCALE="true"
  DRY_RUN="false"
  COOLIFY_ENV_FILE="/nonexistent/path/.env"

  run validate_inputs
  assert_failure
  assert_output --partial "Coolify .env not found"
}

# ── Tailscale IP detection for binding ──────────────────────────────────────────

@test "get_tailscale_ip: returns cached IP" {
  DETECTED_TAILSCALE_IP="100.64.1.42"

  run get_tailscale_ip
  assert_success
  assert_output "100.64.1.42"
}

# ── configure_coolify_binding dry-run ────────────────────────────────────────────

@test "configure_coolify_binding: skips when BIND_DASHBOARD_TO_TAILSCALE=false" {
  BIND_DASHBOARD_TO_TAILSCALE="false"

  run configure_coolify_binding
  assert_success
  refute_output --partial "split-horizon"
}

@test "configure_coolify_binding: dry-run shows planned changes" {
  BIND_DASHBOARD_TO_TAILSCALE="true"
  DETECTED_TAILSCALE_IP="100.64.1.42"
  DRY_RUN="true"

  run configure_coolify_binding
  assert_success
  assert_output --partial "DRY-RUN"
  assert_output --partial "APP_PORT"
  assert_output --partial "8000"
}

# ── Port binding validation ─────────────────────────────────────────────────────

@test "configure_coolify_binding: sets APP_PORT to Tailscale IP:8000" {
  BIND_DASHBOARD_TO_TAILSCALE="true"
  DETECTED_TAILSCALE_IP="100.64.1.42"
  DRY_RUN="true"

  run configure_coolify_binding
  assert_success
  assert_output --partial "100.64.1.42:8000"
}

@test "configure_coolify_binding: sets SOKETI_PORT to Tailscale IP:6001" {
  BIND_DASHBOARD_TO_TAILSCALE="true"
  DETECTED_TAILSCALE_IP="100.64.1.42"
  DRY_RUN="true"

  run configure_coolify_binding
  assert_success
  assert_output --partial "100.64.1.42:6001"
}

# ── Error handling ──────────────────────────────────────────────────────────────

@test "configure_coolify_binding: fails when Tailscale IP not detected" {
  BIND_DASHBOARD_TO_TAILSCALE="true"
  DETECTED_TAILSCALE_IP=""
  DRY_RUN="false"

  run configure_coolify_binding
  assert_failure
  assert_output --partial "Failed to detect Tailscale IP"
}

# ── State file tracking ─────────────────────────────────────────────────────────

@test "write_state: includes tailscale_ip when binding configured" {
  ADMIN_USER="testadmin"
  BIND_DASHBOARD_TO_TAILSCALE="true"
  DETECTED_TAILSCALE_IP="100.64.1.42"
  DRY_RUN="true"

  run write_state
  assert_success
  assert_output --partial "tailscale_ip"
}

@test "write_state: includes bind_dashboard_to_tailscale flag" {
  ADMIN_USER="testadmin"
  BIND_DASHBOARD_TO_TAILSCALE="true"
  DRY_RUN="true"

  run write_state
  assert_success
  assert_output --partial "bind_dashboard_to_tailscale=true"
}

# ── CIDR validation ─────────────────────────────────────────────────────────────

@test "TAILSCALE_CIDR: defaults to 100.64.0.0/10" {
  [[ "${TAILSCALE_CIDR:-100.64.0.0/10}" == "100.64.0.0/10" ]]
}

# ── Integration: full binding flow ──────────────────────────────────────────────

@test "validate_inputs: accepts all dashboard binding options together" {
  ADMIN_USER="testadmin"
  ADMIN_PUBKEY="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeKeyForTesting test@example.com"
  BIND_DASHBOARD_TO_TAILSCALE="true"
  INSTALL_TAILSCALE="true"
  TAILSCALE_AUTH_KEY="tskey-auth-fakekey123"
  DRY_RUN="true"
  SSH_PORT="22"
  ENABLE_AUTO_REBOOT="true"
  AUTO_REBOOT_TIME="03:30"
  JOURNAL_RETENTION="3month"
  SWAP_SIZE="2G"

  run validate_inputs
  assert_success
}
