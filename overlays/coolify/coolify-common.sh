#!/usr/bin/env bash
# overlays/coolify/coolify-common.sh — Coolify-overlay shared logic (cf_*, coolify_phase*_shared, heredoc generators).
# Source this file; do not execute it directly.
# Requires: set -Eeuo pipefail in the caller.

[[ "${BASH_SOURCE[0]}" != "${0}" ]] \
  || { printf 'Source this file, do not execute it.\n' >&2; exit 1; }
if [[ -z "${BASH_VERSINFO:-}" || "${BASH_VERSINFO[0]}" -lt 4 ]]; then
  printf 'Bash 4+ is required (found %s). On macOS use Homebrew bash and run via its absolute path.\n' "${BASH_VERSION:-unknown}" >&2
  return 1
fi
[[ -z "${_COOLIFY_COMMON_LOADED:-}" ]] || return 0
_COOLIFY_COMMON_LOADED=1

_dir="$(dirname "${BASH_SOURCE[0]}")"

# Generic helpers (log/warn/die, prompt_*, regex, RUN_REPORT_*, etc.) live in lib/common.sh.
# shellcheck source=../../lib/common.sh
# shellcheck disable=SC1091
source "${_dir}/../../lib/common.sh"

# ── Layer modules ─────────────────────────────────────────────────────────────
# shellcheck source=lib/cloudflare-api.sh
source "${_dir}/lib/cloudflare-api.sh"
# shellcheck source=modules/phase5-verify.sh
source "${_dir}/modules/phase5-verify.sh"
# shellcheck source=modules/install.sh
source "${_dir}/modules/install.sh"
# shellcheck source=modules/reconcile.sh
source "${_dir}/modules/reconcile.sh"
# shellcheck source=modules/private-tls.sh
source "${_dir}/modules/private-tls.sh"
# shellcheck source=modules/public-tls.sh
source "${_dir}/modules/public-tls.sh"
# shellcheck source=modules/server-config.sh
source "${_dir}/modules/server-config.sh"

# ── Shared deployment helpers ────────────────────────────────────────────────

# report_validation_result — Parse and report base/validate.sh JSON output.
# Caller captures JSON (via SSH or locally) and passes it in as the second argument.
# Usage: report_validation_result "Gate C" "${validate_json}" "Gate C failed. ..."
report_validation_result() {
  local label="$1" validate_json="$2" die_msg="$3"
  local fail_count
  fail_count="$(printf '%s' "${validate_json}" | jq -r '.fail // -1' 2>/dev/null || echo "-1")"
  if [[ "${fail_count}" == "0" ]]; then
    pass "${label}: base/validate.sh — 0 failures"
  else
    fail "${label}: base/validate.sh reported ${fail_count} failures"
    printf '%s\n' "${validate_json}" | jq '.checks[] | select(.status=="FAIL")' 2>/dev/null || true
    die "${die_msg}"
  fi
}

# coolify_phase3_docker_coolify_shared — Shared phase 3 orchestration used by
# deploy.sh and setup.sh. Transport-specific behavior is injected via callbacks.
# Callback signatures:
#   has_docker_fn()
#   install_docker_fn()
#   start_docker_user_fn()
#   verify_docker_user_fn <gate-label>
#   has_coolify_env_fn()
#   install_coolify_fn()
#   reconcile_docker_daemon_fn()
#   restart_docker_user_fn()
#   add_coolify_root_key_fn()
#   fix_host_docker_internal_fn()
#   sync_docker_ssh_cidrs_fn()
coolify_phase3_docker_coolify_shared() {
  local has_docker_fn="$1"
  local install_docker_fn="$2"
  local start_docker_user_fn="$3"
  local verify_docker_user_fn="$4"
  local has_coolify_env_fn="$5"
  local install_coolify_fn="$6"
  local reconcile_docker_daemon_fn="$7"
  local restart_docker_user_fn="$8"
  local add_coolify_root_key_fn="$9"
  local fix_host_docker_internal_fn="${10}"
  local sync_docker_ssh_cidrs_fn="${11}"

  step "3/5" "Install Docker & Coolify"

  # Install Docker (skip if already present).
  if "${has_docker_fn}"; then
    log "Docker already installed — skipping install."
  else
    log "Installing Docker via official apt repository..."
    run_with_heartbeat "Docker installation" "${install_docker_fn}" \
      || die "Docker installation failed."
    pass "Docker installed"
  fi
  pass "Docker present"

  # Start DOCKER-USER hardening service
  "${start_docker_user_fn}" || die "Failed to start docker-user-hardening.service"

  # Gate D: Verify DOCKER-USER rules
  "${verify_docker_user_fn}" "Gate D"

  # Install Coolify (skip if already installed). Probe with retries because
  # Docker may still be converging right after daemon reconciliation.
  local coolify_present="false"
  local coolify_probe_attempts=4
  local coolify_probe_delay=3
  local coolify_probe
  for (( coolify_probe=1; coolify_probe<=coolify_probe_attempts; coolify_probe++ )); do
    if "${has_coolify_env_fn}"; then
      coolify_present="true"
      break
    fi
    if (( coolify_probe < coolify_probe_attempts )); then
      log "Coolify presence check not ready; retrying in ${coolify_probe_delay}s (${coolify_probe}/${coolify_probe_attempts})..."
      sleep "${coolify_probe_delay}"
    fi
  done

  if [[ "${coolify_present}" == "true" ]]; then
    log "Coolify .env found — skipping install (already installed)."
    pass "Coolify already installed"
  else
    log "Installing Coolify (this may take a few minutes)..."
    run_with_heartbeat "Coolify installation" "${install_coolify_fn}" \
      || die "Coolify installation failed."
    pass "Coolify installed"
  fi

  # Coolify installer manages daemon.json; re-apply hardening settings while preserving its keys.
  "${reconcile_docker_daemon_fn}"

  # Docker restart can flush DOCKER-USER runtime rules; re-apply and verify.
  "${restart_docker_user_fn}" \
    || die "Failed to restart docker-user-hardening.service after Docker daemon reconciliation."
  "${verify_docker_user_fn}" "Gate D (post-Coolify)"

  # Add Coolify's generated SSH public key to root's authorized_keys.
  # Required for the Coolify "This Machine" onboarding: Coolify SSHes to localhost as root
  # using its own key. The hardening Match block allows key-only root login from
  # localhost (127.0.0.1), 172.16.0.0/12, and 10.0.0.0/8 (Docker pool); key must be present.
  log "Adding Coolify SSH key to root authorized_keys..."
  "${add_coolify_root_key_fn}" || die "Failed to reconcile root authorized_keys with Coolify key."
  pass "Coolify SSH key in root authorized_keys"

  # Fix host.docker.internal resolution on Linux Docker.
  # Docker on Linux doesn't resolve host-gateway to a real IP in all versions/configurations.
  # Patch Coolify's docker-compose.yml to use the actual coolify network gateway IP,
  # then recreate the container so the fix takes effect.
  log "Fixing host.docker.internal for Linux Docker..."
  run_with_heartbeat "host.docker.internal reconcile" "${fix_host_docker_internal_fn}" \
    || die "Failed to reconcile host.docker.internal in Coolify compose."
  pass "host.docker.internal patched in Coolify docker-compose"

  # Coolify may create new Docker bridge CIDRs (for example 10.0.0.0/24 and 10.0.1.0/24)
  # after bootstrap. Reconcile SSH/UFW bridge allowlists now so final validation does not
  # depend on waiting for the timer.
  log "Reconciling Docker bridge SSH CIDRs..."
  "${sync_docker_ssh_cidrs_fn}" || die "Failed to reconcile Docker bridge SSH CIDRs."
  pass "Docker bridge SSH CIDRs reconciled"
}

# coolify_phase4_binding_dns_shared — Shared phase 4 orchestration used by
# deploy.sh and setup.sh. Transport-specific behavior is injected via callbacks.
# Callback signatures:
#   coolify_env_exists_fn()
#   configure_binding_fn()
#   mark_binding_state_fn()
#   set_wildcard_domain_fn()
#   reconcile_instance_settings_fn()
#   reconcile_pusher_fn()
#   install_cloudflared_fn()
#   configure_cloudflared_fn()
#   stop_cloudflared_fn()
#   fetch_existing_tunnel_fn()   # optional; prints "id<TAB>secret" or nothing
#   configure_private_routes_fn()
#   configure_private_tls_fn()
#   remove_private_routes_fn()
#   restore_public_tls_fn()
coolify_phase4_binding_dns_shared() {
  local coolify_env_exists_fn="$1"
  local configure_binding_fn="$2"
  local mark_binding_state_fn="$3"
  local set_wildcard_domain_fn="$4"
  local reconcile_instance_settings_fn="$5"
  local reconcile_pusher_fn="$6"
  local install_cloudflared_fn="$7"
  local configure_cloudflared_fn="$8"
  local stop_cloudflared_fn="$9"
  local fetch_existing_tunnel_fn="${10}"
  local configure_private_routes_fn="${11}"
  local configure_private_tls_fn="${12}"
  local remove_private_routes_fn="${13}"
  local restore_public_tls_fn="${14}"

  step "4/5" "Configure dashboard binding & DNS"

  # Wait for Coolify to write its .env file before binding (installer is async)
  log "Waiting for Coolify to initialize /data/coolify/source/.env..."
  local coolify_wait=0 coolify_max=120
  until "${coolify_env_exists_fn}"; do
    (( coolify_wait += 5 ))
    if (( coolify_wait >= coolify_max )); then
      warn "Coolify .env not found after ${coolify_max}s — binding may fail; continuing."
      break
    fi
    sleep 5
  done

  log "Restricting Coolify dashboard access to Tailscale via UFW..."
  "${configure_binding_fn}" || die "configure_coolify_binding.sh failed. Fix binding errors before continuing."
  "${mark_binding_state_fn}" || die "Failed to persist bind_dashboard_to_tailscale=true in state."
  pass "Dashboard access restrictions configured"

  # Set Coolify wildcard domain directly in the database.
  # configure_coolify_binding.sh already waited up to 60s for port 8000 to bind,
  # which guarantees the s6 startup sequence (migrate→seed→init) has completed and
  # the server_settings row (server_id=0, the hardcoded Localhost server) exists.
  # The API PATCH /servers/{uuid} does not expose wildcard_domain, so we write
  # directly to PostgreSQL via docker exec on the coolify-db container.
  log "Setting Coolify wildcard domain to http://${APP_DOMAIN}..."
  "${set_wildcard_domain_fn}" || die "Failed to update wildcard domain in Coolify database"
  pass "Coolify wildcard domain: http://${APP_DOMAIN}"

  log "Reconciling Coolify instance settings..."
  "${reconcile_instance_settings_fn}" || die "Failed to reconcile Coolify instance settings"
  pass "Coolify instance settings reconciled"

  # Configure PUSHER_* for the selected mode.
  # Tunnel mode keeps realtime traffic on Tailscale; standard mode clears explicit overrides.
  log "Reconciling PUSHER env vars for ${DEPLOY_MODE} mode..."
  run_with_heartbeat "PUSHER env reconcile (${DEPLOY_MODE})" "${reconcile_pusher_fn}" \
    || die "Failed to reconcile PUSHER env vars"
  if [[ "${DEPLOY_MODE}" == "tunnel" ]]; then
    pass "PUSHER env vars configured: ws.${DOMAIN}:443 (https)"
  else
    pass "PUSHER env vars cleared for standard mode"
  fi

  if [[ "${DEPLOY_MODE}" == "standard" ]]; then
    log "Stopping cloudflared for standard mode..."
    "${stop_cloudflared_fn}" || die "Failed to stop cloudflared for standard mode."
    pass "cloudflared stopped for standard mode"

    # Standard mode must not keep tunnel-private dashboard routes.
    "${remove_private_routes_fn}" || die "Failed to remove private-only dashboard routes."
    pass "Private dashboard routes removed for standard mode"

    log "Restoring public dashboard HTTPS routes and Traefik resolver..."
    "${restore_public_tls_fn}" || die "Failed to restore public dashboard HTTPS routes for standard mode."
    pass "Public dashboard HTTPS routes restored for standard mode"

    # Standard mode: A records pointing to server public IP (proxied)
    log "Configuring DNS: A record ${DOMAIN} → ${SERVER_IP} (proxied)..."
    cf_upsert_a_record "${DOMAIN}" "${SERVER_IP}" "true"
    pass "DNS A record configured: ${DOMAIN} → ${SERVER_IP}"

    # Wildcard A records — always create both scopes so manually set domains at either level work
    local wildcard_name="*.${APP_DOMAIN}"
    log "Configuring DNS: wildcard A record ${wildcard_name} → ${SERVER_IP} (proxied)..."
    cf_upsert_a_record "${wildcard_name}" "${SERVER_IP}" "true"
    pass "DNS wildcard A record configured: ${wildcard_name} → ${SERVER_IP}"
    if [[ "${APP_DOMAIN}" != "${CF_ZONE_NAME}" ]]; then
      local apex_wildcard="*.${CF_ZONE_NAME}"
      cf_upsert_a_record "${apex_wildcard}" "${SERVER_IP}" "true"
      pass "DNS wildcard A record configured: ${apex_wildcard} → ${SERVER_IP}"
    fi
    return 0
  fi

  # Tunnel mode: create tunnel, install cloudflared, CNAME
  log "Creating Cloudflare Tunnel..."
  cf_create_tunnel "${stop_cloudflared_fn}" "${fetch_existing_tunnel_fn}"
  pass "Tunnel ready: ${TUNNEL_ID}"

  log "Installing cloudflared..."
  run_with_heartbeat "cloudflared install" "${install_cloudflared_fn}" \
    || die "Failed to install cloudflared"
  pass "cloudflared installed"

  run_with_heartbeat "cloudflared tunnel configure" "${configure_cloudflared_fn}" \
    || die "Failed to write cloudflared credentials/config or start service"
  local wc_summary="*.${APP_DOMAIN}"
  [[ "${APP_DOMAIN}" != "${CF_ZONE_NAME}" ]] && wc_summary+=" and *.${CF_ZONE_NAME}"
  pass "Tunnel credentials and config written (wildcards: ${wc_summary})"
  pass "cloudflared service running"

  # Private-only dashboard/realtime routes via Tailscale-only host records.
  "${configure_private_routes_fn}" || die "Failed to configure private-only dashboard routes."
  pass "Private dashboard/realtime routes configured for ${DOMAIN} and ws.${DOMAIN}"

  "${configure_private_tls_fn}" || die "Failed to configure trusted private TLS for dashboard/realtime routes."
  pass "Trusted private TLS configured for ${DOMAIN} and ws.${DOMAIN}"

  # Ensure exact host records converge to DNS-only Tailscale A records without
  # deleting matching A records on every rerun.
  cf_delete_conflicting_host_records "${DOMAIN}"
  cf_delete_conflicting_host_records "ws.${DOMAIN}"
  cf_upsert_a_record "${DOMAIN}" "${TS_IP}" "false"
  pass "DNS host A record configured: ${DOMAIN} → ${TS_IP} (DNS-only)"
  cf_upsert_a_record "ws.${DOMAIN}" "${TS_IP}" "false"
  pass "DNS host A record configured: ws.${DOMAIN} → ${TS_IP} (DNS-only)"

  # Create wildcard CNAME records for app routing through cloudflared/Traefik.
  local tunnel_target="${TUNNEL_ID}.cfargotunnel.com"
  cf_upsert_cname "*.${APP_DOMAIN}" "${tunnel_target}"
  pass "DNS wildcard CNAME configured: *.${APP_DOMAIN} → ${tunnel_target}"
  if [[ "${APP_DOMAIN}" != "${CF_ZONE_NAME}" ]]; then
    cf_upsert_cname "*.${CF_ZONE_NAME}" "${tunnel_target}"
    pass "DNS wildcard CNAME configured: *.${CF_ZONE_NAME} → ${tunnel_target}"
  fi
}

# collect_common_inputs — Prompt for inputs shared by both deploy.sh and setup.sh.
# Each script calls this then adds its own script-specific prompts.
collect_common_inputs() {
  load_private_tls_ca_secrets_from_files
  load_cloudflare_tokens_from_files
  [[ -n "${SERVER_IP}" ]]   || prompt_value  SERVER_IP "Server public IP" "" "${IPV4_RE}"
  [[ -n "${ADMIN_USER}" ]]  || prompt_value  ADMIN_USER "Admin username" "coolifyadmin" "${LINUX_USER_RE}"
  [[ -n "${PUBKEY_FILE}" ]] || prompt_value  PUBKEY_FILE "SSH public key file" "${HOME}/.ssh/id_ed25519.pub"
  [[ -n "${TAILSCALE_AUTH_KEY}" ]] || prompt_value TAILSCALE_AUTH_KEY "Tailscale auth key (tskey-auth-...)" ""
  [[ -n "${DEPLOY_MODE}" ]] || prompt_choice DEPLOY_MODE "Deployment mode" "tunnel" "tunnel" "standard"
  [[ -n "${DOMAIN}" ]]      || prompt_value  DOMAIN "Domain name (FQDN)" "" "${FQDN_RE}"
  if [[ -z "${CF_API_TOKEN:-}" ]]; then
    if is_true "${AUTO_YES}"; then
      die "Cloudflare API token is required in non-interactive mode. Set CF_API_TOKEN or use --cf-api-token-file."
    fi
    prompt_secret CF_API_TOKEN "Cloudflare API token"
  fi
  # CF_ZONE intentionally left as-is (derived from domain when empty; --cf-zone overrides)
  [[ -n "${SWAP_SIZE}" ]]   || SWAP_SIZE="2G"
  if [[ -z "${SERVER_TIMEZONE:-}" ]]; then
    if is_true "${AUTO_YES}"; then
      die "Server timezone is required in non-interactive mode. Set SERVER_TIMEZONE or use --server-timezone."
    fi
    prompt_value SERVER_TIMEZONE "Server timezone (IANA, e.g. Australia/Melbourne)" "UTC" "${TIMEZONE_RE}"
  fi
  # App subdomain scope: where Coolify auto-assigns app URLs.
  #   apex → appname.CF_ZONE     e.g. appname.example.com      (default — Free Universal SSL)
  #   vps  → appname.DOMAIN      e.g. appname.vps.example.com  (server-scoped; needs ACM/Enterprise for proxied SSL)
  if [[ -z "${APP_DOMAIN_MODE}" ]]; then
    printf '  App subdomain scope:\n'
    printf '    apex → appname.ZONE_APEX                (default — works with Cloudflare Free SSL)\n'
    printf '    vps  → appname.%s  (scoped to this server; requires paid ACM or Enterprise for proxied SSL)\n' "${DOMAIN:-DOMAIN}"
    prompt_choice APP_DOMAIN_MODE "App subdomain scope" "apex" "apex" "vps"
  fi
  if [[ "${DEPLOY_MODE}" == "tunnel" && -z "${PRIVATE_TLS_CA:-}" ]]; then
    prompt_choice PRIVATE_TLS_CA "Private TLS CA" "letsencrypt" "letsencrypt" "zerossl"
  fi
  if [[ "${DEPLOY_MODE}" == "tunnel" && "${PRIVATE_TLS_CA:-letsencrypt}" == "zerossl" ]]; then
    [[ -n "${ZEROSSL_EAB_KID:-}" ]] || prompt_secret ZEROSSL_EAB_KID "ZeroSSL EAB kid"
    [[ -n "${ZEROSSL_EAB_HMAC:-}" ]] || prompt_secret ZEROSSL_EAB_HMAC "ZeroSSL EAB hmac"
  fi
}

# resolve_app_domain — Set APP_DOMAIN from APP_DOMAIN_MODE after CF_ZONE_NAME is known.
# Call this after cf_get_zone_id.
resolve_app_domain() {
  if [[ "${APP_DOMAIN_MODE}" == "apex" ]]; then
    APP_DOMAIN="${CF_ZONE_NAME}"
  else
    APP_DOMAIN="${DOMAIN}"
    if [[ "${DOMAIN}" != "${CF_ZONE_NAME}" ]]; then
      warn "vps mode: DOMAIN (${DOMAIN}) is a subdomain of zone ${CF_ZONE_NAME}."
      warn "Apps at appname.${DOMAIN} are two levels deep and NOT covered by Cloudflare Free Universal SSL."
      warn "Use --app-domain-mode apex for free proxied SSL, or provision ACM / CF for SaaS manually."
    fi
  fi
  log "App subdomain scope: ${APP_DOMAIN_MODE} — new apps at appname.${APP_DOMAIN}"
}

print_private_tls_ca_notice() {
  [[ "${DEPLOY_MODE}" == "tunnel" ]] || return 0

  if [[ "${PRIVATE_TLS_CA:-letsencrypt}" == "zerossl" ]]; then
    warn "Private TLS fallback selected: ZeroSSL"
    warn "  This deployment will configure Traefik to use ZeroSSL instead of Let's Encrypt for ${DOMAIN} and ws.${DOMAIN}."
    warn "  Required secrets: ZeroSSL EAB kid + ZeroSSL EAB hmac."
    warn "  DNS prerequisite: if CAA records exist, they must authorize sectigo.com."
    warn "  Operational tradeoff: this adds provider-specific ACME/EAB configuration and should only be used when Let's Encrypt is unsuitable or temporarily blocked."
  fi
}

# print_deployment_summary — Print completion banner and next-steps block.
# Uses globals: SERVER_IP, TS_IP, ADMIN_USER, DEPLOY_MODE, DOMAIN, CF_ZONE_NAME, APP_DOMAIN, TUNNEL_ID, SERVER_TIMEZONE
summary_box_print_prefixed_text() {
  local first_prefix="$1" continuation_prefix="$2" text="$3"
  local width=59 prefix available chunk
  prefix="${first_prefix}"

  while :; do
    available=$(( width - ${#prefix} ))
    if (( ${#text} <= available )); then
      printf '│ %s%-*s│\n' "${prefix}" "${available}" "${text}"
      return 0
    fi

    chunk="${text:0:available}"
    if [[ "${chunk}" == *" "* && "${text:available:1}" != " " ]]; then
      chunk="${chunk% *}"
    fi
    [[ -n "${chunk}" ]] || chunk="${text:0:available}"

    printf '│ %s%-*s│\n' "${prefix}" "${available}" "${chunk}"
    text="${text:${#chunk}}"
    text="${text## }"
    prefix="${continuation_prefix}"
  done
}

summary_box_print_field() {
  local label="$1" value="$2" prefix
  printf -v prefix '  %-16s: ' "${label}"
  summary_box_print_prefixed_text "${prefix}" "                    " "${value}"
}

summary_box_print_continuation() {
  summary_box_print_prefixed_text "                    " "                    " "$1"
}

print_deployment_summary() {
  local dashboard_url
  if [[ "${DEPLOY_MODE}" == "tunnel" ]]; then
    dashboard_url="https://${DOMAIN}"
  else
    dashboard_url="http://${TS_IP}:8000"
  fi

  printf '\n'
  printf '┌─────────────────────────────────────────────────────────────┐\n'
  printf '│                    DEPLOYMENT COMPLETE                      │\n'
  printf '├─────────────────────────────────────────────────────────────┤\n'
  summary_box_print_field "Server Public IP" "${SERVER_IP}"
  summary_box_print_field "Tailscale IP" "${TS_IP}"
  summary_box_print_field "Admin User" "${ADMIN_USER}"
  summary_box_print_field "Deploy Mode" "${DEPLOY_MODE}"
  if [[ "${DEPLOY_MODE}" == "tunnel" ]]; then
    summary_box_print_field "Private TLS CA" "${PRIVATE_TLS_CA:-letsencrypt}"
  fi
  summary_box_print_field "Domain" "${DOMAIN}"
  summary_box_print_field "Server Timezone" "${SERVER_TIMEZONE}"
  summary_box_print_field "Dashboard URL" "${dashboard_url}"
  summary_box_print_field "SSH Access" "ssh ${ADMIN_USER}@${TS_IP}"
  printf '├─────────────────────────────────────────────────────────────┤\n'
  if [[ "${DEPLOY_MODE}" == "standard" ]]; then
    summary_box_print_field "DNS" "A ${DOMAIN} -> ${SERVER_IP}"
    summary_box_print_field "Wildcard DNS" "A *.${APP_DOMAIN}"
    [[ "${APP_DOMAIN}" != "${CF_ZONE_NAME}" ]] \
      && summary_box_print_continuation "+ A *.${CF_ZONE_NAME}"
  else
    summary_box_print_field "DNS" "A ${DOMAIN} -> ${TS_IP} (DNS-only)"
    summary_box_print_continuation "+ A ws.${DOMAIN} -> ${TS_IP} (DNS-only)"
    summary_box_print_field "Wildcard DNS" "CNAME *.${APP_DOMAIN}"
    [[ "${APP_DOMAIN}" != "${CF_ZONE_NAME}" ]] \
      && summary_box_print_continuation "+ CNAME *.${CF_ZONE_NAME}"
    summary_box_print_field "Tunnel ID" "${TUNNEL_ID}"
    summary_box_print_field "Public Dashboard" "blocked (Tailscale-only)"
    summary_box_print_field "Public WebSocket" "blocked (Tailscale-only)"
  fi
  printf '└─────────────────────────────────────────────────────────────┘\n'
  printf '\n'
  log "Next steps:"
  if [[ "${DEPLOY_MODE}" == "tunnel" ]]; then
    log "  1. Open https://${DOMAIN} and create your Coolify admin account."
  else
    log "  1. Open http://${TS_IP}:8000 and create your Coolify admin account."
  fi
  log ""
  if [[ "${DEPLOY_MODE}" == "tunnel" ]]; then
    log "  2. Private dashboard/websocket TLS is already configured for https://${DOMAIN} and wss://ws.${DOMAIN} using ${PRIVATE_TLS_CA:-letsencrypt}."
  else
    log "  2. Cloudflare SSL mode (one-time):"
    log "       Cloudflare dashboard > your zone > SSL/TLS > Overview > set to 'Full'"
    log "       (use Full Strict only if you manage strict-valid origin certs for all proxied hosts)"
  fi
  log ""
  log "  3. Start the proxy: Coolify UI > Servers > localhost > Proxy > Start Proxy"
  log "       (required for app subdomains to route through Traefik)"
  log ""
  log "  4. Wildcard Domain is already set to http://${APP_DOMAIN} (done automatically)."
  log "       New apps will get http://appname.${APP_DOMAIN}"
  log "       If an app already has a sslip.io URL: App > Settings > Domains > update it."
  log ""
  log "  5. For each app deployment behind the wildcard route:"
  log "       Use http:// for the app's Coolify domain entry; Cloudflare adds TLS at the edge."
  log "       Example: http://myapp.${APP_DOMAIN}"
  log ""
  log "  6. Deploy your first app — it gets a subdomain + Cloudflare SSL automatically."
}
