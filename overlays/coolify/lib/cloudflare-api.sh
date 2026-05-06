#!/usr/bin/env bash
# overlays/coolify/lib/cloudflare-api.sh — Cloudflare API helpers and TLS/token secret loaders.
# Sourced by coolify-common.sh; do not execute directly.

[[ "${BASH_SOURCE[0]}" != "${0}" ]] \
  || { printf 'Source this file, do not execute it.\n' >&2; exit 1; }

load_private_tls_ca_secrets_from_files() {
  if [[ -n "${ZEROSSL_EAB_KID_FILE:-}" ]]; then
    ZEROSSL_EAB_KID="$(read_secret_file "${ZEROSSL_EAB_KID_FILE}" "ZeroSSL EAB kid")"
  fi
  if [[ -n "${ZEROSSL_EAB_HMAC_FILE:-}" ]]; then
    ZEROSSL_EAB_HMAC="$(read_secret_file "${ZEROSSL_EAB_HMAC_FILE}" "ZeroSSL EAB hmac")"
  fi
}

load_cloudflare_tokens_from_files() {
  if [[ -n "${CF_API_TOKEN_FILE:-}" ]]; then
    CF_API_TOKEN="$(read_secret_file "${CF_API_TOKEN_FILE}" "Cloudflare API token")"
  fi
  if [[ -n "${CF_TUNNEL_API_TOKEN_FILE:-}" ]]; then
    CF_TUNNEL_API_TOKEN="$(read_secret_file "${CF_TUNNEL_API_TOKEN_FILE}" "Cloudflare tunnel API token")"
  fi
}

finalize_cloudflare_tokens() {
  CF_API_TOKEN="${CF_API_TOKEN:-}"
  CF_TUNNEL_API_TOKEN="${CF_TUNNEL_API_TOKEN:-}"
  CF_API_TOKEN="${CF_API_TOKEN%$'\n'}"
  CF_API_TOKEN="${CF_API_TOKEN%$'\r'}"
  CF_TUNNEL_API_TOKEN="${CF_TUNNEL_API_TOKEN%$'\n'}"
  CF_TUNNEL_API_TOKEN="${CF_TUNNEL_API_TOKEN%$'\r'}"

  # Single-token mode: if no dedicated tunnel token is provided, reuse CF_API_TOKEN.
  if [[ -z "${CF_TUNNEL_API_TOKEN:-}" && -n "${CF_API_TOKEN:-}" ]]; then
    CF_TUNNEL_API_TOKEN="${CF_API_TOKEN}"
  fi
}

finalize_private_tls_ca_inputs() {
  PRIVATE_TLS_CA="${PRIVATE_TLS_CA:-letsencrypt}"
  PRIVATE_TLS_CA="${PRIVATE_TLS_CA%$'\n'}"
  PRIVATE_TLS_CA="${PRIVATE_TLS_CA%$'\r'}"
  ZEROSSL_EAB_KID="${ZEROSSL_EAB_KID:-}"
  ZEROSSL_EAB_HMAC="${ZEROSSL_EAB_HMAC:-}"
  ZEROSSL_EAB_KID="${ZEROSSL_EAB_KID%$'\n'}"
  ZEROSSL_EAB_KID="${ZEROSSL_EAB_KID%$'\r'}"
  ZEROSSL_EAB_HMAC="${ZEROSSL_EAB_HMAC%$'\n'}"
  ZEROSSL_EAB_HMAC="${ZEROSSL_EAB_HMAC%$'\r'}"
}

private_tls_resolver_name() {
  printf 'privatedns'
}

private_tls_ca_expected_caa_issuer() {
  case "${PRIVATE_TLS_CA:-letsencrypt}" in
    letsencrypt) printf 'letsencrypt.org' ;;
    zerossl) printf 'sectigo.com' ;;
    *) return 1 ;;
  esac
}

cf_verify_private_tls_ca_caa() {
  [[ "${DEPLOY_MODE}" == "tunnel" ]] || return 0

  local expected_issuer
  expected_issuer="$(private_tls_ca_expected_caa_issuer)" || die "Unsupported private TLS CA: ${PRIVATE_TLS_CA}"

  local host_name response line found_any="false" authorized="false"
  local names=("${DOMAIN}")
  if [[ "${DOMAIN}" != "${CF_ZONE_NAME}" ]]; then
    names+=("${CF_ZONE_NAME}")
  fi

  for host_name in "${names[@]}"; do
    response="$(cf_api GET "/zones/${CF_ZONE_ID}/dns_records?type=CAA&name=${host_name}")"
    cf_expect_success "Cloudflare CAA lookup (${host_name})" "${response}"
    while IFS= read -r line; do
      [[ -n "${line}" ]] || continue
      found_any="true"
      if grep -Fqi -- "${expected_issuer}" <<< "${line}"; then
        authorized="true"
      fi
    done < <(
      printf '%s' "${response}" \
        | jq -r '.result[]? | [.name, (.data.tag // ""), (.data.value // .content // "")] | @tsv'
    )
  done

  if [[ "${found_any}" != "true" ]]; then
    log "Cloudflare CAA preflight: no CAA records found for ${DOMAIN} or ${CF_ZONE_NAME}; ${PRIVATE_TLS_CA} may issue."
    return 0
  fi

  if [[ "${authorized}" == "true" ]]; then
    log "Cloudflare CAA preflight: ${PRIVATE_TLS_CA} issuer ${expected_issuer} is authorized."
    return 0
  fi

  die "Cloudflare CAA preflight failed: found CAA records for ${DOMAIN}/${CF_ZONE_NAME}, but none authorize ${expected_issuer} for private TLS CA ${PRIVATE_TLS_CA}."
}

# ── Cloudflare API ─────────────────────────────────────────────────────────

cf_api_with_token() {
  local method="$1" endpoint="$2" body="${3:-}" token="${4:-}"
  local url="https://api.cloudflare.com/client/v4${endpoint}"
  local args=(-s -X "${method}" -H "Content-Type: application/json")
  [[ -n "${body}" ]] && args+=(-d "${body}")
  [[ -n "${token}" ]] || die "Cloudflare API token is empty for ${method} ${endpoint}"
  # Use a secure temp file instead of pipe to avoid race condition
  # where the token could be read by other processes
  local curl_config
  curl_config="$(mktemp)" || die "Failed to create temp file for curl config"
  printf -- '-H "Authorization: Bearer %s"\n' "${token}" > "${curl_config}"
  chmod 600 "${curl_config}"
  local resp ec
  if ! resp="$(curl --config "${curl_config}" "${args[@]}" "${url}")"; then
    ec=$?
    rm -f "${curl_config}"
    return "${ec}"
  fi
  rm -f "${curl_config}"
  printf '%s' "${resp}"
}

cf_api() {
  cf_api_with_token "$1" "$2" "${3-}" "${CF_API_TOKEN:-}"
}

cf_tunnel_api() {
  local token="${CF_TUNNEL_API_TOKEN:-${CF_API_TOKEN:-}}"
  cf_api_with_token "$1" "$2" "${3-}" "${token}"
}

cf_verify_token() {
  # Use zones endpoint rather than /user/tokens/verify — the latter requires
  # User:User Tokens:Read which is not part of our required token permissions.
  local resp
  resp="$(cf_api GET /zones?per_page=1)"
  local status err code
  status="$(printf '%s' "${resp}" | jq -r '.success // false')"
  if [[ "${status}" != "true" ]]; then
    err="$(printf '%s' "${resp}" | jq -r '.errors[0].message // "unknown"')"
    code="$(printf '%s' "${resp}" | jq -r '.errors[0].code // empty')"
    [[ -n "${code}" ]] && err="${err} (code ${code})"
    die "Cloudflare API token verification failed: ${err}. Ask the user for a token with Zone DNS permissions."
  fi
  log "Cloudflare API token verified."
}

cf_get_zone_id() {
  # Explicit zone ID override (operator already knows the exact zone).
  if [[ -n "${CF_ZONE_ID:-}" ]]; then
    [[ "${CF_ZONE_ID}" =~ ${CF_ID_RE} ]] || die "Invalid --cf-zone-id value: ${CF_ZONE_ID}"
    local zone_resp zone_ok zone_name
    zone_resp="$(cf_api GET "/zones/${CF_ZONE_ID}")"
    zone_ok="$(printf '%s' "${zone_resp}" | jq -r '.success // false')"
    [[ "${zone_ok}" == "true" ]] || die "Cloudflare zone ID lookup failed for '${CF_ZONE_ID}': $(printf '%s' "${zone_resp}" | jq -r '.errors[0].message // "unknown"')"
    zone_name="$(printf '%s' "${zone_resp}" | jq -r '.result.name // empty')"
    [[ -n "${zone_name}" ]] || die "Cloudflare zone name missing for zone ID '${CF_ZONE_ID}'"
    if [[ -n "${CF_ZONE:-}" && "${CF_ZONE}" != "${zone_name}" ]]; then
      die "--cf-zone (${CF_ZONE}) and --cf-zone-id (${CF_ZONE_ID} => ${zone_name}) do not match."
    fi
    CF_ZONE_NAME="${zone_name}"
    CF_ZONE="${zone_name}"
    log "Cloudflare zone ID override: ${CF_ZONE_ID} (${CF_ZONE_NAME})"
    return 0
  fi

  # If --cf-zone was specified, use it directly
  if [[ -n "${CF_ZONE}" ]]; then
    local resp
    resp="$(cf_api GET "/zones?name=${CF_ZONE}&status=active")"
    CF_ZONE_ID="$(printf '%s' "${resp}" | jq -r '.result[0].id // empty')"
    [[ -n "${CF_ZONE_ID}" ]] || die "Cloudflare zone not found for '${CF_ZONE}'. Check --cf-zone value."
    CF_ZONE_NAME="${CF_ZONE}"
    log "Cloudflare zone ID: ${CF_ZONE_ID} (${CF_ZONE_NAME})"
    return 0
  fi

  # Auto-detect zone by trying progressively shorter suffixes of DOMAIN.
  # This correctly handles multi-part TLDs (e.g. .com.au, .co.uk) where
  # stripping only the first label would give a non-existent zone.
  local candidate="${DOMAIN}"
  while [[ "${candidate}" == *.* ]]; do
    local resp
    resp="$(cf_api GET "/zones?name=${candidate}&status=active")"
    CF_ZONE_ID="$(printf '%s' "${resp}" | jq -r '.result[0].id // empty')"
    if [[ -n "${CF_ZONE_ID}" ]]; then
      CF_ZONE_NAME="${candidate}"
      log "Cloudflare zone ID: ${CF_ZONE_ID} (${CF_ZONE_NAME})"
      return 0
    fi
    candidate="${candidate#*.}"  # strip leftmost label and retry
  done
  die "Cloudflare zone not found for any suffix of '${DOMAIN}'. Check domain or use --cf-zone."
}

cf_get_account_id() {
  if [[ -n "${CF_ACCOUNT_ID:-}" ]]; then
    [[ "${CF_ACCOUNT_ID}" =~ ${CF_ID_RE} ]] || die "Invalid --cf-account-id value: ${CF_ACCOUNT_ID}"
    log "Cloudflare account ID override: ${CF_ACCOUNT_ID}"
    return 0
  fi

  local resp
  resp="$(cf_api GET /accounts)"
  CF_ACCOUNT_ID="$(printf '%s' "${resp}" | jq -r '.result[0].id // empty')"
  if [[ -n "${CF_ACCOUNT_ID}" ]]; then
    log "Cloudflare account ID: ${CF_ACCOUNT_ID}"
    return 0
  fi

  # Some scoped API tokens can manage a specific zone/tunnel but return an empty
  # list from /accounts. Fall back to resolving account.id from the selected zone.
  if [[ -n "${CF_ZONE_ID}" ]]; then
    local zone_resp
    zone_resp="$(cf_api GET "/zones/${CF_ZONE_ID}")"
    CF_ACCOUNT_ID="$(printf '%s' "${zone_resp}" | jq -r '.result.account.id // empty')"
    if [[ -n "${CF_ACCOUNT_ID}" ]]; then
      log "Cloudflare account ID (from zone ${CF_ZONE_ID}): ${CF_ACCOUNT_ID}"
      return 0
    fi
  fi

  die "No Cloudflare account found (both /accounts and zone account lookup were empty)."
}

cf_expect_probe_authorized_or_validation_error() {
  local action="$1" resp="$2" expected_codes_csv="$3"
  local success code msg
  success="$(printf '%s' "${resp}" | jq -r '.success // false' 2>/dev/null || echo "false")"
  [[ "${success}" == "true" ]] && return 0
  code="$(printf '%s' "${resp}" | jq -r '.errors[0].code // empty' 2>/dev/null || true)"
  msg="$(printf '%s' "${resp}" | jq -r '.errors[0].message // "unknown"' 2>/dev/null || echo "unknown")"
  if [[ "${code}" == "10000" || "${code}" == "9109" ]]; then
    die "${action} failed: ${msg} (code ${code}). Ask the user for a token with the required permissions."
  fi

  if [[ -z "${expected_codes_csv}" ]]; then
    die "${action} failed unexpectedly: ${msg} (code ${code:-unknown})."
  fi

  local expected
  IFS=',' read -r -a expected <<< "${expected_codes_csv}"
  local allow
  for allow in "${expected[@]}"; do
    [[ "${code}" == "${allow}" ]] && return 0
  done

  die "${action} failed unexpectedly: ${msg} (code ${code:-unknown})."
}

cf_verify_dns_write_token() {
  # Probe DNS write authorization with an intentionally invalid payload.
  # Expected outcome when authorized: validation error (non-auth) and no mutation.
  local resp
  resp="$(cf_api POST "/zones/${CF_ZONE_ID}/dns_records" '{}')"
  cf_expect_probe_authorized_or_validation_error \
    "Cloudflare DNS write permission check" "${resp}" "9000,1004"
  log "Cloudflare DNS write permission verified."
}

cf_verify_tunnel_token() {
  [[ "${DEPLOY_MODE}" == "tunnel" ]] || return 0
  local resp
  resp="$(cf_tunnel_api GET "/accounts/${CF_ACCOUNT_ID}/cfd_tunnel?per_page=1")"
  cf_expect_probe_authorized_or_validation_error \
    "Cloudflare Tunnel read permission check" "${resp}" ""
  local status err
  status="$(printf '%s' "${resp}" | jq -r '.success // false')"
  if [[ "${status}" != "true" ]]; then
    err="$(printf '%s' "${resp}" | jq -r '.errors[0].message // "unknown"')"
    die "Cloudflare tunnel API token verification failed: ${err}. Ask the user for a token with Cloudflare Tunnel permissions."
  fi

  # Probe tunnel create authorization with an intentionally invalid payload.
  # Expected outcome when authorized: validation error (non-auth) and no mutation.
  resp="$(cf_tunnel_api POST "/accounts/${CF_ACCOUNT_ID}/cfd_tunnel" '{}')"
  cf_expect_probe_authorized_or_validation_error \
    "Cloudflare Tunnel write permission check" "${resp}" "1030,1004"
  log "Cloudflare tunnel API token verified (read/write)."
}

cf_expect_success() {
  local action="$1" resp="$2"
  local success
  success="$(printf '%s' "${resp}" | jq -r '.success // false' 2>/dev/null || echo "false")"
  if [[ "${success}" != "true" ]]; then
    local err
    err="$(printf '%s' "${resp}" | jq -r '[.errors[]?.message] | join("; ")' 2>/dev/null || true)"
    [[ -n "${err}" && "${err}" != "null" ]] || err="unknown"
    die "${action} failed: ${err}"
  fi
}

cf_delete_dns_records_by_type() {
  local name="$1"
  shift || true
  local type existing record_id resp

  for type in "$@"; do
    existing="$(cf_api GET "/zones/${CF_ZONE_ID}/dns_records?type=${type}&name=${name}")"
    while IFS= read -r record_id; do
      [[ -n "${record_id}" ]] || continue
      resp="$(cf_api DELETE "/zones/${CF_ZONE_ID}/dns_records/${record_id}")"
      cf_expect_success "Cloudflare ${type} record delete (${name})" "${resp}"
      log "Deleted conflicting ${type} record: ${name} (${record_id})"
    done < <(printf '%s' "${existing}" | jq -r '.result[]?.id // empty')
  done
}

cf_upsert_a_record() {
  local name="$1" ip="$2" proxied="${3:-true}"
  local existing
  cf_delete_dns_records_by_type "${name}" AAAA CNAME
  existing="$(cf_api GET "/zones/${CF_ZONE_ID}/dns_records?type=A&name=${name}")"
  local record_id record_content record_proxied needs_update="true"
  record_id="$(printf '%s' "${existing}" | jq -r '.result[0].id // empty')"
  record_content="$(printf '%s' "${existing}" | jq -r '.result[0].content // empty')"
  record_proxied="$(printf '%s' "${existing}" | jq -r '.result[0].proxied // false')"
  local body
  body="$(jq -n --arg name "${name}" --arg ip "${ip}" --argjson proxied "${proxied}" \
    '{type:"A",name:$name,content:$ip,proxied:$proxied,ttl:1}')"
  local resp

  if [[ -n "${record_id}" ]]; then
    if [[ "${record_content}" == "${ip}" && "${record_proxied}" == "${proxied}" ]]; then
      needs_update="false"
    else
      resp="$(cf_api PUT "/zones/${CF_ZONE_ID}/dns_records/${record_id}" "${body}")"
      cf_expect_success "Cloudflare A record update (${name})" "${resp}"
    fi
    while IFS= read -r duplicate_id; do
      [[ -n "${duplicate_id}" ]] || continue
      resp="$(cf_api DELETE "/zones/${CF_ZONE_ID}/dns_records/${duplicate_id}")"
      cf_expect_success "Cloudflare duplicate A record delete (${name})" "${resp}"
      log "Deleted duplicate A record: ${name} (${duplicate_id})"
    done < <(printf '%s' "${existing}" | jq -r --arg keep "${record_id}" '.result[]?.id | select(. != $keep)')
    if [[ "${needs_update}" == "true" ]]; then
      log "Updated A record: ${name} → ${ip} (proxied=${proxied})"
    else
      log "A record unchanged: ${name} → ${ip} (proxied=${proxied})"
    fi
  else
    resp="$(cf_api POST "/zones/${CF_ZONE_ID}/dns_records" "${body}")"
    cf_expect_success "Cloudflare A record create (${name})" "${resp}"
    log "Created A record: ${name} → ${ip} (proxied=${proxied})"
  fi
}

coolify_tunnel_name() {
  local domain_lc slug digest
  domain_lc="$(printf '%s' "${DOMAIN}" | tr '[:upper:]' '[:lower:]')"
  slug="$(printf '%s' "${domain_lc}" | tr -cs 'a-z0-9' '-')"
  slug="${slug#-}"
  slug="${slug%-}"
  digest="$(printf '%s' "${domain_lc}" | openssl dgst -sha256 -r | awk '{print substr($1, 1, 12)}')"
  printf 'coolify-%s-%s' "${slug:0:42}" "${digest}"
}

cf_create_tunnel() {
  local stop_fn="${1:-}"   # optional: name of function to call to stop cloudflared
  local fetch_existing_tunnel_fn="${2:-}"  # optional: prints "id<TAB>secret" for server-configured tunnel
  local tunnel_name
  tunnel_name="$(coolify_tunnel_name)"

  # Prefer reusing the currently configured tunnel on reruns. If the same-name tunnel set
  # does not match the server's configured credentials, fall back to delete/recreate.
  # Stop cloudflared first in the delete path so it releases active connections.
  local existing_ids=()
  mapfile -t existing_ids < <(
    cf_tunnel_api GET "/accounts/${CF_ACCOUNT_ID}/cfd_tunnel?name=${tunnel_name}&is_deleted=false" \
      | jq -r '.result[]?.id // empty'
  )
  if (( ${#existing_ids[@]} > 0 )); then
    local reusable_id="" reusable_secret="" reusable_material=""
    if [[ -n "${fetch_existing_tunnel_fn}" ]] && declare -F "${fetch_existing_tunnel_fn}" >/dev/null 2>&1; then
      reusable_material="$("${fetch_existing_tunnel_fn}" 2>/dev/null || true)"
      if [[ -n "${reusable_material}" ]]; then
        IFS=$'\t' read -r reusable_id reusable_secret <<< "${reusable_material}"
      fi
    fi

    if [[ -n "${reusable_id}" && -n "${reusable_secret}" ]]; then
      local existing_id found_reusable="false" delete_resp delete_ok delete_err
      for existing_id in "${existing_ids[@]}"; do
        if [[ "${existing_id}" == "${reusable_id}" ]]; then
          found_reusable="true"
          break
        fi
      done
      if [[ "${found_reusable}" == "true" ]]; then
        TUNNEL_ID="${reusable_id}"
        TUNNEL_SECRET="${reusable_secret}"
        for existing_id in "${existing_ids[@]}"; do
          [[ "${existing_id}" == "${TUNNEL_ID}" ]] && continue
          log "Deleting duplicate stale tunnel ${tunnel_name} (${existing_id}) while reusing ${TUNNEL_ID}..."
          delete_resp="$(cf_tunnel_api DELETE "/accounts/${CF_ACCOUNT_ID}/cfd_tunnel/${existing_id}" 2>/dev/null || true)"
          delete_ok="$(printf '%s' "${delete_resp}" | jq -r '.success // false' 2>/dev/null || echo "false")"
          if [[ "${delete_ok}" == "true" ]]; then
            log "Deleted stale tunnel ${existing_id}"
          else
            delete_err="$(printf '%s' "${delete_resp}" | jq -r '[.errors[]?.message] | join("; ")' 2>/dev/null || true)"
            [[ -n "${delete_err}" && "${delete_err}" != "null" ]] || delete_err="unknown"
            die "Could not delete duplicate stale tunnel ${existing_id} (${delete_err}) while reusing ${TUNNEL_ID}."
          fi
        done
        log "Reusing existing tunnel: ${tunnel_name} (${TUNNEL_ID})"
        return 0
      fi
    fi

    log "Stopping cloudflared on server to release tunnel connections before delete..."
    [[ -n "${stop_fn}" ]] && "${stop_fn}"
    sleep 3  # Allow connections to close
    local existing_id delete_resp delete_ok delete_err
    for existing_id in "${existing_ids[@]}"; do
      log "Deleting stale tunnel ${tunnel_name} (${existing_id}) before recreating..."
      delete_resp="$(cf_tunnel_api DELETE "/accounts/${CF_ACCOUNT_ID}/cfd_tunnel/${existing_id}" 2>/dev/null || true)"
      delete_ok="$(printf '%s' "${delete_resp}" | jq -r '.success // false' 2>/dev/null || echo "false")"
      if [[ "${delete_ok}" == "true" ]]; then
        log "Deleted stale tunnel ${existing_id}"
      else
        delete_err="$(printf '%s' "${delete_resp}" | jq -r '[.errors[]?.message] | join("; ")' 2>/dev/null || true)"
        [[ -n "${delete_err}" && "${delete_err}" != "null" ]] || delete_err="unknown"
        die "Could not delete stale tunnel ${existing_id} (${delete_err}); refusing to reuse reserved tunnel name ${tunnel_name}."
      fi
    done
    sleep 2  # Allow CF to release the name
  fi

  TUNNEL_SECRET="$(openssl rand -base64 32)"
  local body
  body="$(jq -n --arg name "${tunnel_name}" --arg secret "${TUNNEL_SECRET}" \
    '{name:$name,tunnel_secret:$secret,config_src:"local"}')"
  local resp
  resp="$(cf_tunnel_api POST "/accounts/${CF_ACCOUNT_ID}/cfd_tunnel" "${body}")"
  TUNNEL_ID="$(printf '%s' "${resp}" | jq -r '.result.id // empty')"
  [[ -n "${TUNNEL_ID}" ]] || die "Failed to create Cloudflare Tunnel: $(printf '%s' "${resp}" | jq -r '.errors[0].message // "unknown"')"
  log "Created tunnel: ${tunnel_name} (${TUNNEL_ID})"
}

cf_upsert_cname() {
  local name="$1" target="$2"
  local existing
  cf_delete_dns_records_by_type "${name}" A AAAA
  existing="$(cf_api GET "/zones/${CF_ZONE_ID}/dns_records?type=CNAME&name=${name}")"
  local record_id record_content record_proxied needs_update="true"
  record_id="$(printf '%s' "${existing}" | jq -r '.result[0].id // empty')"
  record_content="$(printf '%s' "${existing}" | jq -r '.result[0].content // empty')"
  record_proxied="$(printf '%s' "${existing}" | jq -r '.result[0].proxied // false')"
  local body
  body="$(jq -n --arg name "${name}" --arg target "${target}" \
    '{type:"CNAME",name:$name,content:$target,proxied:true,ttl:1}')"
  local resp

  if [[ -n "${record_id}" ]]; then
    if [[ "${record_content}" == "${target}" && "${record_proxied}" == "true" ]]; then
      needs_update="false"
    else
      resp="$(cf_api PUT "/zones/${CF_ZONE_ID}/dns_records/${record_id}" "${body}")"
      cf_expect_success "Cloudflare CNAME update (${name})" "${resp}"
    fi
    while IFS= read -r duplicate_id; do
      [[ -n "${duplicate_id}" ]] || continue
      resp="$(cf_api DELETE "/zones/${CF_ZONE_ID}/dns_records/${duplicate_id}")"
      cf_expect_success "Cloudflare duplicate CNAME delete (${name})" "${resp}"
      log "Deleted duplicate CNAME: ${name} (${duplicate_id})"
    done < <(printf '%s' "${existing}" | jq -r --arg keep "${record_id}" '.result[]?.id | select(. != $keep)')
    if [[ "${needs_update}" == "true" ]]; then
      log "Updated CNAME: ${name} → ${target}"
    else
      log "CNAME unchanged: ${name} → ${target}"
    fi
  else
    resp="$(cf_api POST "/zones/${CF_ZONE_ID}/dns_records" "${body}")"
    cf_expect_success "Cloudflare CNAME create (${name})" "${resp}"
    log "Created CNAME: ${name} → ${target}"
  fi
}

cf_delete_conflicting_host_records() {
  local name="$1"
  cf_delete_dns_records_by_type "${name}" AAAA CNAME
}

cf_assert_private_tailscale_a_record() {
  local name="$1" expected_ip="$2"
  local resp success matching_count conflicting_count
  resp="$(cf_api GET "/zones/${CF_ZONE_ID}/dns_records?type=A&name=${name}")"
  success="$(printf '%s' "${resp}" | jq -r '.success // false')"
  [[ "${success}" == "true" ]] || die "Cloudflare DNS lookup failed for ${name}: $(printf '%s' "${resp}" | jq -r '.errors[0].message // "unknown"')"

  matching_count="$(printf '%s' "${resp}" \
    | jq -r --arg ip "${expected_ip}" '[.result[]? | select((.content // "") == $ip and (.proxied == false))] | length')"
  conflicting_count="$(printf '%s' "${resp}" \
    | jq -r --arg ip "${expected_ip}" '[.result[]? | select((.content // "") != $ip or (.proxied != false))] | length')"

  [[ "${matching_count}" =~ ^[0-9]+$ ]] || matching_count=0
  [[ "${conflicting_count}" =~ ^[0-9]+$ ]] || conflicting_count=0

  (( matching_count >= 1 )) || die "Expected DNS-only A record ${name} → ${expected_ip}, but none found."
  (( conflicting_count == 0 )) || die "Conflicting A record(s) found for ${name}; expected only DNS-only ${expected_ip}."
  log "Verified DNS-only A record: ${name} → ${expected_ip}"
}
