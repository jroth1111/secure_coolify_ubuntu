#!/usr/bin/env bash
# overlays/coolify/modules/private-tls.sh — Private dashboard route and TLS DNS heredoc generators.
# Sourced by coolify-common.sh; do not execute directly.

[[ "${BASH_SOURCE[0]}" != "${0}" ]] \
  || { printf 'Source this file, do not execute it.\n' >&2; exit 1; }

# coolify_configure_private_dashboard_routes_script — Emit host-side script to
# write managed Traefik routes for private dashboard/realtime hostnames.
coolify_configure_private_dashboard_routes_script() {
  cat <<'EOF'
set -Eeuo pipefail
: "${DOMAIN:?DOMAIN is required}"
: "${PRIVATE_TLS_RESOLVER:=privatedns}"

dynamic_dir="/data/coolify/proxy/dynamic"
route_file="${dynamic_dir}/coolify-private-dashboard.yaml"
route_backup_file="${dynamic_dir}/.coolify-private-dashboard.backup"
route_absent_marker="${dynamic_dir}/.coolify-private-dashboard.absent"
mkdir -p "${dynamic_dir}"

if [[ -f "${route_file}" ]]; then
  cp -f "${route_file}" "${route_backup_file}"
  rm -f "${route_absent_marker}"
else
  rm -f "${route_backup_file}"
  : > "${route_absent_marker}"
fi

cat > "${route_file}" <<CFG
# This file is managed by secure-ubuntu-paas.
http:
  middlewares:
    coolify-private-gzip:
      compress: true
    coolify-private-force-https:
      redirectScheme:
        scheme: https
        permanent: true
  routers:
    coolify-private-dashboard-http:
      entryPoints:
        - http
      rule: "Host(\`${DOMAIN}\`)"
      service: noop@internal
      middlewares:
        - coolify-private-force-https
    coolify-private-dashboard-https:
      entryPoints:
        - https
      rule: "Host(\`${DOMAIN}\`)"
      service: coolify-private-dashboard
      middlewares:
        - coolify-private-gzip
      tls:
        certResolver: ${PRIVATE_TLS_RESOLVER}
    coolify-private-realtime-http:
      entryPoints:
        - http
      rule: "Host(\`ws.${DOMAIN}\`)"
      service: noop@internal
      middlewares:
        - coolify-private-force-https
    coolify-private-realtime-https:
      entryPoints:
        - https
      rule: "Host(\`ws.${DOMAIN}\`)"
      service: coolify-private-realtime
      tls:
        certResolver: ${PRIVATE_TLS_RESOLVER}
    coolify-private-terminal-http:
      entryPoints:
        - http
      rule: "Host(\`ws.${DOMAIN}\`) && PathPrefix(\`/terminal/ws\`)"
      service: noop@internal
      middlewares:
        - coolify-private-force-https
      priority: 100
    coolify-private-terminal-https:
      entryPoints:
        - https
      rule: "Host(\`ws.${DOMAIN}\`) && PathPrefix(\`/terminal/ws\`)"
      service: coolify-private-terminal
      priority: 100
      tls:
        certResolver: ${PRIVATE_TLS_RESOLVER}
  services:
    coolify-private-dashboard:
      loadBalancer:
        servers:
          - url: http://coolify:8080
    coolify-private-realtime:
      loadBalancer:
        servers:
          - url: http://coolify-realtime:6001
    coolify-private-terminal:
      loadBalancer:
        servers:
          - url: http://coolify-realtime:6002
CFG

echo "Private dashboard routes written: ${route_file}"
EOF
}

# coolify_configure_private_tls_dns_script — Emit host-side script to ensure
# Traefik can issue trusted certificates for private dashboard/realtime routes
# via ACME DNS-01 using Cloudflare.
coolify_configure_private_tls_dns_script() {
  cat <<'EOF'
set -Eeuo pipefail
: "${CF_DNS_API_TOKEN:?CF_DNS_API_TOKEN is required}"
: "${CF_ZONE_NAME:?CF_ZONE_NAME is required}"
: "${DOMAIN:?DOMAIN is required}"
: "${PRIVATE_TLS_RESOLVER:=privatedns}"
: "${PRIVATE_TLS_CA:=letsencrypt}"
: "${ZEROSSL_CA_SERVER:=https://acme.zerossl.com/v2/DV90}"

case "${PRIVATE_TLS_CA}" in
  letsencrypt)
    ;;
  zerossl)
    : "${ZEROSSL_EAB_KID:?ZEROSSL_EAB_KID is required when PRIVATE_TLS_CA=zerossl}"
    : "${ZEROSSL_EAB_HMAC:?ZEROSSL_EAB_HMAC is required when PRIVATE_TLS_CA=zerossl}"
    ;;
  *)
    echo "Unsupported PRIVATE_TLS_CA: ${PRIVATE_TLS_CA}" >&2
    exit 1
    ;;
esac

proxy_dir="/data/coolify/proxy"
compose_file="${proxy_dir}/docker-compose.yml"
env_file="${proxy_dir}/.env"
dynamic_dir="${proxy_dir}/dynamic"
default_redirect_file="${dynamic_dir}/default_redirect_503.yaml"
coolify_dynamic_file="${dynamic_dir}/coolify.yaml"
private_route_file="${dynamic_dir}/coolify-private-dashboard.yaml"
private_route_backup_file="${dynamic_dir}/.coolify-private-dashboard.backup"
private_route_absent_marker="${dynamic_dir}/.coolify-private-dashboard.absent"

[[ -f "${compose_file}" ]] || { echo "Missing ${compose_file}" >&2; exit 1; }
install -d -m 0700 "${proxy_dir}"

rollback_private_route_file() {
  if [[ -f "${private_route_backup_file}" ]]; then
    mv -f "${private_route_backup_file}" "${private_route_file}"
    rm -f "${private_route_absent_marker}"
  elif [[ -f "${private_route_absent_marker}" ]]; then
    rm -f "${private_route_file}" "${private_route_absent_marker}"
  fi
}

cleanup_private_tls_dns_script() {
  local rc=$?
  if (( rc == 0 )); then
    rm -f "${private_route_backup_file}" "${private_route_absent_marker}"
  else
    rollback_private_route_file || true
  fi
  return "${rc}"
}

trap cleanup_private_tls_dns_script EXIT

cat > "${env_file}" <<ENV
CLOUDFLARE_DNS_API_TOKEN=${CF_DNS_API_TOKEN}
CF_DNS_API_TOKEN=${CF_DNS_API_TOKEN}
ENV
chmod 0600 "${env_file}"

reconcile_private_tls_compose() {
  python3 - "${compose_file}" "${PRIVATE_TLS_RESOLVER}" "${CF_ZONE_NAME}" "${PRIVATE_TLS_CA}" "${ZEROSSL_CA_SERVER}" "${ZEROSSL_EAB_KID:-}" "${ZEROSSL_EAB_HMAC:-}" <<'PY'
from pathlib import Path
import re
import sys

path = Path(sys.argv[1])
resolver = sys.argv[2]
zone = sys.argv[3]
private_tls_ca = sys.argv[4]
zerossl_ca_server = sys.argv[5]
zerossl_eab_kid = sys.argv[6]
zerossl_eab_hmac = sys.argv[7]
env_path = "/data/coolify/proxy/.env"
required_flags = [
    f"--certificatesresolvers.{resolver}.acme.dnschallenge=true",
    f"--certificatesresolvers.{resolver}.acme.dnschallenge.provider=cloudflare",
    f"--certificatesresolvers.{resolver}.acme.dnschallenge.resolvers=1.1.1.1:53,8.8.8.8:53",
    f"--certificatesresolvers.{resolver}.acme.email=coolify-admin@{zone}",
    f"--certificatesresolvers.{resolver}.acme.storage=/traefik/acme.json",
]
if private_tls_ca == "letsencrypt":
    pass
elif private_tls_ca == "zerossl":
    required_flags.extend([
        f"--certificatesresolvers.{resolver}.acme.caserver={zerossl_ca_server}",
        f"--certificatesresolvers.{resolver}.acme.eab.kid={zerossl_eab_kid}",
        f"--certificatesresolvers.{resolver}.acme.eab.hmacencoded={zerossl_eab_hmac}",
    ])
else:
    raise SystemExit(f"Unsupported PRIVATE_TLS_CA: {private_tls_ca}")

text = path.read_text()
lines = text.splitlines(keepends=True)

service_start = next((idx for idx, line in enumerate(lines) if re.match(r"^  traefik:\s*$", line)), None)
if service_start is None:
    raise SystemExit("Traefik service block not found in docker-compose.yml")

service_end = service_start + 1
while service_end < len(lines) and not re.match(r"^  [A-Za-z0-9_-]+:\s*$", lines[service_end]):
    service_end += 1

service_lines = lines[service_start + 1 : service_end]
scrubbed_service_lines = []
resolver_flag_pattern = re.compile(rf"^ {{6}}- '?--certificatesresolvers\.{re.escape(resolver)}\..*'?\s*$")
for line in service_lines:
    if re.match(r"^ {6}- (?:CLOUDFLARE_DNS_API_TOKEN|CF_DNS_API_TOKEN)=.*$", line):
        continue
    if re.match(r"^ {6}- .*certificatesresolvers\.letsencrypt\..*$", line):
        continue
    if resolver_flag_pattern.match(line):
        continue
    scrubbed_service_lines.append(line)
service_lines = scrubbed_service_lines

def find_section(block_lines, key):
    prefix = f"    {key}:"
    for idx, line in enumerate(block_lines):
        if line.startswith(prefix):
            return idx
    return None

def section_end(block_lines, start_idx):
    idx = start_idx + 1
    while idx < len(block_lines):
        if re.match(r"^    [A-Za-z0-9_-]+:\s*$", block_lines[idx]):
            break
        idx += 1
    return idx

env_idx = find_section(service_lines, "env_file")
if env_idx is None:
    insert_idx = 0
    for idx, line in enumerate(service_lines):
        if re.match(r"^    (image|container_name|restart):", line):
            insert_idx = idx + 1
            break
    service_lines[insert_idx:insert_idx] = ["    env_file:\n", f"      - {env_path}\n"]
    env_idx = find_section(service_lines, "env_file")
else:
    env_end = section_end(service_lines, env_idx)
    env_items = service_lines[env_idx + 1 : env_end]
    if f"      - {env_path}\n" not in env_items:
        env_items.append(f"      - {env_path}\n")
        service_lines = service_lines[: env_idx + 1] + env_items + service_lines[env_end:]

command_idx = find_section(service_lines, "command")
if command_idx is None:
    env_idx = find_section(service_lines, "env_file")
    if env_idx is None:
        raise SystemExit("Unable to locate insertion point for Traefik command block")
    insert_idx = section_end(service_lines, env_idx)
    service_lines[insert_idx:insert_idx] = ["    command:\n"]
    command_idx = insert_idx

command_end = section_end(service_lines, command_idx)
command_items = service_lines[command_idx + 1 : command_end]
existing_command_flags = set()
for line in command_items:
    match = re.match(r"^ {6}- '?([^'\n]+)'?\s*$", line)
    if match:
        existing_command_flags.add(match.group(1))

for flag in required_flags:
    if flag not in existing_command_flags:
        command_items.append(f"      - '{flag}'\n")

service_lines = service_lines[: command_idx + 1] + command_items + service_lines[command_end:]
lines = lines[: service_start + 1] + service_lines + lines[service_end:]
path.write_text("".join(lines))
PY
}

reconcile_private_tls_compose

scrub_default_redirect_public_resolver() {
  [[ -f "${default_redirect_file}" ]] || return 0
  python3 - "${default_redirect_file}" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
text = path.read_text()
text = text.replace("      tls:\n        certResolver: letsencrypt\n", "")
path.write_text(text)
PY
}

scrub_coolify_public_https_routers() {
  [[ -f "${coolify_dynamic_file}" ]] || return 0
  python3 - "${coolify_dynamic_file}" <<'PY'
from pathlib import Path
import re
import sys

path = Path(sys.argv[1])
text = path.read_text()
for router_name in ("coolify-https", "coolify-realtime-wss", "coolify-terminal-wss"):
    pattern = rf"(?ms)^    {router_name}:\n(?:      .*\n|        .*\n)*"
    text = re.sub(pattern, "", text)
path.write_text(text)
PY
}

public_router_state_is_clean() {
  ! grep -Eq '^[[:space:]]*certResolver:[[:space:]]*letsencrypt[[:space:]]*$' "${default_redirect_file}" 2>/dev/null \
    && ! grep -Eq '^[[:space:]]*coolify-(https|realtime-wss|terminal-wss):[[:space:]]*$|^[[:space:]]*certresolver:[[:space:]]*letsencrypt[[:space:]]*$' "${coolify_dynamic_file}" 2>/dev/null
}

enforce_private_router_scrub() {
  scrub_default_redirect_public_resolver
  scrub_coolify_public_https_routers
  public_router_state_is_clean
}

# Coolify regenerates this catchall file with a public resolver; remove it in
# tunnel mode so wildcard traffic cannot trigger public ACME flows.
enforce_private_router_scrub || true

if docker compose -f "${compose_file}" config >/dev/null 2>&1; then
  docker compose -f "${compose_file}" up -d >/dev/null
else
  echo "Invalid Traefik compose generated at ${compose_file}" >&2
  exit 1
fi

for _ in $(seq 1 30); do
  if enforce_private_router_scrub; then
    break
  fi
  sleep 1
done

if ! public_router_state_is_clean; then
  echo "Public Traefik HTTPS routes/resolvers remained in ${dynamic_dir}" >&2
  exit 1
fi

wait_for_private_tls_ready() {
  local host="vps.invalid"
  local ws_host="ws.vps.invalid"
  local attempts=120
  local delay=5
  local attempt
  local dashboard_code dashboard_code_insecure dashboard_subject dashboard_issuer
  local ws_code ws_code_insecure ws_subject ws_issuer

  if ! command -v curl >/dev/null 2>&1 || ! command -v openssl >/dev/null 2>&1; then
    return 0
  fi

  probe_private_tls_host() {
    local prefix="${1:?probe_private_tls_host requires prefix}"
    local probe_host="${2:?probe_private_tls_host requires host}"
    local probe_path="${3:?probe_private_tls_host requires path}"
    local ready_regex="${4:?probe_private_tls_host requires ready regex}"
    local code insecure_code cert_meta cert_subject cert_issuer

    code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 \
      --resolve "${probe_host}:443:127.0.0.1" "https://${probe_host}${probe_path}" 2>/dev/null || true)"
    insecure_code="$(curl -k -s -o /dev/null -w '%{http_code}' --max-time 10 \
      --resolve "${probe_host}:443:127.0.0.1" "https://${probe_host}${probe_path}" 2>/dev/null || true)"
    code="${code:-000}"
    insecure_code="${insecure_code:-000}"
    code="${code:0:3}"
    insecure_code="${insecure_code:0:3}"

    cert_meta="$(printf '' | openssl s_client -connect 127.0.0.1:443 -servername "${probe_host}" -showcerts 2>/dev/null \
      | openssl x509 -noout -subject -issuer -ext subjectAltName 2>/dev/null || true)"
    cert_subject="$(awk -F= '/^subject=/{print $2; exit}' <<< "${cert_meta}" | sed 's/^ *//')"
    cert_issuer="$(awk -F= '/^issuer=/{print $2; exit}' <<< "${cert_meta}" | sed 's/^ *//')"

    printf -v "${prefix}_code" '%s' "${code}"
    printf -v "${prefix}_code_insecure" '%s' "${insecure_code}"
    printf -v "${prefix}_subject" '%s' "${cert_subject}"
    printf -v "${prefix}_issuer" '%s' "${cert_issuer}"

    if [[ "${code}" =~ ${ready_regex} ]] \
      && ! grep -Fq "TRAEFIK DEFAULT CERT" <<< "${cert_meta}" \
      && grep -Fq "DNS:${probe_host}" <<< "${cert_meta}"; then
      return 0
    fi

    return 1
  }

  host="${DOMAIN}"
  ws_host="ws.${DOMAIN}"
  for (( attempt=1; attempt<=attempts; attempt++ )); do
    enforce_private_router_scrub || true
    if probe_private_tls_host "dashboard" "${host}" "/api/v1/health" '^2[0-9][0-9]$' \
      && probe_private_tls_host "ws" "${ws_host}" "/" '^[234][0-9][0-9]$' \
      && public_router_state_is_clean; then
      echo "Private TLS certificates ready for ${host} and ${ws_host} (dashboard=${dashboard_code}, websocket=${ws_code})."
      return 0
    fi

    if (( attempt == 1 || attempt % 12 == 0 )); then
      if [[ "${dashboard_code_insecure}" =~ ^2[0-9][0-9]$ && ! "${dashboard_code}" =~ ^2[0-9][0-9]$ ]]; then
        echo "Waiting for trusted private TLS on ${host}: route is up behind untrusted cert (verified=${dashboard_code}, insecure=${dashboard_code_insecure}, subject=${dashboard_subject:-unknown}, issuer=${dashboard_issuer:-unknown}, attempt=${attempt}/${attempts})."
      else
        echo "Waiting for trusted private TLS on ${host}: verified=${dashboard_code}, insecure=${dashboard_code_insecure}, subject=${dashboard_subject:-unknown}, issuer=${dashboard_issuer:-unknown}, attempt=${attempt}/${attempts}."
      fi
      echo "Waiting for trusted private TLS on ${ws_host}: verified=${ws_code:-000}, insecure=${ws_code_insecure:-000}, subject=${ws_subject:-unknown}, issuer=${ws_issuer:-unknown}, attempt=${attempt}/${attempts}."
    fi

    if (( attempt < attempts )); then
      sleep "${delay}"
    fi
  done

  echo "Timed out waiting for trusted private TLS on ${host}; verified=${dashboard_code:-000}, insecure=${dashboard_code_insecure:-000}, subject=${dashboard_subject:-unknown}, issuer=${dashboard_issuer:-unknown}" >&2
  echo "Timed out waiting for trusted private TLS on ${ws_host}; verified=${ws_code:-000}, insecure=${ws_code_insecure:-000}, subject=${ws_subject:-unknown}, issuer=${ws_issuer:-unknown}" >&2
  return 1
}

wait_for_private_tls_ready
enforce_private_router_scrub || true
if ! public_router_state_is_clean; then
  echo "Public Coolify HTTPS routers remained in ${coolify_dynamic_file}" >&2
  exit 1
fi

echo "Private TLS DNS challenge configured for resolver '${PRIVATE_TLS_RESOLVER}'."
EOF
}
