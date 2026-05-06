#!/usr/bin/env bash
# overlays/coolify/modules/server-config.sh — Server-side config heredoc generators
# (private route removal, Coolify SSH key, host.docker.internal, cloudflared).
# Sourced by coolify-common.sh; do not execute directly.

[[ "${BASH_SOURCE[0]}" != "${0}" ]] \
  || { printf 'Source this file, do not execute it.\n' >&2; exit 1; }

# coolify_remove_private_dashboard_routes_script — Emit host-side script to
# remove managed private dashboard route file when not in tunnel mode.
coolify_remove_private_dashboard_routes_script() {
  cat <<'EOF'
set -Eeuo pipefail
route_file="/data/coolify/proxy/dynamic/coolify-private-dashboard.yaml"
route_backup_file="/data/coolify/proxy/dynamic/.coolify-private-dashboard.backup"
route_absent_marker="/data/coolify/proxy/dynamic/.coolify-private-dashboard.absent"
if [[ -f "${route_file}" || -f "${route_backup_file}" || -f "${route_absent_marker}" ]]; then
  rm -f "${route_file}" "${route_backup_file}" "${route_absent_marker}"
  echo "Removed private dashboard routes: ${route_file}"
else
  echo "Private dashboard routes already absent: ${route_file}"
fi
EOF
}

# coolify_add_coolify_root_key_script — Emit host-side script that inserts Coolify's
# generated SSH public key into /root/.ssh/authorized_keys idempotently.
coolify_add_coolify_root_key_script() {
  cat <<'EOF'
set -Eeuo pipefail
key_dir="/data/coolify/ssh/keys"
keyfile="$(ls "${key_dir}"/ssh_key@* "${key_dir}"/id.root@* 2>/dev/null | head -1 || true)"
if [[ -z "${keyfile}" ]]; then
  keyfile="$(find "${key_dir}" -maxdepth 1 -type f ! -name '*.pub' 2>/dev/null | head -1 || true)"
fi
[[ -n "${keyfile}" ]] || { echo "No Coolify SSH key found — skipping"; exit 0; }
pubkey="$(ssh-keygen -y -f "${keyfile}")"
auth="/root/.ssh/authorized_keys"
mkdir -p /root/.ssh && chmod 700 /root/.ssh
touch "${auth}" && chmod 600 "${auth}"
tmp="$(mktemp)"
awk '
  $1 ~ /^(ssh-(rsa|ed25519|dss)|ecdsa-[^[:space:]]+)$/ && NF >= 2 {
    if (!seen[$2]++) {
      print $1 " " $2
    }
  }
' "${auth}" > "${tmp}" 2>/dev/null || true
key_data="$(awk '{print $2}' <<< "${pubkey}")"
if awk '{print $2}' "${tmp}" 2>/dev/null | grep -qxF "${key_data}"; then
  echo "Coolify key already in root authorized_keys"
else
  printf '%s\n' "${pubkey}" >> "${tmp}"
  echo "Coolify key added to root authorized_keys"
fi
install -m 600 "${tmp}" "${auth}"
rm -f "${tmp}"
EOF
}

# coolify_fix_host_docker_internal_script — Emit host-side script that patches
# host.docker.internal in Coolify compose files to the current coolify bridge gateway.
coolify_fix_host_docker_internal_script() {
  cat <<'EOF'
set -Eeuo pipefail
compose_yml="/data/coolify/source/docker-compose.yml"
[[ -f "${compose_yml}" ]] || { echo "docker-compose.yml not found — skipping"; exit 0; }
gateway="$(docker network inspect coolify --format '{{range .IPAM.Config}}{{.Subnet}} {{.Gateway}} {{end}}' 2>/dev/null \
  | tr ' ' '\n' | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | grep -v '/[0-9]' | head -1 || true)"
if [[ -z "${gateway}" ]]; then
  echo "Cannot determine coolify network gateway — skipping host.docker.internal fix"
  exit 0
fi
current="$(grep -m1 'host\.docker\.internal:' "${compose_yml}" | awk -F: '{print $NF}' | tr -d ' ' || true)"
if [[ "${current}" == "${gateway}" ]]; then
  echo "host.docker.internal already set to ${gateway}"
  exit 0
fi
sed -i "s|host\.docker\.internal:.*|host.docker.internal:${gateway}|g" "${compose_yml}"
echo "Patched host.docker.internal → ${gateway}"
docker compose -f /data/coolify/source/docker-compose.yml \
               -f /data/coolify/source/docker-compose.prod.yml \
               up -d --force-recreate coolify soketi 2>&1 | tail -5
EOF
}

# coolify_install_cloudflared_script — Emit host-side script to install cloudflared
# with apt first, then Cloudflare repo fallback.
coolify_install_cloudflared_script() {
  cat <<'EOF'
set -Eeuo pipefail
export DEBIAN_FRONTEND=noninteractive
if bash -c "apt-get update -qq && apt-get install -y -qq cloudflared" 2>/dev/null; then
  exit 0
fi
echo "Trying Cloudflare repository..."
bash -o pipefail -c "curl -fsSL https://pkg.cloudflare.com/cloudflare-main.gpg | tee /usr/share/keyrings/cloudflare-main.gpg >/dev/null"
bash -c "echo \"deb [signed-by=/usr/share/keyrings/cloudflare-main.gpg] https://pkg.cloudflare.com/cloudflared \$(lsb_release -cs) main\" | tee /etc/apt/sources.list.d/cloudflared.list >/dev/null"
bash -c "apt-get update -qq && apt-get install -y -qq cloudflared"
EOF
}

# coolify_configure_cloudflared_script — Emit host-side script to write tunnel creds/config
# and start cloudflared service. Requires TUNNEL_ID, TUNNEL_SECRET, CF_ACCOUNT_ID, DOMAIN,
# APP_DOMAIN, CF_ZONE_NAME in environment.
coolify_configure_cloudflared_script() {
  cat <<'EOF'
set -Eeuo pipefail
: "${TUNNEL_ID:?TUNNEL_ID is required}"
: "${TUNNEL_SECRET:?TUNNEL_SECRET is required}"
: "${CF_ACCOUNT_ID:?CF_ACCOUNT_ID is required}"
: "${DOMAIN:?DOMAIN is required}"
: "${APP_DOMAIN:?APP_DOMAIN is required}"
: "${CF_ZONE_NAME:?CF_ZONE_NAME is required}"

creds_json="$(jq -n --arg id "${TUNNEL_ID}" --arg secret "${TUNNEL_SECRET}" --arg account "${CF_ACCOUNT_ID}" \
  '{AccountTag:$account,TunnelID:$id,TunnelSecret:$secret}')"
mkdir -p /etc/cloudflared
printf '%s' "${creds_json}" > "/etc/cloudflared/${TUNNEL_ID}.json"
chmod 600 "/etc/cloudflared/${TUNNEL_ID}.json"

extra_apex_ingress=""
if [[ "${APP_DOMAIN}" != "${CF_ZONE_NAME}" ]]; then
  extra_apex_ingress="  - hostname: \"*.${CF_ZONE_NAME}\"
    service: http://localhost:80
"
fi
cat > /etc/cloudflared/config.yml <<CFG
tunnel: ${TUNNEL_ID}
credentials-file: /etc/cloudflared/${TUNNEL_ID}.json
metrics: 127.0.0.1:2000

ingress:
  - hostname: ${DOMAIN}
    service: http_status:404
  - hostname: ws.${DOMAIN}
    service: http_status:404
  - hostname: "*.${APP_DOMAIN}"
    service: http://localhost:80
${extra_apex_ingress}  - service: http_status:404
CFG

cloudflared service install 2>/dev/null || true
systemctl enable --now cloudflared
for attempt in $(seq 1 30); do
  if systemctl is-active --quiet cloudflared 2>/dev/null \
    && curl -sf --max-time 3 http://127.0.0.1:2000/ready >/dev/null 2>&1; then
    exit 0
  fi
  (( attempt < 30 )) || break
  sleep 2
done

echo "cloudflared service did not reach a ready state on 127.0.0.1:2000/ready" >&2
journalctl -u cloudflared -n 20 --no-pager >&2 || true
exit 1
EOF
}
