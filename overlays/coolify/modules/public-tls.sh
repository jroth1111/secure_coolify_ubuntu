#!/usr/bin/env bash
# overlays/coolify/modules/public-tls.sh — Public dashboard TLS restore heredoc generator.
# Sourced by coolify-common.sh; do not execute directly.

[[ "${BASH_SOURCE[0]}" != "${0}" ]] \
  || { printf 'Source this file, do not execute it.\n' >&2; exit 1; }

# coolify_restore_public_dashboard_tls_script — Emit host-side script to remove
# tunnel-private proxy state and restore public dashboard HTTPS routing.
coolify_restore_public_dashboard_tls_script() {
  cat <<'EOF'
set -Eeuo pipefail
: "${DOMAIN:?DOMAIN is required}"
: "${CF_ZONE_NAME:?CF_ZONE_NAME is required}"
: "${PRIVATE_TLS_RESOLVER:=privatedns}"

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
install -d -m 0700 "${dynamic_dir}"

reconcile_public_tls_compose() {
  python3 - "${compose_file}" "${PRIVATE_TLS_RESOLVER}" "${CF_ZONE_NAME}" <<'PY'
from pathlib import Path
import re
import sys

path = Path(sys.argv[1])
private_resolver = sys.argv[2]
zone = sys.argv[3]
env_path = "/data/coolify/proxy/.env"
required_flags = [
    "--certificatesresolvers.letsencrypt.acme.httpchallenge=true",
    "--certificatesresolvers.letsencrypt.acme.httpchallenge.entrypoint=http",
    f"--certificatesresolvers.letsencrypt.acme.email=coolify-admin@{zone}",
    "--certificatesresolvers.letsencrypt.acme.storage=/traefik/acme.json",
]

text = path.read_text()
lines = text.splitlines(keepends=True)

service_start = next((idx for idx, line in enumerate(lines) if re.match(r"^  traefik:\s*$", line)), None)
if service_start is None:
    raise SystemExit("Traefik service block not found in docker-compose.yml")

service_end = service_start + 1
while service_end < len(lines) and not re.match(r"^  [A-Za-z0-9_-]+:\s*$", lines[service_end]):
    service_end += 1

service_lines = lines[service_start + 1 : service_end]

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

scrubbed_service_lines = []
private_flag_pattern = re.compile(rf"^ {{6}}- '?--certificatesresolvers\.{re.escape(private_resolver)}\..*'?\s*$")
for line in service_lines:
    if re.match(r"^ {6}- (?:CLOUDFLARE_DNS_API_TOKEN|CF_DNS_API_TOKEN)=.*$", line):
        continue
    if private_flag_pattern.match(line):
        continue
    scrubbed_service_lines.append(line)
service_lines = scrubbed_service_lines

env_idx = find_section(service_lines, "env_file")
if env_idx is not None:
    env_end = section_end(service_lines, env_idx)
    env_items = [line for line in service_lines[env_idx + 1 : env_end] if line.strip() != f"- {env_path}"]
    if env_items:
        service_lines = service_lines[: env_idx + 1] + env_items + service_lines[env_end:]
    else:
        service_lines = service_lines[:env_idx] + service_lines[env_end:]

command_idx = find_section(service_lines, "command")
if command_idx is None:
    insert_idx = 0
    for idx, line in enumerate(service_lines):
        if re.match(r"^    (image|container_name|restart):", line):
            insert_idx = idx + 1
            break
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

reconcile_public_redirect_file() {
  python3 - "${default_redirect_file}" <<'PY'
from pathlib import Path
import re
import sys

path = Path(sys.argv[1])
text = path.read_text() if path.exists() else "http:\n  routers:\n    catchall:\n      priority: -1000\n"

if not re.search(r"(?m)^http:\s*$", text):
    text = "http:\n  routers:\n    catchall:\n      priority: -1000\n"
elif not re.search(r"(?m)^  routers:\s*$", text):
    if not text.endswith("\n"):
        text += "\n"
    text += "  routers:\n    catchall:\n      priority: -1000\n"
elif not re.search(r"(?m)^    catchall:\s*$", text):
    text = re.sub(r"(?m)^  routers:\s*$", "  routers:\n    catchall:\n      priority: -1000\n", text, count=1)

pattern = re.compile(r"(?ms)^(    catchall:\n)(.*?)(?=^    [A-Za-z0-9_-]+:\s*$|^  [A-Za-z0-9_-]+:\s*$|\Z)")
match = pattern.search(text)
if match is None:
    raise SystemExit("Unable to reconcile catchall router in default_redirect_503.yaml")

body = match.group(2)
body = re.sub(r"(?ms)^      tls:\n(?:        .*\n)*", "", body)
if body and not body.endswith("\n"):
    body += "\n"
body += "      tls:\n        certResolver: letsencrypt\n"
text = text[:match.start()] + match.group(1) + body + text[match.end():]
path.write_text(text)
PY
}

reconcile_public_dashboard_routes() {
  python3 - "${coolify_dynamic_file}" "${DOMAIN}" <<'PY'
from pathlib import Path
import re
import sys

path = Path(sys.argv[1])
domain = sys.argv[2]
text = path.read_text() if path.exists() else "http:\n"

if not re.search(r"(?m)^http:\s*$", text):
    if text and not text.endswith("\n"):
        text += "\n"
    text += "http:\n"

for router_name in ("coolify-https", "coolify-realtime-wss", "coolify-terminal-wss"):
    pattern = rf"(?ms)^    {router_name}:\n(?:      .*\n|        .*\n)*"
    text = re.sub(pattern, "", text)

for service_name in ("coolify-public-dashboard", "coolify-public-realtime", "coolify-public-terminal"):
    pattern = rf"(?ms)^    {service_name}:\n(?:      .*\n|        .*\n|          .*\n)*"
    text = re.sub(pattern, "", text)

def ensure_http_section(section: str) -> None:
    global text
    if re.search(rf"(?m)^  {section}:\s*$", text):
        return
    if not text.endswith("\n"):
        text += "\n"
    text += f"  {section}:\n"

def append_section_block(section: str, block: str) -> None:
    global text
    pattern = re.compile(rf"(?ms)^(  {section}:\n)(.*?)(?=^  [A-Za-z0-9_-]+:\s*$|\Z)")
    match = pattern.search(text)
    if match is None:
        raise SystemExit(f"Missing http.{section} section in coolify.yaml")
    body = match.group(2)
    if body and not body.endswith("\n"):
        body += "\n"
    body += block
    text = text[:match.start()] + match.group(1) + body + text[match.end():]

ensure_http_section("routers")
ensure_http_section("services")

router_block = f"""    coolify-https:
      entryPoints:
        - https
      rule: "Host(`{domain}`)"
      service: coolify-public-dashboard
      tls:
        certResolver: letsencrypt
    coolify-realtime-wss:
      entryPoints:
        - https
      rule: "Host(`{domain}`) && PathPrefix(`/app/`)"
      service: coolify-public-realtime
      tls:
        certResolver: letsencrypt
    coolify-terminal-wss:
      entryPoints:
        - https
      rule: "Host(`{domain}`) && PathPrefix(`/terminal/ws`)"
      service: coolify-public-terminal
      priority: 100
      tls:
        certResolver: letsencrypt
"""

service_block = """    coolify-public-dashboard:
      loadBalancer:
        servers:
          - url: http://coolify:8080
    coolify-public-realtime:
      loadBalancer:
        servers:
          - url: http://coolify-realtime:6001
    coolify-public-terminal:
      loadBalancer:
        servers:
          - url: http://coolify-realtime:6002
"""

append_section_block("routers", router_block)
append_section_block("services", service_block)
path.write_text(text)
PY
}

reconcile_public_tls_compose
reconcile_public_redirect_file
reconcile_public_dashboard_routes
rm -f "${private_route_file}" "${private_route_backup_file}" "${private_route_absent_marker}" "${env_file}"

if docker compose -f "${compose_file}" config >/dev/null 2>&1; then
  docker compose -f "${compose_file}" up -d >/dev/null
else
  echo "Invalid Traefik compose generated at ${compose_file}" >&2
  exit 1
fi

echo "Public dashboard TLS restored for ${DOMAIN}"
EOF
}
