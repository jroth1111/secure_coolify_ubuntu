#!/usr/bin/env bash
# overlays/coolify/modules/install.sh — Docker and Coolify install heredoc generators.
# Sourced by coolify-common.sh; do not execute directly.

[[ "${BASH_SOURCE[0]}" != "${0}" ]] \
  || { printf 'Source this file, do not execute it.\n' >&2; exit 1; }

# coolify_install_docker_engine_script — Emit host-side script to install Docker
# via the official apt repository (no convenience curl|sh installer).
coolify_install_docker_engine_script() {
  cat <<'EOF'
set -Eeuo pipefail
export DEBIAN_FRONTEND=noninteractive
source /etc/os-release
codename="${VERSION_CODENAME:-}"
[[ -n "${codename}" ]] || { echo "VERSION_CODENAME missing in /etc/os-release" >&2; exit 1; }

apt-get update -qq
apt-get install -y -qq ca-certificates curl gnupg
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
chmod a+r /etc/apt/keyrings/docker.asc
cat > /etc/apt/sources.list.d/docker.list <<REPO
deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu ${codename} stable
REPO
apt-get update -qq
apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
EOF
}

# coolify_install_coolify_script — Emit host-side script to install Coolify by
# downloading installer to a local temp file, validating basic format, then executing it.
coolify_install_coolify_script() {
  cat <<'EOF'
set -Eeuo pipefail
installer_url="https://cdn.coollabs.io/coolify/install.sh"
tmp="$(mktemp /tmp/coolify-install.XXXXXX.sh)"
cleanup() { rm -f "${tmp}"; }
trap cleanup EXIT

curl -fsSL "${installer_url}" -o "${tmp}"
[[ -s "${tmp}" ]] || { echo "Downloaded Coolify installer is empty" >&2; exit 1; }
head -1 "${tmp}" | grep -Eq '^#!.*/(ba)?sh$' || { echo "Unexpected Coolify installer header" >&2; exit 1; }
chmod 700 "${tmp}"
if command -v timeout >/dev/null 2>&1; then
  if ! timeout --signal=TERM --kill-after=60 1800 bash "${tmp}"; then
    rc=$?
    if [[ "${rc}" -eq 124 || "${rc}" -eq 137 ]]; then
      echo "Coolify installer timed out after 1800s (likely blocked image pull)." >&2
    fi
    exit "${rc}"
  fi
else
  bash "${tmp}"
fi
EOF
}

# coolify_reconcile_docker_daemon_script — Emit a host-side script that enforces
# daemon.json hardening keys while preserving unrelated settings.
# Caller is responsible for transport/execution (local bash -s vs remote sudo bash -s).
coolify_reconcile_docker_daemon_script() {
  cat <<'EOF'
set -Eeuo pipefail
daemon_json="/etc/docker/daemon.json"
state_file="/var/lib/server-hardening/state"
nproc_hard="8192"
nproc_soft="4096"
tmp="$(mktemp)" || { echo "Failed to create temp file for daemon.json merge" >&2; exit 1; }

if [[ -f "${state_file}" ]]; then
  nproc_hard="$(grep -m1 '^docker_nproc_hard=' "${state_file}" | cut -d= -f2- || echo "8192")"
  nproc_soft="$(grep -m1 '^docker_nproc_soft=' "${state_file}" | cut -d= -f2- || echo "4096")"
fi
[[ "${nproc_hard}" =~ ^[1-9][0-9]*$ ]] || nproc_hard="8192"
[[ "${nproc_soft}" =~ ^[1-9][0-9]*$ ]] || nproc_soft="4096"
if (( nproc_soft > nproc_hard )); then
  nproc_soft="${nproc_hard}"
fi

if [[ -f "${daemon_json}" ]]; then
  current_driver="$(jq -r '.["log-driver"] // ""' "${daemon_json}" 2>/dev/null || true)"
  if [[ "${current_driver}" != "" && "${current_driver}" != "json-file" ]]; then
    echo "WARNING: Docker log-driver drift detected (was '${current_driver}', expected 'json-file'). Reconciling..." >&2
  fi
  current_live_restore="$(jq -r '.["live-restore"] // ""' "${daemon_json}" 2>/dev/null || true)"
  if [[ "${current_live_restore}" != "" && "${current_live_restore}" != "true" ]]; then
    echo "WARNING: Docker live-restore drift detected (was '${current_live_restore}', expected 'true'). Reconciling..." >&2
  fi
  current_ipc_mode="$(jq -r '.["default-ipc-mode"] // ""' "${daemon_json}" 2>/dev/null || true)"
  if [[ "${current_ipc_mode}" != "" && "${current_ipc_mode}" != "private" ]]; then
    echo "WARNING: Docker default-ipc-mode drift detected (was '${current_ipc_mode}', expected 'private'). Reconciling..." >&2
  fi
  current_storage_driver="$(jq -r '.["storage-driver"] // ""' "${daemon_json}" 2>/dev/null || true)"
  if [[ "${current_storage_driver}" != "" && "${current_storage_driver}" != "overlay2" ]]; then
    echo "WARNING: Docker storage-driver drift detected (was '${current_storage_driver}', expected 'overlay2'). Reconciling..." >&2
  fi
fi

if [[ -f "${daemon_json}" ]]; then
  jq \
    --argjson nproc_hard "${nproc_hard}" \
    --argjson nproc_soft "${nproc_soft}" \
    '. + {
      "log-driver":"json-file",
      "log-opts":((.["log-opts"] // {}) + {"max-size":"10m","max-file":"3"}),
      "live-restore":true,
      "default-ipc-mode":"private",
      "storage-driver":"overlay2",
      "default-ulimits":((.["default-ulimits"] // {}) + {
        "nofile":{"Name":"nofile","Hard":65536,"Soft":65536},
        "nproc":{"Name":"nproc","Hard":$nproc_hard,"Soft":$nproc_soft}
      })
    }' "${daemon_json}" > "${tmp}"
else
  jq -n \
    --argjson nproc_hard "${nproc_hard}" \
    --argjson nproc_soft "${nproc_soft}" \
    '{
      "log-driver":"json-file",
      "log-opts":{"max-size":"10m","max-file":"3"},
      "live-restore":true,
      "default-ipc-mode":"private",
      "storage-driver":"overlay2",
      "default-ulimits":{
        "nofile":{"Name":"nofile","Hard":65536,"Soft":65536},
        "nproc":{"Name":"nproc","Hard":$nproc_hard,"Soft":$nproc_soft}
      }
    }' > "${tmp}"
fi

if [[ -f "${daemon_json}" ]] && cmp -s "${tmp}" "${daemon_json}"; then
  rm -f "${tmp}"
  exit 0
fi

if [[ -f "${daemon_json}" ]]; then
  cp -a "${daemon_json}" "${daemon_json}.bak.$(date +%s)"
fi

cat "${tmp}" > "${daemon_json}"
chmod 0644 "${daemon_json}"
rm -f "${tmp}"
if ! systemctl restart docker; then
  echo "Failed to restart Docker after daemon.json update" >&2
  exit 1
fi
EOF
}
