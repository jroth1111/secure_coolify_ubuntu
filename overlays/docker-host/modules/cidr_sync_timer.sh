configure_docker_ssh_cidr_sync_timer() {
  if ! is_true "${STRICT_DOCKER_SSH_CIDRS}"; then
    if is_true "${DRY_RUN}"; then
      log "DRY-RUN: would disable docker-ssh-cidr-sync.timer in compatibility CIDR mode."
      return 0
    fi
    systemctl disable --now docker-ssh-cidr-sync.timer 2>/dev/null || true
    rm -f "${DOCKER_SSH_CIDR_SYNC_SERVICE}" "${DOCKER_SSH_CIDR_SYNC_TIMER}" "${DOCKER_SSH_CIDR_SYNC_SCRIPT}" 2>/dev/null || true
    run systemctl daemon-reload
    return 0
  fi

  if is_true "${DRY_RUN}"; then
    log "DRY-RUN: would install docker-ssh-cidr-sync.timer."
    return 0
  fi

  write_file "${DOCKER_SSH_CIDR_SYNC_SCRIPT}" "0750" "root" "root" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail

STATE_FILE="/var/lib/bootstrap-hardening/state"
STATE_LOCK_FILE="${STATE_FILE}.lock"
SSH_DROPIN_FILE="/etc/ssh/sshd_config.d/00-coolify-hardening.conf"
RULE_COMMENT="coolify-hardening-ssh-docker-bridge"

[[ -f "${STATE_FILE}" ]] || exit 0

copy_state_file() {
  local dest="$1"
  if command -v flock >/dev/null 2>&1; then
    flock -s "${STATE_LOCK_FILE}" bash -ceu 'cat "$1" > "$2"' _ "${STATE_FILE}" "${dest}"
  else
    cat "${STATE_FILE}" > "${dest}"
  fi
}

update_state_docker_cidrs() {
  local cidr_csv="$1"
  local tmp_state
  tmp_state="$(mktemp)"

  if command -v flock >/dev/null 2>&1; then
    exec 9>"${STATE_LOCK_FILE}"
    flock 9
  fi

  awk -v cidr_csv="${cidr_csv}" '
    BEGIN { updated=0 }
    /^docker_ssh_cidrs=/ {
      print "docker_ssh_cidrs=" cidr_csv
      updated=1
      next
    }
    { print }
    END {
      if (!updated) print "docker_ssh_cidrs=" cidr_csv
    }
  ' "${STATE_FILE}" > "${tmp_state}"
  install -m 0640 "${tmp_state}" "${STATE_FILE}"
  rm -f "${tmp_state}"

  if command -v flock >/dev/null 2>&1; then
    flock -u 9 || true
    exec 9>&-
  fi
}

state_snapshot="$(mktemp)"
copy_state_file "${state_snapshot}"
# shellcheck disable=SC1090
source "${state_snapshot}"
rm -f "${state_snapshot}"

is_true() {
  case "${1,,}" in
    1|true|yes|y|on) return 0 ;;
    *) return 1 ;;
  esac
}

if ! is_true "${strict_docker_ssh_cidrs:-false}"; then
  exit 0
fi

admin_user="${admin_user:-}"
ssh_port="${ssh_port:-22}"
[[ -n "${admin_user}" ]] || exit 0
[[ "${ssh_port}" =~ ^[0-9]+$ ]] || ssh_port="22"

is_valid_cidr() {
  [[ "$1" =~ ^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/([0-9]|[12][0-9]|3[0-2])$ ]]
}

normalize_cidr() {
  python3 - "$1" <<'PY'
import ipaddress
import sys
try:
    net = ipaddress.ip_network(sys.argv[1], strict=False)
    if isinstance(net, ipaddress.IPv4Network):
        print(str(net))
except Exception:
    pass
PY
}

declare -a cidrs=()
declare -A seen=()

add_cidr() {
  local cidr="$1"
  local normalized
  [[ -n "${cidr}" ]] || return 0
  is_valid_cidr "${cidr}" || return 0
  normalized="$(normalize_cidr "${cidr}")"
  [[ -n "${normalized}" ]] || return 0
  if [[ -z "${seen[${normalized}]:-}" ]]; then
    cidrs+=("${normalized}")
    seen["${normalized}"]=1
  fi
}

if command -v docker >/dev/null 2>&1; then
  while IFS= read -r cidr; do
    add_cidr "${cidr}"
  done < <(
    docker network ls --filter driver=bridge -q 2>/dev/null \
      | xargs -r docker network inspect --format '{{range .IPAM.Config}}{{.Subnet}}{{"\n"}}{{end}}' 2>/dev/null \
      | awk 'NF' \
      | sort -u
  )
fi

if command -v ip >/dev/null 2>&1; then
  while IFS= read -r cidr; do
    add_cidr "${cidr}"
  done < <(
    ip -o -4 addr show 2>/dev/null \
      | awk '$2 ~ /^docker0$/ || $2 ~ /^br-[[:alnum:]]+$/ { print $4 }' \
      | awk 'NF' \
      | sort -u
  )
fi

if [[ ${#cidrs[@]} -eq 0 ]]; then
  IFS=',' read -r -a previous_cidrs <<< "${docker_ssh_cidrs:-10.0.0.0/8,172.16.0.0/12}"
  for cidr in "${previous_cidrs[@]}"; do
    cidr="${cidr//[[:space:]]/}"
    add_cidr "${cidr}"
  done
fi

[[ ${#cidrs[@]} -gt 0 ]] || exit 0

match_addresses="127.0.0.1,::1"
for cidr in "${cidrs[@]}"; do
  match_addresses+=",${cidr}"
done

if [[ -f "${SSH_DROPIN_FILE}" ]] && grep -q '^Match Address ' "${SSH_DROPIN_FILE}"; then
  desired_line="Match Address ${match_addresses}"
  current_line="$(grep -m1 '^Match Address ' "${SSH_DROPIN_FILE}" || true)"
  if [[ "${current_line}" != "${desired_line}" ]]; then
    tmp_dropin="$(mktemp)"
    backup_dropin="${SSH_DROPIN_FILE}.bak.$(date +%s)"
    cp -a "${SSH_DROPIN_FILE}" "${backup_dropin}"
    sed "0,/^Match Address /s|^Match Address .*|${desired_line}|" "${SSH_DROPIN_FILE}" > "${tmp_dropin}"
    install -m 0644 "${tmp_dropin}" "${SSH_DROPIN_FILE}"
    rm -f "${tmp_dropin}"
    if ! sshd -t; then
      cp -a "${backup_dropin}" "${SSH_DROPIN_FILE}"
      exit 1
    fi
    if systemctl is-active --quiet ssh 2>/dev/null; then
      systemctl reload ssh || systemctl restart ssh
    elif systemctl is-active --quiet sshd 2>/dev/null; then
      systemctl reload sshd || systemctl restart sshd
    fi
    rm -f "${SSH_DROPIN_FILE}".bak.*
  fi
fi

# Reconcile UFW Docker bridge SSH rules to current CIDRs.
if command -v ufw >/dev/null 2>&1; then
  IFS=',' read -r -a old_cidrs <<< "${docker_ssh_cidrs:-}"
  for old_cidr in "${old_cidrs[@]}"; do
    old_cidr="${old_cidr//[[:space:]]/}"
    [[ -n "${old_cidr}" ]] || continue
    # Delete tcp-specific rule
    ufw --force delete allow in proto tcp from "${old_cidr}" to any port "${ssh_port}" comment "${RULE_COMMENT}" >/dev/null 2>&1 || true
    # Delete orphaned non-tcp rule (try multiple syntaxes for compatibility)
    ufw --force delete allow in from "${old_cidr}" to any port "${ssh_port}" comment "${RULE_COMMENT}" >/dev/null 2>&1 || true
    ufw --force delete allow from "${old_cidr}" to any port "${ssh_port}" comment "${RULE_COMMENT}" >/dev/null 2>&1 || true
  done
  for cidr in "${cidrs[@]}"; do
    ufw allow in proto tcp from "${cidr}" to any port "${ssh_port}" comment "${RULE_COMMENT}" >/dev/null 2>&1 || true
  done
fi

cidr_csv="$(IFS=,; echo "${cidrs[*]}")"
update_state_docker_cidrs "${cidr_csv}"
EOF

  write_file "${DOCKER_SSH_CIDR_SYNC_SERVICE}" "0644" "root" "root" <<EOF
[Unit]
Description=Reconcile Docker bridge CIDRs in SSH/UFW hardening rules
After=docker.service network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=${DOCKER_SSH_CIDR_SYNC_SCRIPT}
EOF

  write_file "${DOCKER_SSH_CIDR_SYNC_TIMER}" "0644" "root" "root" <<'EOF'
[Unit]
Description=Periodic Docker bridge CIDR reconciliation for SSH hardening

[Timer]
OnBootSec=3min
OnUnitActiveSec=10min
Persistent=true

[Install]
WantedBy=timers.target
EOF

  run systemctl daemon-reload
  run systemctl enable --now docker-ssh-cidr-sync.timer
  run systemctl start docker-ssh-cidr-sync.service
  wait_for_systemd_unit_success "docker-ssh-cidr-sync.service" 15 2 \
    || die "docker-ssh-cidr-sync.service did not complete successfully."
  log "docker-ssh-cidr-sync.timer enabled (strict Docker SSH CIDR auto-reconcile)."
}
