#!/usr/bin/env bats
# Additional behavior tests to close function coverage gaps in base/validate.sh

load '../../helpers/helpers'

start_fake_unix_socket() {
  local sock_path="$1"
  python3 - "${sock_path}" <<'PY' &
import os
import socket
import sys
import time

path = sys.argv[1]
try:
    os.unlink(path)
except FileNotFoundError:
    pass

sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
sock.bind(path)
sock.listen(1)
time.sleep(30)
PY
  local pid=$!
  for _ in $(seq 1 50); do
    [[ -S "${sock_path}" ]] && break
    sleep 0.1
  done
  if [[ ! -S "${sock_path}" ]]; then
    kill "${pid}" 2>/dev/null || true
    wait "${pid}" 2>/dev/null || true
    return 1
  fi
  printf '%s\n' "${pid}"
}

stop_fake_unix_socket() {
  local pid="${1:-}"
  [[ -n "${pid}" ]] || return 0
  kill "${pid}" 2>/dev/null || true
  wait "${pid}" 2>/dev/null || true
}

setup() {
  source_validate_script
  reset_validate_runtime
}

@test "parse_cli_args: sets json mode and state file path" {
  parse_cli_args --json
  [ "${JSON_MODE}" = "true" ]
  [ "${STATE_FILE}" = "/var/lib/server-hardening/state" ]
}

@test "record (runtime): increments PASS count for PASS status" {
  record "PASS" "runtime-check" "ok"
  local json
  json="$(emit_validate_results_json)"
  assert_json_check_status "${json}" "runtime-check" "PASS"
  assert_json_fail_count "${json}" "0"
}

@test "check (runtime): records FAIL when command exits non-zero" {
  check "runtime-check" false
  local json
  json="$(emit_validate_results_json)"
  assert_json_check_status "${json}" "runtime-check" "FAIL"
  assert_json_check_detail_contains "${json}" "runtime-check" "false"
  assert_json_fail_count "${json}" "1"
}

@test "detect_container_runtime: flags containerized runtime" {
  systemd-detect-virt() {
    echo docker
    return 0
  }

  detect_container_runtime
  [ "${IS_CONTAINER}" = "true" ]
}

@test "load_state_context: imports state values into runtime vars" {
  local state
  state="$(mktemp)"
  cat > "${state}" <<STATE
admin_user=alice
ssh_port=2222
wan_iface=eth0
tailscale_direct_wan=true
update_profile=balanced
timezone=Australia/Melbourne
docker_present=true
docker_rules_applied=true
allowed_privileged_containers=coolify-proxy,forgejo-dind
STATE

  STATE_FILE="${state}"
  load_state_context

  [ "${ADMIN_USER}" = "alice" ]
  [ "${SSH_PORT}" = "2222" ]
  [ "${WAN_IFACE}" = "eth0" ]
  [ "${TAILSCALE_DIRECT_WAN}" = "true" ]
  [ "${UPDATE_PROFILE}" = "balanced" ]
  [ "${DOCKER_PRESENT}" = "true" ]
  [ "${DOCKER_RULES_APPLIED}" = "true" ]
  [ "${CONFIGURED_TIMEZONE}" = "Australia/Melbourne" ]
  [ "${ALLOWED_PRIVILEGED_CONTAINERS}" = "coolify-proxy,forgejo-dind" ]

  rm -f "${state}"
}

@test "regex_escape: escapes regex metacharacters" {
  run regex_escape 'a.b[c]\\d+$'
  assert_success
  assert_output 'a\.b\[c\]\\d\+\$'
}

@test "load_docker_ssh_cidrs: returns de-duplicated configured CIDRs" {
  DOCKER_SSH_CIDRS='10.0.0.0/8, 172.16.0.0/12,10.0.0.0/8'
  STRICT_DOCKER_SSH_CIDRS='false'

  run load_docker_ssh_cidrs
  assert_success
  assert_line --index 0 '10.0.0.0/8'
  assert_line --index 1 '172.16.0.0/12'
}

@test "infer_update_profile: detects balanced profile when updates origin present" {
  local apt_local
  apt_local="$(mktemp)"
  printf '"origin=Ubuntu,codename=${distro_codename}-updates,label=Ubuntu";\n' > "${apt_local}"

  run infer_update_profile "${apt_local}"
  assert_success
  assert_output 'balanced'

  rm -f "${apt_local}"
}

@test "ufw_check: records active firewall and tailscale-scoped rules" {
  SSH_PORT="22"
  TAILSCALE_IFACE="tailscale0"
  WAN_IFACE="eth0"
  TUNNEL_MODE="false"
  TAILSCALE_DIRECT_WAN="false"
  DOCKER_SSH_CIDRS='10.0.0.0/8'

  ufw() {
    if [[ "$1" == "status" ]]; then
      cat <<UFW
Status: active
22/tcp                     ALLOW IN    on tailscale0
22/tcp                     ALLOW IN    10.0.0.0/8
8000/tcp                   ALLOW IN    on tailscale0
6001/tcp                   ALLOW IN    on tailscale0
6002/tcp                   ALLOW IN    on tailscale0
UFW
      return 0
    fi
    return 0
  }

  ufw_check
  local json
  json="$(emit_validate_results_json)"
  assert_json_check_status "${json}" "ufw: active" "PASS"
  assert_json_check_status "${json}" "ufw: SSH on tailscale0" "PASS"
  assert_json_fail_count "${json}" "0"
}

@test "ufw_check: does not treat 2222/tcp as a match for SSH_PORT=22" {
  SSH_PORT="22"
  TAILSCALE_IFACE="tailscale0"
  WAN_IFACE="eth0"
  TUNNEL_MODE="false"
  TAILSCALE_DIRECT_WAN="false"
  DOCKER_SSH_CIDRS='10.0.0.0/8'

  ufw() {
    if [[ "$1" == "status" ]]; then
      cat <<UFW
Status: active
2222/tcp                   ALLOW IN    on tailscale0
22/tcp                     ALLOW IN    10.0.0.0/8
8000/tcp                   ALLOW IN    on tailscale0
6001/tcp                   ALLOW IN    on tailscale0
6002/tcp                   ALLOW IN    on tailscale0
UFW
      return 0
    fi
    return 0
  }

  ufw_check
  local json
  json="$(emit_validate_results_json)"
  assert_json_check_status "${json}" "ufw: SSH on tailscale0" "FAIL"
}

@test "ufw_check: fails when docker bridge SSH rule is not tcp-only" {
  SSH_PORT="22"
  TAILSCALE_IFACE="tailscale0"
  WAN_IFACE="eth0"
  TUNNEL_MODE="false"
  TAILSCALE_DIRECT_WAN="false"
  DOCKER_SSH_CIDRS='10.0.0.0/8'

  ufw() {
    if [[ "$1" == "status" ]]; then
      cat <<UFW
Status: active
22/tcp                     ALLOW IN    on tailscale0
22                         ALLOW IN    10.0.0.0/8
8000/tcp                   ALLOW IN    on tailscale0
6001/tcp                   ALLOW IN    on tailscale0
6002/tcp                   ALLOW IN    on tailscale0
UFW
      return 0
    fi
    return 0
  }

  ufw_check
  local json
  json="$(emit_validate_results_json)"
  assert_json_check_status "${json}" "ufw: SSH from Docker bridge (10.0.0.0/8)" "FAIL"
  assert_json_fail_count "${json}" "1"
}

@test "swap_check: reports disabled swap when swap_size is 0" {
  swap_size="0"

  swap_check
  local json
  json="$(emit_validate_results_json)"
  assert_json_check_status "${json}" "swap: disabled" "INFO"
  assert_json_fail_count "${json}" "0"
}

@test "swap_check: passes when swap is active and fstab has a single entry" {
  swap_size="2G"
  IS_CONTAINER="false"

  swapon() {
    if [[ "${1:-}" == "--show" && "${2:-}" == "--noheadings" && "${3:-}" == "--bytes" ]]; then
      echo "/swapfile file 2147483648 0 -2"
      return 0
    fi
    if [[ "${1:-}" == "--show" && "${2:-}" == "--noheadings" ]]; then
      echo "/swapfile file 2G 0B -2"
      return 0
    fi
    return 0
  }

  grep() {
    if [[ "${1:-}" == "-cE" && "${2:-}" == "^/swapfile[[:space:]]" && "${3:-}" == "/etc/fstab" ]]; then
      echo 1
      return 0
    fi
    command grep "$@"
  }

  swap_check
  local json
  json="$(emit_validate_results_json)"
  assert_json_check_status "${json}" "swap: active (2048M)" "PASS"
  assert_json_check_status "${json}" "swap: single fstab entry" "PASS"
}

@test "apparmor_check: passes when aa-status reports enabled" {
  aa-status() {
    [[ "$1" == "--enabled" ]] && return 0
    return 0
  }

  apparmor_check
  local json
  json="$(emit_validate_results_json)"
  assert_json_check_status "${json}" "apparmor: enabled" "PASS"
  assert_json_fail_count "${json}" "0"
}

@test "listening_ports_info: records discovered listening ports" {
  ss() {
    cat <<SS
State Recv-Q Send-Q Local Address:Port Peer Address:Port Process
LISTEN 0      4096   0.0.0.0:22      0.0.0.0:*
SS
  }

  listening_ports_info
  local json
  json="$(emit_validate_results_json)"
  assert_json_check_status "${json}" "listening: TCP ports" "INFO"
  assert_json_check_detail_contains "${json}" "listening: TCP ports" "22"
}

@test "coolify_ssh_check: returns cleanly when Coolify SSH dir is absent" {
  run coolify_ssh_check
  assert_success
}

@test "coolify_ssh_check: records FAIL when key directory exists without ssh_key entries" {
  local key_dir="/data/coolify/ssh/keys"
  if [[ -d "${key_dir}" ]] && compgen -G "${key_dir}/ssh_key@*" >/dev/null; then
    skip "existing Coolify ssh keys present"
  fi

  mkdir -p "${key_dir}" 2>/dev/null || skip "unable to create ${key_dir}"

  coolify_ssh_check
  local json
  json="$(emit_validate_results_json)"
  assert_json_check_status "${json}" "coolify: ssh key exists" "FAIL"
  assert_json_fail_count "${json}" "1"

  rmdir "${key_dir}" 2>/dev/null || true
  rmdir "/data/coolify/ssh" 2>/dev/null || true
  rmdir "/data/coolify" 2>/dev/null || true
}

@test "coolify_ssh_check: records PASS when host key path is usable" {
  local key_dir="/data/coolify/ssh/keys"
  local key_file="${key_dir}/ssh_key@test-$$"
  local auth_file="/root/.ssh/authorized_keys"
  local auth_backup=""
  local had_auth="false"
  local pubkey="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestKeyData coolify@test"

  if [[ -d "${key_dir}" ]] && compgen -G "${key_dir}/ssh_key@*" >/dev/null; then
    skip "existing Coolify ssh keys present"
  fi

  mkdir -p "${key_dir}" 2>/dev/null || skip "unable to create ${key_dir}"
  mkdir -p "/root/.ssh" 2>/dev/null || skip "unable to create /root/.ssh"

  if [[ -f "${auth_file}" ]]; then
    had_auth="true"
    auth_backup="$(mktemp)"
    cp "${auth_file}" "${auth_backup}"
  fi

  : > "${key_file}"
  printf '%s\n' "${pubkey}" > "${auth_file}"

  ssh-keygen() {
    if [[ "${1:-}" == "-y" ]]; then
      echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestKeyData generated@test"
      return 0
    fi
    return 1
  }

  ssh() { return 0; }

  command() {
    if [[ "${1:-}" == "-v" && "${2:-}" == "docker" ]]; then
      return 1
    fi
    builtin command "$@"
  }

  coolify_ssh_check
  local json
  json="$(emit_validate_results_json)"
  assert_json_check_status "${json}" "coolify: ssh key exists" "PASS"
  assert_json_check_status "${json}" "coolify: key in root authorized_keys" "PASS"
  assert_json_check_status "${json}" "coolify: root@127.0.0.1 SSH functional" "PASS"
  assert_json_fail_count "${json}" "0"

  rm -f "${key_file}"
  if [[ "${had_auth}" == "true" ]]; then
    cp "${auth_backup}" "${auth_file}"
  else
    rm -f "${auth_file}"
  fi
  rm -f "${auth_backup}"
  rmdir "${key_dir}" 2>/dev/null || true
  rmdir "/data/coolify/ssh" 2>/dev/null || true
  rmdir "/data/coolify" 2>/dev/null || true
}

@test "cloudflared_check: reports info when cloudflared is not installed" {
  systemctl() { return 1; }
  cloudflared_check
  local json
  json="$(emit_validate_results_json)"
  assert_json_check_status "${json}" "cloudflared: not installed" "INFO"
  assert_json_fail_count "${json}" "0"
}

@test "cloudflared_check: records PASS when service is active" {
  command() {
    if [[ "${1:-}" == "-v" && "${2:-}" == "cloudflared" ]]; then
      return 0
    fi
    builtin command "$@"
  }

  systemctl() {
    if [[ "${1:-}" == "list-unit-files" ]]; then
      echo "cloudflared.service enabled"
      return 0
    fi
    if [[ "${1:-}" == "is-active" && "${2:-}" == "--quiet" && "${3:-}" == "cloudflared" ]]; then
      return 0
    fi
    return 0
  }

  cloudflared_check
  local json
  json="$(emit_validate_results_json)"
  assert_json_check_status "${json}" "cloudflared: service active" "PASS"
}

@test "coolify_container_check: reports info when Docker is missing" {
  command() {
    if [[ "$1" == "-v" && "$2" == "docker" ]]; then
      return 1
    fi
    builtin command "$@"
  }

  coolify_container_check
  local json
  json="$(emit_validate_results_json)"
  assert_json_check_status "${json}" "coolify-containers: docker" "INFO"
  assert_json_fail_count "${json}" "0"
}

@test "coolify_container_check: records PASS when required containers are healthy" {
  if [[ ! -d "/data/coolify" ]]; then
    mkdir -p "/data/coolify" 2>/dev/null || skip "unable to create /data/coolify"
  fi

  command() {
    if [[ "${1:-}" == "-v" && "${2:-}" == "docker" ]]; then
      return 0
    fi
    builtin command "$@"
  }

  docker() {
    if [[ "${1:-}" == "inspect" && "${2:-}" == "--format" ]]; then
      case "${3:-}" in
        "{{.State.Status}}")
          echo running
          return 0
          ;;
        "{{if .State.Health}}{{.State.Health.Status}}{{else}}no-healthcheck{{end}}")
          echo healthy
          return 0
          ;;
      esac
    fi
    return 0
  }

  coolify_container_check
  local json
  json="$(emit_validate_results_json)"
  assert_json_check_status "${json}" "coolify-containers: coolify running (healthy)" "PASS"
  assert_json_check_status "${json}" "coolify-containers: coolify-db running (healthy)" "PASS"
}

@test "admin_sudo_check: reports info when admin user is not configured" {
  ADMIN_USER=""
  admin_sudo_check
  local json
  json="$(emit_validate_results_json)"
  assert_json_check_status "${json}" "admin: sudo" "INFO"
  assert_json_fail_count "${json}" "0"
}

@test "admin_sudo_check: passes when configured admin has sudo and valid authorized_keys" {
  local tmphome
  tmphome="$(mktemp -d)"
  mkdir -p "${tmphome}/.ssh"
  cat > "${tmphome}/.ssh/authorized_keys" <<'EOF'
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestKeyData admin@test
EOF

  ADMIN_USER="alice"

  id() {
    if [[ "${1:-}" == "alice" ]]; then
      return 0
    fi
    if [[ "${1:-}" == "-nG" && "${2:-}" == "alice" ]]; then
      echo "alice sudo"
      return 0
    fi
    command id "$@"
  }

  getent() {
    if [[ "${1:-}" == "passwd" && "${2:-}" == "alice" ]]; then
      echo "alice:x:1000:1000:Alice:${tmphome}:/bin/bash"
      return 0
    fi
    command getent "$@"
  }

  sudo() {
    if [[ "${1:-}" == "-l" && "${2:-}" == "-U" && "${3:-}" == "alice" ]]; then
      echo "(ALL) NOPASSWD: ALL"
      return 0
    fi
    return 1
  }

  admin_sudo_check
  local json
  json="$(emit_validate_results_json)"
  assert_json_check_status "${json}" "admin: in sudo group" "PASS"
  assert_json_check_status "${json}" "admin: passwordless sudo (via other config)" "PASS"
  assert_json_check_status "${json}" "admin: authorized_keys format" "PASS"
  assert_json_fail_count "${json}" "0"

  rm -rf "${tmphome}"
}

@test "auditd_check: executes and records audit status outcomes" {
  IS_CONTAINER="true"
  systemctl() { return 1; }
  auditctl() { return 1; }

  auditd_check
  local json
  json="$(emit_validate_results_json)"
  assert_json_check_status "${json}" "auditd: active" "INFO"
  assert_json_check_status "${json}" "auditd: rules" "FAIL"
  assert_json_fail_count "${json}" "1"
}

@test "auditd_check: records PASS when auditd service, rules, and policy are compliant" {
  local tmp_auditd_conf
  tmp_auditd_conf="$(mktemp)"
  cat > "${tmp_auditd_conf}" <<'EOF'
max_log_file_action = keep_logs
disk_full_action = suspend
disk_error_action = suspend
space_left = 100
space_left_action = syslog
admin_space_left = 50
admin_space_left_action = suspend
EOF

  IS_CONTAINER="false"
  AUDITD_CONF="${tmp_auditd_conf}"

  systemctl() { return 0; }
  auditctl() {
    if [[ "${1:-}" == "-l" ]]; then
      cat <<'RULES'
-a always,exit -F arch=b64 -S sethostname -k identity
-a always,exit -F arch=b64 -S chmod -k sudoers-change
-a always,exit -F arch=b64 -S init_module -k kernel-module
-a always,exit -F arch=b64 -S execve -k user_commands
RULES
      return 0
    fi
    if [[ "${1:-}" == "-s" ]]; then
      cat <<'STATUS'
lost 0
backlog 5
STATUS
      return 0
    fi
    return 1
  }

  auditd_check
  local json
  json="$(emit_validate_results_json)"
  assert_json_check_status "${json}" "auditd: active" "PASS"
  assert_json_check_status "${json}" "auditd: max_log_file_action=keep_logs" "PASS"
  assert_json_check_status "${json}" "auditd: queue loss (lost=0)" "PASS"
  assert_json_fail_count "${json}" "0"

  rm -f "${tmp_auditd_conf}"
}

@test "banner_check: records banner verification result" {
  banner_check
  local json
  local status
  json="$(emit_validate_results_json)"
  status="$(json_check_status "${json}" "banner: /etc/issue.net")"
  [[ -n "${status}" ]]
}

@test "banner_check: records PASS when AUTHORIZED marker check succeeds" {
  if [[ ! -f /etc/issue.net ]]; then
    skip "/etc/issue.net missing in test environment"
  fi

  grep() { return 0; }

  banner_check
  local json
  json="$(emit_validate_results_json)"
  assert_json_check_status "${json}" "banner: /etc/issue.net present" "PASS"
}

@test "coolify_binding_check: records binding guard posture" {
  BIND_DASHBOARD_TO_TAILSCALE="false"
  coolify_binding_check
  local json
  json="$(emit_validate_results_json)"
  assert_json_check_status "${json}" "coolify: dashboard UFW restriction" "INFO"
  assert_json_fail_count "${json}" "0"
}

@test "coolify_binding_check: records PASS when tailscale-scoped UFW rules and guard timer are active" {
  BIND_DASHBOARD_TO_TAILSCALE="true"
  TAILSCALE_IFACE="tailscale0"

  command() {
    if [[ "${1:-}" == "-v" && "${2:-}" == "ufw" ]]; then
      return 0
    fi
    builtin command "$@"
  }

  ufw() {
    if [[ "${1:-}" == "status" ]]; then
      cat <<'UFW'
Status: active
8000/tcp                   ALLOW IN    on tailscale0
6001/tcp                   ALLOW IN    on tailscale0
6002/tcp                   ALLOW IN    on tailscale0
UFW
      return 0
    fi
    return 0
  }

  ss() {
    echo "LISTEN 0 4096 0.0.0.0:8000 0.0.0.0:* users:(\"docker\",pid=1,fd=1)"
  }

  systemctl() {
    if [[ "${1:-}" == "is-active" && "${2:-}" == "--quiet" && "${3:-}" == "coolify-binding-guard.timer" ]]; then
      return 0
    fi
    return 0
  }

  coolify_binding_check
  local json
  json="$(emit_validate_results_json)"
  assert_json_check_status "${json}" "coolify: UFW rule port 8000 on tailscale0" "PASS"
  assert_json_check_status "${json}" "coolify: UFW binding-guard timer active" "PASS"
  assert_json_fail_count "${json}" "0"
}

@test "disabled_services_check: passes when services are masked" {
  systemctl() {
    if [[ "$1" == "is-enabled" ]]; then
      echo masked
      return 0
    fi
    return 0
  }

  disabled_services_check
  local json
  json="$(emit_validate_results_json)"
  assert_json_check_status "${json}" "disabled: rpcbind.service (masked)" "PASS"
  assert_json_check_status "${json}" "disabled: avahi-daemon.service (masked)" "PASS"
  assert_json_check_status "${json}" "disabled: cups.service (masked)" "PASS"
  assert_json_fail_count "${json}" "0"
}

@test "docker_daemon_check: records daemon config status" {
  command() {
    if [[ "$1" == "-v" && "$2" == "docker" ]]; then
      return 1
    fi
    builtin command "$@"
  }

  docker_daemon_check
  local json
  json="$(emit_validate_results_json)"
  assert_json_check_status "${json}" "docker-daemon: daemon.json" "INFO"
  assert_json_fail_count "${json}" "0"
}

@test "docker_daemon_check: records PASS when managed daemon settings are present" {
  local daemon_json="/etc/docker/daemon.json"
  local daemon_backup=""
  local had_daemon="false"

  mkdir -p "/etc/docker" 2>/dev/null || skip "unable to create /etc/docker"
  if [[ -f "${daemon_json}" ]]; then
    had_daemon="true"
    daemon_backup="$(mktemp)"
    cp "${daemon_json}" "${daemon_backup}"
  fi

  cat > "${daemon_json}" <<'EOF'
{
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m"
  },
  "live-restore": true,
  "default-ipc-mode": "private",
  "storage-driver": "overlay2",
  "default-ulimits": {
    "nofile": {"Name":"nofile","Hard":1048576,"Soft":1048576},
    "nproc": {"Name":"nproc","Hard":65535,"Soft":65535}
  }
}
EOF

  command() {
    if [[ "${1:-}" == "-v" && "${2:-}" == "docker" ]]; then
      return 0
    fi
    builtin command "$@"
  }

  docker() {
    if [[ "${1:-}" == "info" && "${2:-}" == "--format" ]]; then
      echo "json-file"
      return 0
    fi
    if [[ "${1:-}" == "info" ]]; then
      return 0
    fi
    return 0
  }

  docker_daemon_check
  local json
  json="$(emit_validate_results_json)"
  assert_json_check_status "${json}" "docker-daemon: log-driver is json-file" "PASS"
  assert_json_check_status "${json}" "docker-daemon: default-ipc-mode is private" "PASS"
  assert_json_check_status "${json}" "docker-daemon: live log-driver is json-file" "PASS"

  if [[ "${had_daemon}" == "true" ]]; then
    cp "${daemon_backup}" "${daemon_json}"
  else
    rm -f "${daemon_json}"
  fi
  rm -f "${daemon_backup}"
}

@test "docker_daemon_check: fails when live-restore is explicitly false" {
  local daemon_json="/etc/docker/daemon.json"
  local daemon_backup=""
  local had_daemon="false"

  mkdir -p "/etc/docker" 2>/dev/null || skip "unable to create /etc/docker"
  if [[ -f "${daemon_json}" ]]; then
    had_daemon="true"
    daemon_backup="$(mktemp)"
    cp "${daemon_json}" "${daemon_backup}"
  fi

  cat > "${daemon_json}" <<'EOF'
{
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m"
  },
  "live-restore": false,
  "default-ipc-mode": "private",
  "storage-driver": "overlay2",
  "default-ulimits": {
    "nofile": {"Name":"nofile","Hard":1048576,"Soft":1048576},
    "nproc": {"Name":"nproc","Hard":65535,"Soft":65535}
  }
}
EOF

  command() {
    if [[ "${1:-}" == "-v" && "${2:-}" == "docker" ]]; then
      return 0
    fi
    builtin command "$@"
  }

  docker() {
    if [[ "${1:-}" == "info" && "${2:-}" == "--format" ]]; then
      echo "json-file"
      return 0
    fi
    if [[ "${1:-}" == "info" ]]; then
      return 0
    fi
    return 0
  }

  docker_daemon_check
  local json
  json="$(emit_validate_results_json)"
  assert_json_check_status "${json}" "docker-daemon: live-restore" "FAIL"

  if [[ "${had_daemon}" == "true" ]]; then
    cp "${daemon_backup}" "${daemon_json}"
  else
    rm -f "${daemon_json}"
  fi
  rm -f "${daemon_backup}"
}

@test "docker_trust_boundary_check: records info when Docker is unavailable" {
  command() {
    if [[ "$1" == "-v" && "$2" == "docker" ]]; then
      return 1
    fi
    builtin command "$@"
  }

  docker_trust_boundary_check
  local json
  json="$(emit_validate_results_json)"
  assert_json_check_status "${json}" "docker-trust: docker" "INFO"
  assert_json_fail_count "${json}" "0"
}

@test "docker_trust_boundary_check: records PASS when socket ownership and boundaries are sane" {
  local sock_dir sock_pid
  sock_dir="$(mktemp -d)"
  DOCKER_SOCK="${sock_dir}/docker.sock"
  sock_pid="$(start_fake_unix_socket "${DOCKER_SOCK}")"

  ADMIN_USER="alice"

  command() {
    if [[ "${1:-}" == "-v" && "${2:-}" == "docker" ]]; then
      return 0
    fi
    builtin command "$@"
  }

  stat() {
    if [[ "${2:-}" == "${DOCKER_SOCK}" ]]; then
      case "${1:-}" in
        -c)
          case "${3:-}" in
            %a) echo 660 ;;
            %U) echo root ;;
            %G) echo docker ;;
          esac
          return 0
          ;;
      esac
    fi
    command stat "$@"
  }

  getent() {
    if [[ "${1:-}" == "group" && "${2:-}" == "docker" ]]; then
      echo "docker:x:999:"
      return 0
    fi
    command getent "$@"
  }

  docker() {
    if [[ "${1:-}" == "ps" && "${2:-}" == "-q" ]]; then
      return 0
    fi
    if [[ "${1:-}" == "inspect" ]]; then
      return 0
    fi
    return 0
  }

  docker_trust_boundary_check
  local json
  json="$(emit_validate_results_json)"
  assert_json_check_status "${json}" "docker-trust: socket world-writable check" "PASS"
  assert_json_check_status "${json}" "docker-trust: socket owner is root" "PASS"
  assert_json_check_status "${json}" "docker-trust: docker group has no named members" "PASS"
  assert_json_check_status "${json}" "docker-trust: admin user not in docker group" "PASS"
  assert_json_check_status "${json}" "docker-trust: privileged containers allowlist" "PASS"

  stop_fake_unix_socket "${sock_pid}"
  rm -rf "${sock_dir}"
}

@test "docker_trust_boundary_check: fails when docker group has named members" {
  local sock_dir sock_pid
  sock_dir="$(mktemp -d)"
  DOCKER_SOCK="${sock_dir}/docker.sock"
  sock_pid="$(start_fake_unix_socket "${DOCKER_SOCK}")"

  ADMIN_USER="alice"

  command() {
    if [[ "${1:-}" == "-v" && "${2:-}" == "docker" ]]; then
      return 0
    fi
    builtin command "$@"
  }

  stat() {
    if [[ "${2:-}" == "${DOCKER_SOCK}" ]]; then
      case "${1:-}" in
        -c)
          case "${3:-}" in
            %a) echo 660 ;;
            %U) echo root ;;
            %G) echo docker ;;
          esac
          return 0
          ;;
      esac
    fi
    command stat "$@"
  }

  getent() {
    if [[ "${1:-}" == "group" && "${2:-}" == "docker" ]]; then
      echo "docker:x:999:alice,bob"
      return 0
    fi
    command getent "$@"
  }

  docker() {
    if [[ "${1:-}" == "ps" && "${2:-}" == "-q" ]]; then
      return 0
    fi
    if [[ "${1:-}" == "inspect" ]]; then
      return 0
    fi
    return 0
  }

  docker_trust_boundary_check
  local json
  json="$(emit_validate_results_json)"
  assert_json_check_status "${json}" "docker-trust: docker group has no named members" "FAIL"
  assert_json_check_status "${json}" "docker-trust: admin user not in docker group" "FAIL"
  assert_json_fail_count "${json}" "2"

  stop_fake_unix_socket "${sock_pid}"
  rm -rf "${sock_dir}"
}

@test "private_domain_hosts_check: passes when dashboard hosts are not loopback-pinned" {
  local hosts_file
  hosts_file="$(mktemp)"
  cat > "${hosts_file}" <<'EOF'
127.0.0.1 localhost
127.0.1.1 vps
EOF

  DOMAIN="vps.example.com"
  HOSTS_FILE="${hosts_file}"

  private_domain_hosts_check
  local json
  json="$(emit_validate_results_json)"
  assert_json_check_status "${json}" "hosts: dashboard domain not loopback-pinned" "PASS"
  assert_json_check_status "${json}" "hosts: websocket domain not loopback-pinned" "PASS"
  assert_json_fail_count "${json}" "0"

  rm -f "${hosts_file}"
}

@test "private_domain_hosts_check: fails when dashboard hosts are loopback-pinned" {
  local hosts_file
  hosts_file="$(mktemp)"
  cat > "${hosts_file}" <<'EOF'
127.0.0.1 localhost vps.example.com ws.vps.example.com
EOF

  DOMAIN="vps.example.com"
  HOSTS_FILE="${hosts_file}"

  private_domain_hosts_check
  local json
  json="$(emit_validate_results_json)"
  assert_json_check_status "${json}" "hosts: dashboard domain not loopback-pinned" "FAIL"
  assert_json_check_status "${json}" "hosts: websocket domain not loopback-pinned" "FAIL"
  assert_json_fail_count "${json}" "2"

  rm -f "${hosts_file}"
}

@test "coolify_instance_settings_check: fails when registration is enabled and fqdn is empty" {
  local tempdir
  tempdir="$(mktemp -d)"
  COOLIFY_ENV_FILE="${tempdir}/coolify.env"
  cat > "${COOLIFY_ENV_FILE}" <<'EOF'
DB_USERNAME=coolify
DB_DATABASE=coolify
DB_PASSWORD=secret
EOF
  DOMAIN="vps.example.com"
  TUNNEL_MODE="true"

  command() {
    if [[ "${1:-}" == "-v" && "${2:-}" == "docker" ]]; then
      return 0
    fi
    builtin command "$@"
  }

  docker() {
    if [[ "${1:-}" == "ps" ]]; then
      echo "coolify-db"
      return 0
    fi
    if [[ "${1:-}" == "exec" ]]; then
      echo "t|"
      return 0
    fi
    return 0
  }

  coolify_instance_settings_check
  local json
  json="$(emit_validate_results_json)"
  assert_json_check_status "${json}" "coolify: registration disabled" "FAIL"
  assert_json_check_status "${json}" "coolify: instance fqdn" "FAIL"
  assert_json_fail_count "${json}" "2"

  rm -rf "${tempdir}"
}

@test "coolify_instance_settings_check: passes when tunnel mode keeps fqdn empty and registration is disabled" {
  local tempdir
  tempdir="$(mktemp -d)"
  COOLIFY_ENV_FILE="${tempdir}/coolify.env"
  cat > "${COOLIFY_ENV_FILE}" <<'EOF'
DB_USERNAME=coolify
DB_DATABASE=coolify
DB_PASSWORD=secret
EOF
  DOMAIN="vps.example.com"
  TUNNEL_MODE="true"

  command() {
    if [[ "${1:-}" == "-v" && "${2:-}" == "docker" ]]; then
      return 0
    fi
    builtin command "$@"
  }

  docker() {
    if [[ "${1:-}" == "ps" ]]; then
      echo "coolify-db"
      return 0
    fi
    if [[ "${1:-}" == "exec" ]]; then
      echo "f|"
      return 0
    fi
    return 0
  }

  coolify_instance_settings_check
  local json
  json="$(emit_validate_results_json)"
  assert_json_check_status "${json}" "coolify: registration disabled" "PASS"
  assert_json_check_status "${json}" "coolify: instance fqdn" "PASS"
  assert_json_fail_count "${json}" "0"

  rm -rf "${tempdir}"
}

@test "docker_trust_boundary_check: fails when privileged containers are not allowlisted" {
  local sock_dir sock_pid
  sock_dir="$(mktemp -d)"
  DOCKER_SOCK="${sock_dir}/docker.sock"
  sock_pid="$(start_fake_unix_socket "${DOCKER_SOCK}")"

  ADMIN_USER="alice"
  ALLOWED_PRIVILEGED_CONTAINERS="coolify-proxy"

  command() {
    if [[ "${1:-}" == "-v" && "${2:-}" == "docker" ]]; then
      return 0
    fi
    builtin command "$@"
  }

  stat() {
    if [[ "${2:-}" == "${DOCKER_SOCK}" ]]; then
      case "${1:-}" in
        -c)
          case "${3:-}" in
            %a) echo 660 ;;
            %U) echo root ;;
            %G) echo docker ;;
          esac
          return 0
          ;;
      esac
    fi
    command stat "$@"
  }

  getent() {
    if [[ "${1:-}" == "group" && "${2:-}" == "docker" ]]; then
      echo "docker:x:999:"
      return 0
    fi
    command getent "$@"
  }

  docker() {
    if [[ "${1:-}" == "ps" && "${2:-}" == "-q" ]]; then
      printf 'cid-1\ncid-2\n'
      return 0
    fi
    if [[ "${1:-}" == "inspect" ]]; then
      printf '/coolify-proxy\n/rogue-service\n'
      return 0
    fi
    return 0
  }

  docker_trust_boundary_check
  local json
  json="$(emit_validate_results_json)"
  assert_json_check_status "${json}" "docker-trust: privileged containers allowlist" "FAIL"
  assert_json_check_detail_contains "${json}" "docker-trust: privileged containers allowlist" "rogue-service"
  assert_json_fail_count "${json}" "1"

  stop_fake_unix_socket "${sock_pid}"
  rm -rf "${sock_dir}"
}

@test "cloudflared_check: fails when tunnel proxy still references public letsencrypt" {
  local tempdir config_file private_route_file compose_file redirect_file coolify_env_file
  tempdir="$(mktemp -d)"
  config_file="${tempdir}/config.yml"
  private_route_file="${tempdir}/coolify-private-dashboard.yaml"
  compose_file="${tempdir}/docker-compose.yml"
  redirect_file="${tempdir}/default_redirect_503.yaml"
  dynamic_file="${tempdir}/coolify.yaml"
  coolify_env_file="${tempdir}/coolify.env"

  cat > "${config_file}" <<'EOF'
tunnel: test-tunnel
ingress:
  - hostname: "vps.example.com"
    service: http://localhost:80
  - hostname: "ws.vps.example.com"
    service: http_status:404
  - hostname: "vps.example.com"
    service: http_status:404
  - service: http_status:404
EOF

  cat > "${private_route_file}" <<'EOF'
http:
  middlewares:
    coolify-private-force-https:
      redirectScheme:
        scheme: https
  routers:
    coolify-private-dashboard-http:
      rule: "Host(`vps.example.com`)"
      service: noop@internal
      middlewares:
        - coolify-private-force-https
    coolify-private-dashboard-https:
      rule: "Host(`vps.example.com`)"
      tls:
        certResolver: privatedns
    coolify-private-realtime-http:
      rule: "Host(`ws.vps.example.com`)"
      service: noop@internal
      middlewares:
        - coolify-private-force-https
    coolify-private-realtime-https:
      rule: "Host(`ws.vps.example.com`)"
      tls:
        certResolver: privatedns
    coolify-private-terminal-http:
      rule: "Host(`ws.vps.example.com`) && PathPrefix(`/terminal/ws`)"
      service: noop@internal
      middlewares:
        - coolify-private-force-https
    coolify-private-terminal-https:
      rule: "Host(`ws.vps.example.com`) && PathPrefix(`/terminal/ws`)"
      tls:
        certResolver: privatedns
EOF

  cat > "${compose_file}" <<'EOF'
services:
  traefik:
    command:
      - '--certificatesresolvers.letsencrypt.acme.storage=/traefik/acme.json'
EOF

  cat > "${redirect_file}" <<'EOF'
http:
  routers:
    catchall:
      tls:
        certResolver: letsencrypt
EOF

  cat > "${dynamic_file}" <<'EOF'
http:
  routers:
    coolify-https:
      tls:
        certresolver: letsencrypt
EOF

  cat > "${coolify_env_file}" <<'EOF'
PUSHER_HOST=ws.vps.example.com
PUSHER_PORT=443
PUSHER_SCHEME=https
EOF

  TUNNEL_MODE="true"
  TAILSCALE_IP=""
  CLOUDFLARED_CONFIG_FILE="${config_file}"
  COOLIFY_PRIVATE_ROUTE_FILE="${private_route_file}"
  COOLIFY_PROXY_COMPOSE_FILE="${compose_file}"
  COOLIFY_PROXY_DEFAULT_REDIRECT_FILE="${redirect_file}"
  COOLIFY_PROXY_DYNAMIC_FILE="${dynamic_file}"
  COOLIFY_ENV_FILE="${coolify_env_file}"

  systemctl() {
    if [[ "${1:-}" == "list-unit-files" ]]; then
      echo "cloudflared.service enabled"
      return 0
    fi
    if [[ "${1:-}" == "is-active" && "${2:-}" == "--quiet" ]]; then
      return 0
    fi
    if [[ "${1:-}" == "is-active" ]]; then
      echo "active"
      return 0
    fi
    return 0
  }

  command() {
    if [[ "${1:-}" == "-v" ]]; then
      case "${2:-}" in
        cloudflared|sysctl) return 0 ;;
        getent|dig) return 1 ;;
      esac
    fi
    builtin command "$@"
  }

  sysctl() {
    if [[ "${1:-}" == "-n" && "${2:-}" == "net.ipv4.ping_group_range" ]]; then
      echo "0 2147483647"
      return 0
    fi
    command sysctl "$@"
  }

  pgrep() { return 1; }

  cloudflared_check
  local json
  json="$(emit_validate_results_json)"
  assert_json_check_status "${json}" "cloudflared: public letsencrypt resolver removed" "FAIL"
  assert_json_check_status "${json}" "cloudflared: catchall route avoids public letsencrypt" "FAIL"
  assert_json_check_status "${json}" "cloudflared: generated Coolify HTTPS routers disabled" "FAIL"
  assert_json_fail_count "${json}" "3"

  rm -rf "${tempdir}"
}

@test "cloudflared_check: passes when tunnel proxy avoids public letsencrypt drift" {
  local tempdir config_file private_route_file compose_file redirect_file coolify_env_file
  tempdir="$(mktemp -d)"
  config_file="${tempdir}/config.yml"
  private_route_file="${tempdir}/coolify-private-dashboard.yaml"
  compose_file="${tempdir}/docker-compose.yml"
  redirect_file="${tempdir}/default_redirect_503.yaml"
  dynamic_file="${tempdir}/coolify.yaml"
  coolify_env_file="${tempdir}/coolify.env"

  cat > "${config_file}" <<'EOF'
tunnel: test-tunnel
ingress:
  - hostname: "vps.example.com"
    service: http://localhost:80
  - hostname: "ws.vps.example.com"
    service: http_status:404
  - hostname: "vps.example.com"
    service: http_status:404
  - service: http_status:404
EOF

  cat > "${private_route_file}" <<'EOF'
http:
  middlewares:
    coolify-private-force-https:
      redirectScheme:
        scheme: https
  routers:
    coolify-private-dashboard-http:
      rule: "Host(`vps.example.com`)"
      service: noop@internal
      middlewares:
        - coolify-private-force-https
    coolify-private-dashboard-https:
      rule: "Host(`vps.example.com`)"
      tls:
        certResolver: privatedns
    coolify-private-realtime-http:
      rule: "Host(`ws.vps.example.com`)"
      service: noop@internal
      middlewares:
        - coolify-private-force-https
    coolify-private-realtime-https:
      rule: "Host(`ws.vps.example.com`)"
      tls:
        certResolver: privatedns
    coolify-private-terminal-http:
      rule: "Host(`ws.vps.example.com`) && PathPrefix(`/terminal/ws`)"
      service: noop@internal
      middlewares:
        - coolify-private-force-https
    coolify-private-terminal-https:
      rule: "Host(`ws.vps.example.com`) && PathPrefix(`/terminal/ws`)"
      tls:
        certResolver: privatedns
EOF

  cat > "${compose_file}" <<'EOF'
services:
  traefik:
    command:
      - '--certificatesresolvers.privatedns.acme.dnschallenge=true'
      - '--certificatesresolvers.privatedns.acme.dnschallenge.provider=cloudflare'
      - '--certificatesresolvers.privatedns.acme.dnschallenge.resolvers=1.1.1.1:53,8.8.8.8:53'
      - '--certificatesresolvers.privatedns.acme.email=coolify-admin@example.com'
      - '--certificatesresolvers.privatedns.acme.storage=/traefik/acme.json'
EOF

  cat > "${redirect_file}" <<'EOF'
http:
  routers:
    catchall:
      priority: -1000
EOF

  cat > "${dynamic_file}" <<'EOF'
http:
  routers:
    coolify-http:
      rule: Host(`vps.example.com`)
EOF

  cat > "${coolify_env_file}" <<'EOF'
PUSHER_HOST=ws.vps.example.com
PUSHER_PORT=443
PUSHER_SCHEME=https
EOF

  TUNNEL_MODE="true"
  TAILSCALE_IP=""
  CLOUDFLARED_CONFIG_FILE="${config_file}"
  COOLIFY_PRIVATE_ROUTE_FILE="${private_route_file}"
  COOLIFY_PROXY_COMPOSE_FILE="${compose_file}"
  COOLIFY_PROXY_DEFAULT_REDIRECT_FILE="${redirect_file}"
  COOLIFY_PROXY_DYNAMIC_FILE="${dynamic_file}"
  COOLIFY_ENV_FILE="${coolify_env_file}"

  systemctl() {
    if [[ "${1:-}" == "list-unit-files" ]]; then
      echo "cloudflared.service enabled"
      return 0
    fi
    if [[ "${1:-}" == "is-active" && "${2:-}" == "--quiet" ]]; then
      return 0
    fi
    if [[ "${1:-}" == "is-active" ]]; then
      echo "active"
      return 0
    fi
    return 0
  }

  command() {
    if [[ "${1:-}" == "-v" ]]; then
      case "${2:-}" in
        cloudflared|sysctl|openssl|curl) return 0 ;;
        getent|dig) return 1 ;;
      esac
    fi
    builtin command "$@"
  }

  openssl() {
    if [[ "${1:-}" == "s_client" ]]; then
      cat <<'EOF'
CONNECTED
EOF
      return 0
    fi
    if [[ "${1:-}" == "x509" ]]; then
      cat <<'EOF'
subject=CN = vps.example.com
issuer=CN = Example Intermediate
X509v3 Subject Alternative Name:
    DNS:vps.example.com, DNS:ws.vps.example.com
EOF
      return 0
    fi
    command openssl "$@"
  }

  curl() {
    local url="${@: -1}"
    case "${url}" in
      "http://vps.example.com") echo "302" ; return 0 ;;
      "https://vps.example.com/api/v1/health") echo "200" ; return 0 ;;
      "http://ws.vps.example.com") echo "302" ; return 0 ;;
      "https://ws.vps.example.com/") echo "200" ; return 0 ;;
    esac
    command curl "$@"
  }

  sysctl() {
    if [[ "${1:-}" == "-n" && "${2:-}" == "net.ipv4.ping_group_range" ]]; then
      echo "0 2147483647"
      return 0
    fi
    command sysctl "$@"
  }

  pgrep() { return 1; }

  cloudflared_check
  local json
  json="$(emit_validate_results_json)"
  assert_json_check_status "${json}" "cloudflared: public letsencrypt resolver removed" "PASS"
  assert_json_check_status "${json}" "cloudflared: private TLS resolver present in Traefik command" "PASS"
  assert_json_check_status "${json}" "cloudflared: private TLS CA (letsencrypt) flags present" "PASS"
  assert_json_check_status "${json}" "cloudflared: catchall route avoids public letsencrypt" "PASS"
  assert_json_check_status "${json}" "cloudflared: generated Coolify HTTPS routers disabled" "PASS"
  assert_json_check_status "${json}" "cloudflared: coolify-private-dashboard-https uses certResolver" "PASS"
  assert_json_check_status "${json}" "cloudflared: coolify-private-realtime-https uses certResolver" "PASS"
  assert_json_check_status "${json}" "cloudflared: coolify-private-terminal-https uses certResolver" "PASS"
  assert_json_check_status "${json}" "cloudflared: private HTTPS routers use certResolver" "PASS"
  assert_json_check_status "${json}" "cloudflared: dashboard host served TLS cert" "PASS"
  assert_json_check_status "${json}" "cloudflared: dashboard host certificate SAN (vps.example.com)" "PASS"
  assert_json_check_status "${json}" "cloudflared: websocket host served TLS cert" "PASS"
  assert_json_check_status "${json}" "cloudflared: websocket host certificate SAN (ws.vps.example.com)" "PASS"
  assert_json_check_status "${json}" "cloudflared: private dashboard HTTP redirect verified" "PASS"
  assert_json_check_status "${json}" "cloudflared: private dashboard HTTPS health verified" "PASS"
  assert_json_check_status "${json}" "cloudflared: private websocket HTTP redirect verified" "PASS"
  assert_json_check_status "${json}" "cloudflared: private websocket HTTPS route verified" "PASS"
  assert_json_fail_count "${json}" "0"

  rm -rf "${tempdir}"
}

@test "cloudflared_check: passes when ZeroSSL private TLS flags are present" {
  local tempdir config_file private_route_file compose_file redirect_file dynamic_file coolify_env_file
  tempdir="$(mktemp -d)"
  config_file="${tempdir}/config.yml"
  private_route_file="${tempdir}/coolify-private-dashboard.yaml"
  compose_file="${tempdir}/docker-compose.yml"
  redirect_file="${tempdir}/default_redirect_503.yaml"
  dynamic_file="${tempdir}/coolify.yaml"
  coolify_env_file="${tempdir}/coolify.env"

  cat > "${config_file}" <<'EOF'
tunnel: test-tunnel
ingress:
  - hostname: "vps.example.com"
    service: http://localhost:80
  - hostname: "ws.vps.example.com"
    service: http_status:404
  - hostname: "vps.example.com"
    service: http_status:404
  - service: http_status:404
EOF

  cat > "${private_route_file}" <<'EOF'
http:
  routers:
    coolify-private-dashboard-https:
      rule: "Host(`vps.example.com`)"
      tls:
        certResolver: privatedns
    coolify-private-realtime-https:
      rule: "Host(`ws.vps.example.com`)"
      tls:
        certResolver: privatedns
    coolify-private-terminal-https:
      rule: "Host(`ws.vps.example.com`) && PathPrefix(`/terminal/ws`)"
      tls:
        certResolver: privatedns
EOF

  cat > "${compose_file}" <<'EOF'
services:
  traefik:
    command:
      - '--certificatesresolvers.privatedns.acme.dnschallenge=true'
      - '--certificatesresolvers.privatedns.acme.dnschallenge.provider=cloudflare'
      - '--certificatesresolvers.privatedns.acme.dnschallenge.resolvers=1.1.1.1:53,8.8.8.8:53'
      - '--certificatesresolvers.privatedns.acme.email=coolify-admin@example.com'
      - '--certificatesresolvers.privatedns.acme.storage=/traefik/acme.json'
      - '--certificatesresolvers.privatedns.acme.caserver=https://acme.zerossl.com/v2/DV90'
      - '--certificatesresolvers.privatedns.acme.eab.kid=test-kid'
      - '--certificatesresolvers.privatedns.acme.eab.hmacencoded=test-hmac'
EOF

  cat > "${redirect_file}" <<'EOF'
http:
  routers:
    catchall:
      priority: -1000
EOF

  cat > "${dynamic_file}" <<'EOF'
http:
  routers:
    coolify-http:
      rule: Host(`vps.example.com`)
EOF

  cat > "${coolify_env_file}" <<'EOF'
PUSHER_HOST=ws.vps.example.com
PUSHER_PORT=443
PUSHER_SCHEME=https
EOF

  TUNNEL_MODE="true"
  TAILSCALE_IP=""
  CLOUDFLARED_CONFIG_FILE="${config_file}"
  COOLIFY_PRIVATE_ROUTE_FILE="${private_route_file}"
  COOLIFY_PROXY_COMPOSE_FILE="${compose_file}"
  COOLIFY_PROXY_DEFAULT_REDIRECT_FILE="${redirect_file}"
  COOLIFY_PROXY_DYNAMIC_FILE="${dynamic_file}"
  COOLIFY_ENV_FILE="${coolify_env_file}"

  systemctl() {
    if [[ "${1:-}" == "list-unit-files" ]]; then
      echo "cloudflared.service enabled"
      return 0
    fi
    if [[ "${1:-}" == "is-active" && "${2:-}" == "--quiet" ]]; then
      return 0
    fi
    if [[ "${1:-}" == "is-active" ]]; then
      echo "active"
      return 0
    fi
    return 0
  }

  command() {
    if [[ "${1:-}" == "-v" ]]; then
      case "${2:-}" in
        cloudflared|sysctl) return 0 ;;
        getent|dig|openssl|curl) return 1 ;;
      esac
    fi
    builtin command "$@"
  }

  sysctl() {
    if [[ "${1:-}" == "-n" && "${2:-}" == "net.ipv4.ping_group_range" ]]; then
      echo "0 2147483647"
      return 0
    fi
    command sysctl "$@"
  }

  pgrep() { return 1; }

  cloudflared_check
  local json
  json="$(emit_validate_results_json)"
  assert_json_check_status "${json}" "cloudflared: private TLS resolver present in Traefik command" "PASS"
  assert_json_check_status "${json}" "cloudflared: private TLS CA (zerossl) flags present" "PASS"

  rm -rf "${tempdir}"
}

@test "cloudflared_check: fails when private hosts still serve Traefik default cert" {
  local tempdir config_file private_route_file compose_file redirect_file dynamic_file coolify_env_file
  tempdir="$(mktemp -d)"
  config_file="${tempdir}/config.yml"
  private_route_file="${tempdir}/coolify-private-dashboard.yaml"
  compose_file="${tempdir}/docker-compose.yml"
  redirect_file="${tempdir}/default_redirect_503.yaml"
  dynamic_file="${tempdir}/coolify.yaml"
  coolify_env_file="${tempdir}/coolify.env"

  cat > "${config_file}" <<'EOF'
tunnel: test-tunnel
ingress:
  - hostname: "vps.example.com"
    service: http://localhost:80
  - hostname: "ws.vps.example.com"
    service: http_status:404
  - hostname: "vps.example.com"
    service: http_status:404
  - service: http_status:404
EOF

  cat > "${private_route_file}" <<'EOF'
http:
  middlewares:
    coolify-private-force-https:
      redirectScheme:
        scheme: https
  routers:
    coolify-private-dashboard-http:
      rule: "Host(`vps.example.com`)"
      service: noop@internal
      middlewares:
        - coolify-private-force-https
    coolify-private-dashboard-https:
      rule: "Host(`vps.example.com`)"
      tls:
        certResolver: privatedns
    coolify-private-realtime-http:
      rule: "Host(`ws.vps.example.com`)"
      service: noop@internal
      middlewares:
        - coolify-private-force-https
    coolify-private-realtime-https:
      rule: "Host(`ws.vps.example.com`)"
      tls:
        certResolver: privatedns
    coolify-private-terminal-http:
      rule: "Host(`ws.vps.example.com`) && PathPrefix(`/terminal/ws`)"
      service: noop@internal
      middlewares:
        - coolify-private-force-https
    coolify-private-terminal-https:
      rule: "Host(`ws.vps.example.com`) && PathPrefix(`/terminal/ws`)"
      tls:
        certResolver: privatedns
EOF

  cat > "${compose_file}" <<'EOF'
services:
  traefik:
    command:
      - '--certificatesresolvers.privatedns.acme.storage=/traefik/acme.json'
EOF

  cat > "${redirect_file}" <<'EOF'
http:
  routers:
    catchall:
      priority: -1000
EOF

  cat > "${dynamic_file}" <<'EOF'
http:
  routers:
    coolify-http:
      rule: Host(`vps.example.com`)
EOF

  cat > "${coolify_env_file}" <<'EOF'
PUSHER_HOST=ws.vps.example.com
PUSHER_PORT=443
PUSHER_SCHEME=https
EOF

  TUNNEL_MODE="true"
  TAILSCALE_IP=""
  CLOUDFLARED_CONFIG_FILE="${config_file}"
  COOLIFY_PRIVATE_ROUTE_FILE="${private_route_file}"
  COOLIFY_PROXY_COMPOSE_FILE="${compose_file}"
  COOLIFY_PROXY_DEFAULT_REDIRECT_FILE="${redirect_file}"
  COOLIFY_PROXY_DYNAMIC_FILE="${dynamic_file}"
  COOLIFY_ENV_FILE="${coolify_env_file}"

  systemctl() {
    if [[ "${1:-}" == "list-unit-files" ]]; then
      echo "cloudflared.service enabled"
      return 0
    fi
    if [[ "${1:-}" == "is-active" && "${2:-}" == "--quiet" ]]; then
      return 0
    fi
    if [[ "${1:-}" == "is-active" ]]; then
      echo "active"
      return 0
    fi
    return 0
  }

  command() {
    if [[ "${1:-}" == "-v" ]]; then
      case "${2:-}" in
        cloudflared|sysctl|openssl|curl) return 0 ;;
        getent|dig) return 1 ;;
      esac
    fi
    builtin command "$@"
  }

  openssl() {
    if [[ "${1:-}" == "s_client" ]]; then
      cat <<'EOF'
CONNECTED
EOF
      return 0
    fi
    if [[ "${1:-}" == "x509" ]]; then
      cat <<'EOF'
subject=CN = TRAEFIK DEFAULT CERT
issuer=CN = TRAEFIK DEFAULT CERT
X509v3 Subject Alternative Name:
    DNS:vps.example.com, DNS:ws.vps.example.com
EOF
      return 0
    fi
    command openssl "$@"
  }

  curl() {
    local url="${@: -1}"
    case "${url}" in
      "http://vps.example.com") echo "302" ; return 0 ;;
      "https://vps.example.com/api/v1/health") echo "000" ; return 0 ;;
      "http://ws.vps.example.com") echo "302" ; return 0 ;;
      "https://ws.vps.example.com/") echo "000" ; return 0 ;;
    esac
    command curl "$@"
  }

  sysctl() {
    if [[ "${1:-}" == "-n" && "${2:-}" == "net.ipv4.ping_group_range" ]]; then
      echo "0 2147483647"
      return 0
    fi
    command sysctl "$@"
  }

  pgrep() { return 1; }

  cloudflared_check
  local json
  json="$(emit_validate_results_json)"
  assert_json_check_status "${json}" "cloudflared: private TLS resolver present in Traefik command" "FAIL"
  assert_json_check_status "${json}" "cloudflared: dashboard host served TLS cert" "FAIL"
  assert_json_check_status "${json}" "cloudflared: websocket host served TLS cert" "FAIL"
  assert_json_check_status "${json}" "cloudflared: private dashboard HTTP redirect verified" "PASS"
  assert_json_check_status "${json}" "cloudflared: private dashboard HTTPS health verified" "FAIL"
  assert_json_check_status "${json}" "cloudflared: private websocket HTTP redirect verified" "PASS"
  assert_json_check_status "${json}" "cloudflared: private websocket HTTPS route verified" "FAIL"
  assert_json_fail_count "${json}" "5"

  rm -rf "${tempdir}"
}

@test "docker_user_check: fails fast when iptables is unavailable" {
  command() {
    if [[ "$1" == "-v" && "$2" == "iptables" ]]; then
      return 1
    fi
    builtin command "$@"
  }

  docker_user_check
  local json
  json="$(emit_validate_results_json)"
  assert_json_check_status "${json}" "docker-user: iptables" "FAIL"
  assert_json_fail_count "${json}" "1"
}

@test "docker_user_check: records info when docker service is unavailable and apply was deferred" {
  DOCKER_RULES_APPLIED="false"

  command() {
    if [[ "$1" == "-v" ]]; then
      case "$2" in
        iptables|docker|systemctl) return 0 ;;
      esac
    fi
    builtin command "$@"
  }
  docker() { return 0; }
  systemctl() {
    if [[ "$1" == "list-unit-files" ]]; then
      printf 'UNIT FILE STATE\n'
      return 0
    fi
    return 0
  }
  iptables() {
    echo "iptables should be skipped for deferred docker rules" >&2
    return 99
  }

  docker_user_check
  local json
  json="$(emit_validate_results_json)"
  assert_json_check_status "${json}" "docker-user: IPv4" "INFO"
  assert_json_fail_count "${json}" "0"
}

@test "docker_user_check: records PASS when managed rules are present and tunnel mode has no wan-web bypass" {
  TUNNEL_MODE="true"
  DOCKER_RULES_APPLIED="true"

  command() {
    if [[ "${1:-}" == "-v" ]]; then
      case "${2:-}" in
        iptables|docker|systemctl) return 0 ;;
        ip6tables) return 1 ;;
      esac
    fi
    builtin command "$@"
  }

  docker() {
    if [[ "${1:-}" == "info" ]]; then
      echo "iptables: true"
      return 0
    fi
    return 0
  }

  systemctl() {
    if [[ "${1:-}" == "list-unit-files" ]]; then
      echo "docker.service enabled"
      return 0
    fi
    return 0
  }

  iptables() {
    if [[ "${1:-}" == "-t" && "${2:-}" == "filter" && "${3:-}" == "-S" && "${4:-}" == "DOCKER-USER" ]]; then
      cat <<'EOF'
-N DOCKER-USER
-A DOCKER-USER -m comment --comment coolify-hardening-wan-drop -j DROP
-A DOCKER-USER -m comment --comment coolify-hardening-bridge-docker0 -j RETURN
EOF
      return 0
    fi
    return 0
  }

  docker_user_check
  local json
  json="$(emit_validate_results_json)"
  assert_json_check_status "${json}" "docker-user: IPv4 wan-drop" "PASS"
  assert_json_check_status "${json}" "docker-user: IPv4 bridge-docker0" "PASS"
  assert_json_check_status "${json}" "docker-user: tunnel-mode no wan-web" "PASS"
  assert_json_fail_count "${json}" "0"
}

@test "docker_user_lifecycle_check: records info when Docker is not installed" {
  command() {
    if [[ "$1" == "-v" && "$2" == "docker" ]]; then
      return 1
    fi
    builtin command "$@"
  }

  docker_user_lifecycle_check
  local json
  json="$(emit_validate_results_json)"
  assert_json_check_status "${json}" "docker-user: unit file" "INFO"
  assert_json_fail_count "${json}" "0"
}

@test "docker_user_lifecycle_check: records PASS when unit wiring and lifecycle are valid" {
  local unit_file="/etc/systemd/system/docker-user-hardening.service"
  local backup=""
  local had_unit="false"

  mkdir -p "/etc/systemd/system" 2>/dev/null || skip "unable to create /etc/systemd/system"
  if [[ -f "${unit_file}" ]]; then
    had_unit="true"
    backup="$(mktemp)"
    cp "${unit_file}" "${backup}"
  fi

  cat > "${unit_file}" <<'EOF'
[Unit]
Description=docker user hardening
PartOf=docker.service

[Service]
Type=oneshot
ExecStart=/bin/true

[Install]
WantedBy=docker.service
EOF

  systemctl() {
    if [[ "${1:-}" == "show" && "${2:-}" == "docker-user-hardening.service" ]]; then
      case "${3:-}" in
        --property=ActiveState)
          echo inactive
          return 0
          ;;
        --property=Result)
          echo success
          return 0
          ;;
      esac
    fi
    return 0
  }

  docker_user_lifecycle_check
  local json
  json="$(emit_validate_results_json)"
  assert_json_check_status "${json}" "docker-user: PartOf=docker.service" "PASS"
  assert_json_check_status "${json}" "docker-user: WantedBy=docker.service" "PASS"
  assert_json_check_status "${json}" "docker-user: service completed successfully" "PASS"
  assert_json_fail_count "${json}" "0"

  if [[ "${had_unit}" == "true" ]]; then
    cp "${backup}" "${unit_file}"
  else
    rm -f "${unit_file}"
  fi
  rm -f "${backup}"
}

@test "docker_ssh_cidr_sync_check: records PASS when strict mode timer/service are healthy" {
  local sync_script
  sync_script="$(mktemp)"
  cat > "${sync_script}" <<'EOF'
#!/usr/bin/env bash
normalize_cidr() { :; }
EOF
  chmod 755 "${sync_script}"

  STRICT_DOCKER_SSH_CIDRS="true"
  DOCKER_SSH_CIDRS="172.20.0.0/16"
  DOCKER_SSH_CIDR_SYNC_SCRIPT="${sync_script}"
  DOCKER_SSH_CIDR_SYNC_SERVICE="docker-ssh-cidr-sync.service"
  DOCKER_SSH_CIDR_SYNC_TIMER="docker-ssh-cidr-sync.timer"

  command() {
    if [[ "${1:-}" == "-v" && "${2:-}" == "docker" ]]; then
      return 0
    fi
    builtin command "$@"
  }

  docker() { return 0; }

  systemctl() {
    if [[ "${1:-}" == "is-active" && "${2:-}" == "--quiet" && "${3:-}" == "docker-ssh-cidr-sync.timer" ]]; then
      return 0
    fi
    if [[ "${1:-}" == "show" && "${2:-}" == "docker-ssh-cidr-sync.service" && "${3:-}" == "--property=ActiveState" ]]; then
      echo inactive
      return 0
    fi
    if [[ "${1:-}" == "show" && "${2:-}" == "docker-ssh-cidr-sync.service" && "${3:-}" == "--property=Result" ]]; then
      echo success
      return 0
    fi
    return 1
  }

  docker_ssh_cidr_sync_check
  local json
  json="$(emit_validate_results_json)"
  assert_json_check_status "${json}" "docker-ssh-cidr-sync: CIDR normalization" "PASS"
  assert_json_check_status "${json}" "docker-ssh-cidr-sync: timer active" "PASS"
  assert_json_check_status "${json}" "docker-ssh-cidr-sync: service completed successfully" "PASS"
  assert_json_check_status "${json}" "docker-ssh-cidr-sync: compatibility fallback cleared" "PASS"
  assert_json_fail_count "${json}" "0"

  rm -f "${sync_script}"
}

@test "docker_ssh_cidr_sync_check: fails when strict mode still uses broad compatibility CIDRs after Docker install" {
  local sync_script
  sync_script="$(mktemp)"
  cat > "${sync_script}" <<'EOF'
#!/usr/bin/env bash
normalize_cidr() { :; }
EOF
  chmod 755 "${sync_script}"

  STRICT_DOCKER_SSH_CIDRS="true"
  DOCKER_SSH_CIDRS="10.0.0.0/8,172.16.0.0/12"
  DOCKER_SSH_CIDR_SYNC_SCRIPT="${sync_script}"
  DOCKER_SSH_CIDR_SYNC_SERVICE="docker-ssh-cidr-sync.service"
  DOCKER_SSH_CIDR_SYNC_TIMER="docker-ssh-cidr-sync.timer"

  command() {
    if [[ "${1:-}" == "-v" && "${2:-}" == "docker" ]]; then
      return 0
    fi
    builtin command "$@"
  }

  docker() { return 0; }

  systemctl() {
    if [[ "${1:-}" == "is-active" && "${2:-}" == "--quiet" && "${3:-}" == "docker-ssh-cidr-sync.timer" ]]; then
      return 0
    fi
    if [[ "${1:-}" == "show" && "${2:-}" == "docker-ssh-cidr-sync.service" && "${3:-}" == "--property=ActiveState" ]]; then
      echo inactive
      return 0
    fi
    if [[ "${1:-}" == "show" && "${2:-}" == "docker-ssh-cidr-sync.service" && "${3:-}" == "--property=Result" ]]; then
      echo success
      return 0
    fi
    return 1
  }

  docker_ssh_cidr_sync_check
  local json
  json="$(emit_validate_results_json)"
  assert_json_check_status "${json}" "docker-ssh-cidr-sync: compatibility fallback cleared" "FAIL"
  assert_json_fail_count "${json}" "1"

  rm -f "${sync_script}"
}

@test "docker_ssh_cidr_sync_check: fails when normalization is missing and service is failing" {
  local sync_script
  sync_script="$(mktemp)"
  cat > "${sync_script}" <<'EOF'
#!/usr/bin/env bash
echo legacy
EOF
  chmod 755 "${sync_script}"

  STRICT_DOCKER_SSH_CIDRS="true"
  DOCKER_SSH_CIDR_SYNC_SCRIPT="${sync_script}"
  DOCKER_SSH_CIDR_SYNC_SERVICE="docker-ssh-cidr-sync.service"
  DOCKER_SSH_CIDR_SYNC_TIMER="docker-ssh-cidr-sync.timer"

  systemctl() {
    if [[ "${1:-}" == "is-active" && "${2:-}" == "--quiet" && "${3:-}" == "docker-ssh-cidr-sync.timer" ]]; then
      return 1
    fi
    if [[ "${1:-}" == "list-unit-files" ]]; then
      echo "docker-ssh-cidr-sync.timer enabled"
      return 0
    fi
    if [[ "${1:-}" == "show" && "${2:-}" == "docker-ssh-cidr-sync.service" && "${3:-}" == "--property=ActiveState" ]]; then
      echo inactive
      return 0
    fi
    if [[ "${1:-}" == "show" && "${2:-}" == "docker-ssh-cidr-sync.service" && "${3:-}" == "--property=Result" ]]; then
      echo exit-code
      return 0
    fi
    return 1
  }

  docker_ssh_cidr_sync_check
  local json
  json="$(emit_validate_results_json)"
  assert_json_check_status "${json}" "docker-ssh-cidr-sync: CIDR normalization" "FAIL"
  assert_json_check_status "${json}" "docker-ssh-cidr-sync: timer active" "FAIL"
  assert_json_check_status "${json}" "docker-ssh-cidr-sync: service result" "FAIL"
  assert_json_fail_count "${json}" "3"

  rm -f "${sync_script}"
}

@test "docker_user_lifecycle_check: records info in gate-c mode when Docker hardening was not expected" {
  GATE_C_MODE="true"
  DOCKER_PRESENT="false"
  DOCKER_RULES_APPLIED="false"

  command() {
    if [[ "${1:-}" == "-v" && "${2:-}" == "docker" ]]; then
      return 0
    fi
    builtin command "$@"
  }

  docker_user_lifecycle_check
  local json
  json="$(emit_validate_results_json)"
  assert_json_check_status "${json}" "docker-user: unit file" "INFO"
  assert_json_fail_count "${json}" "0"
}

@test "docker_daemon_check: records info in gate-c mode when Docker hardening was not expected" {
  GATE_C_MODE="true"
  DOCKER_PRESENT="false"
  DOCKER_RULES_APPLIED="false"

  command() {
    if [[ "${1:-}" == "-v" && "${2:-}" == "docker" ]]; then
      return 0
    fi
    builtin command "$@"
  }

  docker_daemon_check
  local json
  json="$(emit_validate_results_json)"
  assert_json_check_status "${json}" "docker-daemon: daemon.json" "INFO"
  assert_json_fail_count "${json}" "0"
}

@test "docker_hardening_expected: gate-c requires state-based Docker hardening signal" {
  GATE_C_MODE="true"
  DOCKER_PRESENT="false"
  DOCKER_RULES_APPLIED="false"

  command() {
    if [[ "${1:-}" == "-v" && "${2:-}" == "docker" ]]; then
      return 0
    fi
    builtin command "$@"
  }

  run docker_hardening_expected
  [ "${status}" -eq 1 ]

  DOCKER_PRESENT="true"
  run docker_hardening_expected
  assert_success
}

@test "docker_ssh_cidr_sync_check: defers compatibility fallback enforcement in gate-c mode until Docker was hardened" {
  local sync_script
  sync_script="$(mktemp)"
  cat > "${sync_script}" <<'EOF'
#!/usr/bin/env bash
normalize_cidr() { :; }
EOF
  chmod 755 "${sync_script}"

  GATE_C_MODE="true"
  DOCKER_PRESENT="false"
  DOCKER_RULES_APPLIED="false"
  STRICT_DOCKER_SSH_CIDRS="true"
  DOCKER_SSH_CIDRS="10.0.0.0/8,172.16.0.0/12"
  DOCKER_SSH_CIDR_SYNC_SCRIPT="${sync_script}"
  DOCKER_SSH_CIDR_SYNC_SERVICE="docker-ssh-cidr-sync.service"
  DOCKER_SSH_CIDR_SYNC_TIMER="docker-ssh-cidr-sync.timer"

  command() {
    if [[ "${1:-}" == "-v" && "${2:-}" == "docker" ]]; then
      return 0
    fi
    builtin command "$@"
  }

  systemctl() {
    if [[ "${1:-}" == "is-active" && "${2:-}" == "--quiet" && "${3:-}" == "docker-ssh-cidr-sync.timer" ]]; then
      return 0
    fi
    if [[ "${1:-}" == "show" && "${2:-}" == "docker-ssh-cidr-sync.service" && "${3:-}" == "--property=ActiveState" ]]; then
      echo inactive
      return 0
    fi
    if [[ "${1:-}" == "show" && "${2:-}" == "docker-ssh-cidr-sync.service" && "${3:-}" == "--property=Result" ]]; then
      echo success
      return 0
    fi
    return 1
  }

  docker_ssh_cidr_sync_check
  local json
  json="$(emit_validate_results_json)"
  assert_json_check_missing "${json}" "docker-ssh-cidr-sync: compatibility fallback cleared"
  assert_json_fail_count "${json}" "0"

  rm -f "${sync_script}"
}

@test "fail2ban_check: records fail/info when fail2ban is absent" {
  systemctl() { return 1; }
  fail2ban_check
  local json
  json="$(emit_validate_results_json)"
  assert_json_check_status "${json}" "fail2ban: active" "FAIL"
  assert_json_fail_count "${json}" "1"
}

@test "fail2ban_check: records PASS when service, jail, ignoreip, and backend are healthy" {
  local jail_file="/etc/fail2ban/jail.d/coolify-hardening.local"
  local jail_backup=""
  local had_jail="false"

  mkdir -p "/etc/fail2ban/jail.d" 2>/dev/null || skip "unable to create /etc/fail2ban/jail.d"
  if [[ -f "${jail_file}" ]]; then
    had_jail="true"
    jail_backup="$(mktemp)"
    cp "${jail_file}" "${jail_backup}"
  fi

  cat > "${jail_file}" <<'EOF'
[DEFAULT]
ignoreip = 127.0.0.1/8 100.64.0.0/10
banaction = iptables-multiport
EOF

  TAILSCALE_CIDR="100.64.0.0/10"

  systemctl() {
    if [[ "${1:-}" == "is-active" && "${2:-}" == "--quiet" && "${3:-}" == "fail2ban" ]]; then
      return 0
    fi
    return 0
  }

  fail2ban-client() {
    if [[ "${1:-}" == "status" && "${2:-}" == "sshd" ]]; then
      return 0
    fi
    return 1
  }

  iptables() {
    if [[ "${1:-}" == "-L" && "${2:-}" == "f2b-sshd" ]]; then
      return 0
    fi
    return 0
  }

  fail2ban_check
  local json
  json="$(emit_validate_results_json)"
  assert_json_check_status "${json}" "fail2ban: active" "PASS"
  assert_json_check_status "${json}" "fail2ban: sshd jail enabled" "PASS"
  assert_json_check_status "${json}" "fail2ban: ignoreip includes Tailscale CIDR" "PASS"
  assert_json_check_status "${json}" "fail2ban: f2b-sshd iptables chain present" "PASS"
  assert_json_fail_count "${json}" "0"

  if [[ "${had_jail}" == "true" ]]; then
    cp "${jail_backup}" "${jail_file}"
  else
    rm -f "${jail_file}"
  fi
  rm -f "${jail_backup}"
}

@test "fail2ban_check: parses banaction with spaces and inline comment" {
  local jail_file="/etc/fail2ban/jail.d/coolify-hardening.local"
  local jail_backup=""
  local had_jail="false"

  mkdir -p "/etc/fail2ban/jail.d" 2>/dev/null || skip "unable to create /etc/fail2ban/jail.d"
  if [[ -f "${jail_file}" ]]; then
    had_jail="true"
    jail_backup="$(mktemp)"
    cp "${jail_file}" "${jail_backup}"
  fi

  cat > "${jail_file}" <<'EOF'
[DEFAULT]
ignoreip = 127.0.0.1/8 100.64.0.0/10
banaction    =    ufw   # required in this environment
EOF

  TAILSCALE_CIDR="100.64.0.0/10"

  systemctl() {
    if [[ "${1:-}" == "is-active" && "${2:-}" == "--quiet" && "${3:-}" == "fail2ban" ]]; then
      return 0
    fi
    return 0
  }

  fail2ban-client() {
    if [[ "${1:-}" == "status" && "${2:-}" == "sshd" ]]; then
      return 0
    fi
    return 1
  }

  ufw() {
    if [[ "${1:-}" == "status" ]]; then
      echo "Status: active"
      return 0
    fi
    return 0
  }

  fail2ban_check
  local json
  json="$(emit_validate_results_json)"
  assert_json_check_status "${json}" "fail2ban: banaction=ufw and UFW active" "PASS"

  if [[ "${had_jail}" == "true" ]]; then
    cp "${jail_backup}" "${jail_file}"
  else
    rm -f "${jail_file}"
  fi
  rm -f "${jail_backup}"
}

@test "journald_check: records journald persistence posture" {
  JOURNALD_DROPIN="$(mktemp)"
  cat > "${JOURNALD_DROPIN}" <<'EOF'
[Journal]
Storage=persistent
SystemKeepFree=500M
EOF

  journald_check
  local json
  json="$(emit_validate_results_json)"
  assert_json_check_status "${json}" "journald: persistent storage config" "PASS"
  rm -f "${JOURNALD_DROPIN}"
}

@test "rsyslog_check: records PASS when log targets are writable and runtime is healthy" {
  stat() {
    if [[ "${1:-}" == "-c" && "${2:-}" == "%U" ]]; then echo root; return 0; fi
    if [[ "${1:-}" == "-c" && "${2:-}" == "%G" ]]; then echo syslog; return 0; fi
    if [[ "${1:-}" == "-c" && "${2:-}" == "%a" ]]; then echo 770; return 0; fi
    command stat "$@"
  }
  rsyslog_collect_log_targets() {
    printf '%s\n' "/var/log/ufw.log"
  }
  su() { return 0; }
  systemctl() {
    if [[ "${1:-}" == "is-active" && "${2:-}" == "--quiet" && "${3:-}" == "rsyslog" ]]; then
      return 0
    fi
    if [[ "${1:-}" == "show" && "${2:-}" == "-p" && "${3:-}" == "ActiveEnterTimestamp" ]]; then
      echo "2026-03-05 02:24:40"
      return 0
    fi
    return 0
  }
  journalctl() { return 0; }
  grep() {
    if [[ "$*" == *"/etc/logrotate.d/rsyslog"* || "$*" == *"/etc/logrotate.d/ufw"* ]]; then
      return 0
    fi
    command grep "$@"
  }

  rsyslog_check
  local json
  json="$(emit_validate_results_json)"
  assert_json_check_status "${json}" "rsyslog: /var/log owner/group" "PASS"
  assert_json_check_status "${json}" "rsyslog: /var/log group-write enabled" "PASS"
  assert_json_check_status "${json}" "rsyslog: logrotate create directive" "PASS"
  assert_json_check_status "${json}" "rsyslog: ufw logrotate create directive" "PASS"
  assert_json_check_status "${json}" "rsyslog: runtime log-write health" "PASS"
}

@test "rsyslog_check: records FAIL when /var/log is not group-writable and targets are missing" {
  stat() {
    if [[ "${1:-}" == "-c" && "${2:-}" == "%U" ]]; then echo root; return 0; fi
    if [[ "${1:-}" == "-c" && "${2:-}" == "%G" ]]; then echo syslog; return 0; fi
    if [[ "${1:-}" == "-c" && "${2:-}" == "%a" ]]; then echo 750; return 0; fi
    command stat "$@"
  }
  rsyslog_collect_log_targets() {
    printf '%s\n' "/var/log/missing.log"
  }
  systemctl() { return 1; }
  grep() { return 1; }

  rsyslog_check
  local json
  json="$(emit_validate_results_json)"
  assert_json_check_status "${json}" "rsyslog: /var/log group-write" "FAIL"
  assert_json_check_status "${json}" "rsyslog: target exists (/var/log/missing.log)" "FAIL"
  assert_json_check_status "${json}" "rsyslog: logrotate create directive" "FAIL"
  assert_json_check_status "${json}" "rsyslog: ufw logrotate create directive" "FAIL"
  assert_json_check_status "${json}" "rsyslog: service active" "FAIL"
}

@test "ssh_check: records PASS for expected hardened sshd output" {
  sshd() {
    if [[ "$1" == "-T" ]]; then
      cat <<SSHD
permitrootlogin no
passwordauthentication no
pubkeyauthentication yes
permitemptypasswords no
compression no
ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com
macs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
kexalgorithms sntrup761x25519-sha512@openssh.com,curve25519-sha256
hostkeyalgorithms ssh-ed25519,rsa-sha2-512,rsa-sha2-256
allowusers alice
SSHD
      return 0
    fi
    return 0
  }

  ADMIN_USER="alice"
  ssh_check
  local json
  json="$(emit_validate_results_json)"
  assert_json_check_status "${json}" "ssh: permitrootlogin=no" "PASS"
  assert_json_check_status "${json}" "ssh: passwordauthentication=no" "PASS"
}

@test "sysctl_check: records PASS when expected values are present" {
  sysctl() {
    if [[ "$1" == "-n" ]]; then
      case "$2" in
        net.ipv4.tcp_syncookies|net.ipv4.ip_forward|fs.protected_hardlinks|fs.protected_symlinks|kernel.kptr_restrict|kernel.dmesg_restrict|kernel.unprivileged_bpf_disabled|net.ipv4.conf.all.accept_source_route|net.ipv4.conf.default.accept_source_route|net.ipv4.conf.all.accept_redirects|net.ipv4.conf.default.accept_redirects|net.ipv4.conf.all.secure_redirects|net.ipv4.conf.default.secure_redirects|net.ipv4.conf.all.send_redirects|net.ipv4.conf.default.send_redirects|net.ipv4.icmp_echo_ignore_broadcasts|net.ipv4.icmp_ignore_bogus_error_responses)
          echo 1 ;;
        kernel.perf_event_paranoid)
          echo 3 ;;
        kernel.yama.ptrace_scope)
          echo 1 ;;
        vm.swappiness)
          echo 10 ;;
        *)
          echo 1 ;;
      esac
      return 0
    fi
    return 0
  }

  sysctl_check
  local json
  json="$(emit_validate_results_json)"
  assert_json_check_status "${json}" "sysctl: net.ipv4.tcp_syncookies=1" "PASS"
  assert_json_check_status "${json}" "sysctl: vm.swappiness=10" "PASS"
}

@test "timesync_check: passes when timedatectl reports synchronized NTP" {
  timedatectl() {
    if [[ "$1" == "show" && "$2" == "--property=NTP" ]]; then
      echo yes
      return 0
    fi
    if [[ "$1" == "show" && "$2" == "--property=NTPSynchronized" ]]; then
      echo yes
      return 0
    fi
    return 0
  }

  timesync_check
  local json
  json="$(emit_validate_results_json)"
  assert_json_check_status "${json}" "timesync: NTP active" "PASS"
  assert_json_check_status "${json}" "timesync: NTPSynchronized" "PASS"
}

@test "timezone_check: passes when current timezone matches configured state" {
  CONFIGURED_TIMEZONE="Australia/Melbourne"
  timedatectl() {
    if [[ "$1" == "show" && "$2" == "--property=Timezone" ]]; then
      echo "Australia/Melbourne"
      return 0
    fi
    return 0
  }

  timezone_check
  local json
  json="$(emit_validate_results_json)"
  assert_json_check_status "${json}" "timezone: configured (Australia/Melbourne)" "PASS"
}

@test "timezone_check: fails when configured timezone does not match current timezone" {
  CONFIGURED_TIMEZONE="UTC"
  timedatectl() {
    if [[ "$1" == "show" && "$2" == "--property=Timezone" ]]; then
      echo "Australia/Melbourne"
      return 0
    fi
    return 0
  }

  timezone_check
  local json
  json="$(emit_validate_results_json)"
  assert_json_check_status "${json}" "timezone: configured (UTC)" "FAIL"
}

@test "timezone_check: records INFO instead of FAIL when timedatectl is unavailable" {
  CONFIGURED_TIMEZONE=""
  command() {
    if [[ "${1:-}" == "-v" && "${2:-}" == "timedatectl" ]]; then
      return 1
    fi
    builtin command "$@"
  }

  timezone_check
  local json
  json="$(emit_validate_results_json)"
  assert_json_fail_count "${json}" "0"
}

@test "networkd_wait_online_check: passes when ifupdown is authoritative and apt-helper wait-online succeeds" {
  local apt_helper_mock
  apt_helper_mock="$(mktemp)"
  trap 'rm -f "${apt_helper_mock}"' RETURN
  cat > "${apt_helper_mock}" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
  chmod +x "${apt_helper_mock}"
  APT_HELPER_BIN="${apt_helper_mock}"

  ifupdown_is_authoritative() { return 0; }
  command() {
    if [[ "${1:-}" == "-v" && "${2:-}" == "timeout" ]]; then
      return 0
    fi
    builtin command "$@"
  }
  timeout() { shift; "$@"; }
  systemctl() {
    case "$*" in
      "show --property=LoadState --value systemd-networkd.socket"|\
      "show --property=LoadState --value systemd-networkd.service"|\
      "show --property=LoadState --value networkd-dispatcher.service"|\
      "show --property=LoadState --value networking.service")
        echo loaded
        return 0
        ;;
      "is-active systemd-networkd.socket"|\
      "is-active systemd-networkd.service"|\
      "is-active networkd-dispatcher.service")
        echo inactive
        return 0
        ;;
      "is-enabled systemd-networkd.socket"|\
      "is-enabled systemd-networkd.service"|\
      "is-enabled networkd-dispatcher.service")
        echo disabled
        return 0
        ;;
    esac
    return 1
  }

  networkd_wait_online_check
  local json
  json="$(emit_validate_results_json)"
  assert_json_check_status "${json}" "networkd-wait-online: ifupdown authoritative" "PASS"
  assert_json_check_status "${json}" "networkd-wait-online: stray systemd-networkd stack disabled" "PASS"
  assert_json_check_status "${json}" "networkd-wait-online: apt-helper wait-online succeeds" "PASS"
  assert_json_fail_count "${json}" "0"
}

@test "networkd_wait_online_check: fails when tuned networkd provider still fails apt-helper wait-online" {
  local apt_helper_mock
  apt_helper_mock="$(mktemp)"
  local dropin_backup=""
  local had_dropin="false"
  trap '
    if [[ "${had_dropin}" == "true" ]]; then
      cp "${dropin_backup}" "${NETWORKD_WAIT_ONLINE_DROPIN}" >/dev/null 2>&1 || true
      rm -f "${dropin_backup}"
    else
      rm -f "${NETWORKD_WAIT_ONLINE_DROPIN}"
    fi
    rm -f "${apt_helper_mock}"
  ' RETURN
  cat > "${apt_helper_mock}" <<'EOF'
#!/usr/bin/env bash
exit 1
EOF
  chmod +x "${apt_helper_mock}"
  APT_HELPER_BIN="${apt_helper_mock}"

  ifupdown_is_authoritative() { return 1; }
  command() {
    if [[ "${1:-}" == "-v" && "${2:-}" == "timeout" ]]; then
      return 0
    fi
    builtin command "$@"
  }
  timeout() { shift; "$@"; }
  systemctl() {
    case "$*" in
      "show --property=LoadState --value systemd-networkd-wait-online.service")
        echo loaded
        return 0
        ;;
      "show systemd-networkd-wait-online.service -p ExecStart --value")
        echo "/lib/systemd/systemd-networkd-wait-online --any --timeout=15"
        return 0
        ;;
    esac
    return 1
  }

  if [[ -f "${NETWORKD_WAIT_ONLINE_DROPIN}" ]]; then
    had_dropin="true"
    dropin_backup="$(mktemp)"
    cp "${NETWORKD_WAIT_ONLINE_DROPIN}" "${dropin_backup}"
  fi
  mkdir -p "$(dirname "${NETWORKD_WAIT_ONLINE_DROPIN}")"
  cat > "${NETWORKD_WAIT_ONLINE_DROPIN}" <<'EOF'
[Service]
ExecStart=
ExecStart=/lib/systemd/systemd-networkd-wait-online --any --timeout=15
EOF

  networkd_wait_online_check
  local json
  json="$(emit_validate_results_json)"
  assert_json_check_status "${json}" "networkd-wait-online: drop-in present (--any --timeout=15)" "PASS"
  assert_json_check_status "${json}" "networkd-wait-online: effective ExecStart tuned" "PASS"
  assert_json_check_status "${json}" "networkd-wait-online: apt-helper wait-online succeeds" "FAIL"
}

@test "tailscale_check: fails when tailscale interface is missing" {
  TAILSCALE_IFACE="tailscale0"

  ip() { return 1; }
  tailscale() { return 1; }

  tailscale_check
  local json
  json="$(emit_validate_results_json)"
  assert_json_check_status "${json}" "tailscale: tailscale0" "FAIL"
  assert_json_fail_count "${json}" "1"
}

@test "tailscale_check: records PASS when interface, BackendState, and IPv4 are present" {
  TAILSCALE_IFACE="tailscale0"

  ip() {
    if [[ "${1:-}" == "link" && "${2:-}" == "show" && "${3:-}" == "tailscale0" ]]; then
      return 0
    fi
    return 1
  }

  systemctl() { return 1; }

  command() {
    if [[ "${1:-}" == "-v" && "${2:-}" == "tailscale" ]]; then
      return 0
    fi
    builtin command "$@"
  }

  tailscale() {
    if [[ "${1:-}" == "status" && "${2:-}" == "--json" ]]; then
      echo '{"BackendState":"Running","Peer":[]}'
      return 0
    fi
    if [[ "${1:-}" == "ip" && "${2:-}" == "-4" ]]; then
      echo "100.64.0.2"
      return 0
    fi
    if [[ "${1:-}" == "debug" && "${2:-}" == "prefs" ]]; then
      echo '{"RunSSH":false}'
      return 0
    fi
    return 0
  }

  tailscale_check
  local json
  json="$(emit_validate_results_json)"
  assert_json_check_status "${json}" "tailscale: tailscale0 present" "PASS"
  assert_json_check_status "${json}" "tailscale: BackendState=Running" "PASS"
  assert_json_check_status "${json}" "tailscale: IPv4 assigned (100.64.0.2)" "PASS"
  assert_json_check_status "${json}" "tailscale: RunSSH=false" "PASS"
  assert_json_fail_count "${json}" "0"
}

@test "tailscale_check: retries transient unknown RunSSH reads before recording PASS" {
  TAILSCALE_IFACE="tailscale0"
  local old_path="${PATH}"
  local mock_dir
  local debug_counter_file
  mock_dir="$(mktemp -d)"
  debug_counter_file="$(mktemp)"
  printf '0\n' > "${debug_counter_file}"
  export TAILSCALE_DEBUG_COUNTER_FILE="${debug_counter_file}"
  PATH="${mock_dir}:${PATH}"

  ip() {
    if [[ "${1:-}" == "link" && "${2:-}" == "show" && "${3:-}" == "tailscale0" ]]; then
      return 0
    fi
    return 1
  }

  systemctl() { return 1; }

  cat > "${mock_dir}/tailscale" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [[ "${1:-}" == "status" && "${2:-}" == "--json" ]]; then
  echo '{"BackendState":"Running","Peer":[]}'
  exit 0
fi
if [[ "${1:-}" == "ip" && "${2:-}" == "-4" ]]; then
  echo "100.64.0.2"
  exit 0
fi
if [[ "${1:-}" == "debug" && "${2:-}" == "prefs" ]]; then
  count="$(<"${TAILSCALE_DEBUG_COUNTER_FILE}")"
  count=$((count + 1))
  printf '%s\n' "${count}" > "${TAILSCALE_DEBUG_COUNTER_FILE}"
  if (( count < 3 )); then
    echo '{}'
  else
    echo '{"RunSSH":false}'
  fi
  exit 0
fi
exit 0
EOF
  chmod +x "${mock_dir}/tailscale"

  cat > "${mock_dir}/sleep" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
  chmod +x "${mock_dir}/sleep"

  tailscale_check
  local json
  json="$(emit_validate_results_json)"
  assert_json_check_status "${json}" "tailscale: RunSSH=false" "PASS"
  assert_json_fail_count "${json}" "0"

  PATH="${old_path}"
  /bin/rm -rf "${mock_dir}"
  /bin/rm -f "${debug_counter_file}"
}

@test "tailscale_check: fails on alternate tailscaled notify warning wording" {
  TAILSCALE_IFACE="tailscale0"

  ip() {
    if [[ "${1:-}" == "link" && "${2:-}" == "show" && "${3:-}" == "tailscale0" ]]; then
      return 0
    fi
    return 1
  }

  command() {
    if [[ "${1:-}" == "-v" && ( "${2:-}" == "tailscale" || "${2:-}" == "journalctl" ) ]]; then
      return 0
    fi
    builtin command "$@"
  }

  systemctl() {
    if [[ "${1:-}" == "show" && "${2:-}" == "--property=LoadState" && "${3:-}" == "--value" && "${4:-}" == "tailscaled.service" ]]; then
      echo "loaded"
      return 0
    fi
    if [[ "${1:-}" == "show" && "${2:-}" == "tailscaled.service" && "${3:-}" == "-p" && "${4:-}" == "NotifyAccess" && "${5:-}" == "--value" ]]; then
      echo "all"
      return 0
    fi
    if [[ "${1:-}" == "show" && "${2:-}" == "tailscaled.service" && "${3:-}" == "-p" && "${4:-}" == "ActiveEnterTimestamp" && "${5:-}" == "--value" ]]; then
      echo "2026-03-05 02:24:40"
      return 0
    fi
    return 0
  }

  tailscale() {
    if [[ "${1:-}" == "status" && "${2:-}" == "--json" ]]; then
      echo '{"BackendState":"Running","Peer":[]}'
      return 0
    fi
    if [[ "${1:-}" == "ip" && "${2:-}" == "-4" ]]; then
      echo "100.64.0.2"
      return 0
    fi
    if [[ "${1:-}" == "debug" && "${2:-}" == "prefs" ]]; then
      echo '{"RunSSH":false}'
      return 0
    fi
    return 0
  }

  journalctl() {
    echo 'Cannot find unit for notify message of PID 123, ignoring.'
    return 0
  }

  tailscale_check
  local json
  json="$(emit_validate_results_json)"
  assert_json_check_status "${json}" "tailscale: no systemd notify warnings after last start" "FAIL"
  assert_json_check_detail_contains "${json}" "tailscale: no systemd notify warnings after last start" "found 1 warning"
}

@test "unattended_upgrades_check: fails when local policy file is missing" {
  unattended_upgrades_check
  local json
  json="$(emit_validate_results_json)"
  assert_json_check_status "${json}" "auto-updates: local config" "FAIL"
  assert_json_fail_count "${json}" "1"
}

@test "unattended_upgrades_check: records PASS for security-only profile with active timers" {
  local apt_local="/etc/apt/apt.conf.d/52unattended-upgrades-local"
  local apt_backup=""
  local had_apt_local="false"
  local override1="/etc/systemd/system/apt-daily.timer.d/override.conf"
  local override2="/etc/systemd/system/apt-daily-upgrade.timer.d/override.conf"
  local override1_backup=""
  local override2_backup=""
  local had_override1="false"
  local had_override2="false"

  mkdir -p "/etc/apt/apt.conf.d" 2>/dev/null || skip "unable to create /etc/apt/apt.conf.d"
  mkdir -p "/etc/systemd/system/apt-daily.timer.d" 2>/dev/null || skip "unable to create apt-daily timer override dir"
  mkdir -p "/etc/systemd/system/apt-daily-upgrade.timer.d" 2>/dev/null || skip "unable to create apt-daily-upgrade timer override dir"

  if [[ -f "${apt_local}" ]]; then
    had_apt_local="true"
    apt_backup="$(mktemp)"
    cp "${apt_local}" "${apt_backup}"
  fi
  if [[ -f "${override1}" ]]; then
    had_override1="true"
    override1_backup="$(mktemp)"
    cp "${override1}" "${override1_backup}"
  fi
  if [[ -f "${override2}" ]]; then
    had_override2="true"
    override2_backup="$(mktemp)"
    cp "${override2}" "${override2_backup}"
  fi

  cat > "${apt_local}" <<'EOF'
"origin=Ubuntu,codename=${distro_codename}-security,label=Ubuntu";
Unattended-Upgrade::Automatic-Reboot "false";
EOF

  cat > "${override1}" <<'EOF'
[Timer]
Persistent=false
EOF
  cat > "${override2}" <<'EOF'
[Timer]
Persistent=false
EOF

  UPDATE_PROFILE="security-only"
  systemctl() {
    if [[ "${1:-}" == "is-active" && "${2:-}" == "--quiet" ]]; then
      return 0
    fi
    return 1
  }

  unattended_upgrades_check
  local json
  json="$(emit_validate_results_json)"
  assert_json_check_status "${json}" "auto-updates: Ubuntu security origin covered" "PASS"
  assert_json_check_status "${json}" "auto-updates: Ubuntu updates origin excluded (security-only)" "PASS"
  assert_json_check_status "${json}" "auto-updates: Docker CE origin excluded (security-only)" "PASS"
  assert_json_check_status "${json}" "auto-updates: apt-daily.timer active" "PASS"
  assert_json_check_status "${json}" "auto-updates: apt-daily-upgrade.timer active" "PASS"
  assert_json_fail_count "${json}" "0"

  if [[ "${had_apt_local}" == "true" ]]; then
    cp "${apt_backup}" "${apt_local}"
  else
    rm -f "${apt_local}"
  fi

  if [[ "${had_override1}" == "true" ]]; then
    cp "${override1_backup}" "${override1}"
  else
    rm -f "${override1}"
  fi

  if [[ "${had_override2}" == "true" ]]; then
    cp "${override2_backup}" "${override2}"
  else
    rm -f "${override2}"
  fi

  rm -f "${apt_backup}" "${override1_backup}" "${override2_backup}"
}

@test "validate_timer_check: records timer state outcome" {
  systemctl() {
    if [[ "$1" == "is-enabled" ]]; then
      echo enabled
      return 0
    fi
    if [[ "$1" == "is-active" ]]; then
      return 0
    fi
    return 0
  }

  validate_timer_check
  local json
  json="$(emit_validate_results_json)"
  assert_json_check_status "${json}" "validate-timer: active" "PASS"
  assert_json_fail_count "${json}" "0"
}

@test "main: runs check pipeline and emits JSON summary" {
  parse_cli_args() { JSON_MODE="true"; }
  detect_container_runtime() { :; }
  load_state_context() { :; }
  ssh_check() { record "PASS" "ssh: ok"; }
  ufw_check() { record "PASS" "ufw: ok"; }
  docker_user_check() { record "PASS" "docker-user: ok"; }
  docker_user_lifecycle_check() { record "PASS" "docker-user-lifecycle: ok"; }
  sysctl_check() { record "PASS" "sysctl: ok"; }
  fail2ban_check() { record "PASS" "fail2ban: ok"; }
  auditd_check() { record "PASS" "auditd: ok"; }
  journald_check() { record "PASS" "journald: ok"; }
  timesync_check() { record "PASS" "timesync: ok"; }
  timezone_check() { record "PASS" "timezone: ok"; }
  swap_check() { record "INFO" "swap: skipped"; }
  banner_check() { record "PASS" "banner: ok"; }
  admin_sudo_check() { record "PASS" "sudo: ok"; }
  docker_daemon_check() { record "PASS" "daemon: ok"; }
  docker_trust_boundary_check() { record "PASS" "trust: ok"; }
  apparmor_check() { record "PASS" "apparmor: ok"; }
  disabled_services_check() { record "PASS" "services: ok"; }
  tailscale_check() { record "PASS" "tailscale: ok"; }
  coolify_binding_check() { record "PASS" "binding: ok"; }
  coolify_ssh_check() { record "PASS" "coolify ssh: ok"; }
  coolify_container_check() { record "PASS" "containers: ok"; }
  validate_timer_check() { record "PASS" "timer: ok"; }
  listening_ports_info() { record "INFO" "ports: info"; }
  cloudflared_check() { record "INFO" "cloudflared: info"; }

  run main
  assert_success
  assert_output --partial '"pass"'
}

@test "main: skips cloudflared runtime checks in gate-c mode" {
  parse_cli_args() { JSON_MODE="true"; GATE_C_MODE="true"; }
  detect_container_runtime() { :; }
  load_state_context() { :; }
  ssh_check() { record "PASS" "ssh: ok"; }
  ufw_check() { record "PASS" "ufw: ok"; }
  docker_user_check() { record "PASS" "docker-user: ok"; }
  docker_user_lifecycle_check() { record "PASS" "docker-user-lifecycle: ok"; }
  docker_ssh_cidr_sync_check() { record "PASS" "docker-ssh-cidr-sync: ok"; }
  docker_daemon_check() { record "PASS" "daemon: ok"; }
  docker_trust_boundary_check() { record "PASS" "trust: ok"; }
  sysctl_check() { record "PASS" "sysctl: ok"; }
  fail2ban_check() { record "PASS" "fail2ban: ok"; }
  auditd_check() { record "PASS" "auditd: ok"; }
  unattended_upgrades_check() { record "PASS" "updates: ok"; }
  reboot_required_check() { record "INFO" "reboot: ok"; }
  journald_check() { record "PASS" "journald: ok"; }
  rsyslog_check() { record "PASS" "rsyslog: ok"; }
  timesync_check() { record "PASS" "timesync: ok"; }
  timezone_check() { record "PASS" "timezone: ok"; }
  swap_check() { record "INFO" "swap: skipped"; }
  bootloader_check() { record "PASS" "bootloader: ok"; }
  banner_check() { record "PASS" "banner: ok"; }
  admin_sudo_check() { record "PASS" "sudo: ok"; }
  apparmor_check() { record "PASS" "apparmor: ok"; }
  disabled_services_check() { record "PASS" "services: ok"; }
  apport_check() { record "PASS" "apport: ok"; }
  cron_check() { record "PASS" "cron: ok"; }
  networkd_wait_online_check() { record "PASS" "networkd: ok"; }
  private_domain_hosts_check() { record "PASS" "hosts: ok"; }
  tailscale_check() { record "PASS" "tailscale: ok"; }
  coolify_binding_check() { record "PASS" "binding: ok"; }
  coolify_ssh_check() { record "FAIL" "coolify ssh: should skip"; }
  coolify_container_check() { record "FAIL" "containers: should skip"; }
  coolify_instance_settings_check() { record "FAIL" "settings: should skip"; }
  validate_timer_check() { record "PASS" "timer: ok"; }
  listening_ports_info() { record "INFO" "ports: info"; }
  cloudflared_check() { record "FAIL" "cloudflared: should skip"; }

  run main
  assert_success
  assert_output --partial 'gate-c: cloudflared checks'
  refute_output --partial 'cloudflared: should skip'
}

@test "apport_check: records disabled apport posture" {
  local defaults
  defaults="$(mktemp)"
  printf "enabled=0\n" > "${defaults}"
  APPORT_DEFAULT_FILE="${defaults}"

  systemctl() {
    if [[ "$1" == "list-unit-files" ]]; then
      echo "apport.service enabled"
      return 0
    fi
    if [[ "$1" == "is-active" ]]; then
      return 1
    fi
    if [[ "$1" == "is-enabled" ]]; then
      echo masked
      return 0
    fi
    return 0
  }

  apport_check
  local json
  json="$(emit_validate_results_json)"
  assert_json_check_status "${json}" "apport: enabled=0" "PASS"
  assert_json_check_status "${json}" "apport: service inactive" "PASS"
  assert_json_check_status "${json}" "apport: service disabled/masked (masked)" "PASS"
  assert_json_fail_count "${json}" "0"
  rm -f "${defaults}"
}

@test "bootloader_check: records info in container mode" {
  IS_CONTAINER="true"

  bootloader_check
  local json
  json="$(emit_validate_results_json)"
  assert_json_check_status "${json}" "bootloader: partition safety" "INFO"
  assert_json_fail_count "${json}" "0"
}

@test "cron_check: records normalized EXTRA_OPTS and clean journal" {
  unit_available() { return 0; }
  systemctl() {
    if [[ "$1" == "show" && "$2" == "cron.service" && "$3" == "-p" && "$4" == "Environment" ]]; then
      echo 'EXTRA_OPTS='
      return 0
    fi
    if [[ "$1" == "show" && "$2" == "cron.service" && "$3" == "-p" && "$4" == "ActiveEnterTimestamp" ]]; then
      echo 'Thu 2026-03-06 00:00:00 UTC'
      return 0
    fi
    return 0
  }
  journalctl() { return 0; }

  cron_check
  local json
  json="$(emit_validate_results_json)"
  assert_json_check_status "${json}" "cron: EXTRA_OPTS environment set" "PASS"
  assert_json_check_status "${json}" "cron: no EXTRA_OPTS unset warnings after last start" "PASS"
  assert_json_fail_count "${json}" "0"
}

@test "ifupdown_is_authoritative: callable when networking.service is present" {
  run bash -c '
    source "'"${VALIDATE_SCRIPT}"'"
    unit_available() { return 0; }
    ifupdown_is_authoritative || true
  '
  assert_success
}

@test "reboot_required_check: records pass when reboot is not required" {
  if [[ -f /run/reboot-required ]]; then
    skip "/run/reboot-required already present on runner"
  fi

  reboot_required_check
  local json
  json="$(emit_validate_results_json)"
  assert_json_check_status "${json}" "reboot: not required" "PASS"
  assert_json_fail_count "${json}" "0"
}

@test "resolve_root_disk: returns parent disk for root source" {
  findmnt() { echo /dev/vda1; }
  lsblk() { echo vda; }

  run resolve_root_disk
  assert_success
  assert_output "/dev/vda"
}

@test "tailscale_runssh_pref_value: returns parsed RunSSH preference" {
  tailscale() {
    if [[ "$1" == "debug" && "$2" == "prefs" ]]; then
      echo '{"RunSSH":false}'
      return 0
    fi
    return 1
  }

  run tailscale_runssh_pref_value 1 0
  assert_success
  assert_output "false"
}
