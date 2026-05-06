configure_ssh_socket() {
  # Bind ssh.socket to Tailscale IP + localhost instead of 0.0.0.0:22.
  # Defense-in-depth: even if UFW is flushed, SSH is not exposed publicly.
  local socket_unit="/etc/systemd/system/ssh.socket"
  local ts_ip=""

  ts_ip="$(tailscale ip -4 2>/dev/null || true)"
  if [[ -z "${ts_ip}" ]]; then
    warn "Could not detect Tailscale IP; skipping ssh.socket binding."
    return 0
  fi

  if ! is_true "${DRY_RUN}"; then
    mkdir -p /etc/systemd/system/ssh.socket.d
    cat > /etc/systemd/system/ssh.socket.d/10-bind-tailscale.conf <<SOCKETEOF
[Socket]
# Override default ListenStream=0.0.0.0:22 — bind to Tailscale + localhost only
ListenStream=
ListenStream=${ts_ip}:22
ListenStream=127.0.0.1:22
ListenStream=[::1]:22
SOCKETEOF
    systemctl daemon-reload
    systemctl restart ssh.socket
    log "Bound ssh.socket to ${ts_ip}:22, 127.0.0.1:22, [::1]:22."
  else
    log "DRY-RUN: would bind ssh.socket to ${ts_ip}:22 and localhost."
  fi
}
