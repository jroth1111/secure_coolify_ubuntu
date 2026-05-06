configure_fail2ban() {
  write_file "${FAIL2BAN_LOCAL_FILE}" "0644" "root" "root" <<'EOF'
# Managed by bootstrap hardening
[Definition]
allowipv6 = auto
EOF

  write_file "${FAIL2BAN_JAIL_FILE}" "0644" "root" "root" <<EOF
# Managed by bootstrap hardening
[DEFAULT]
bantime = 1h
findtime = 10m
maxretry = 5
banaction = ufw
ignoreip = 127.0.0.1/8 ::1 ${TAILSCALE_CIDR}

[sshd]
enabled = true
port = ${SSH_PORT}
backend = systemd
maxretry = 3
bantime = 1h
EOF

  run systemctl enable --now fail2ban
  if ! is_true "${DRY_RUN}"; then
    run systemctl restart fail2ban
    wait_for_fail2ban_sshd_jail 15 2 \
      || die "fail2ban started but the sshd jail did not become active."
  fi
}
