# Ubuntu 24.04.4 Hardening Procedure for Coolify VPS

This procedure targets a dedicated Coolify host on Ubuntu `24.04.4 LTS` with:
- SSH restricted to `tailscale0`
- Public web ingress on `80/443` (or no inbound web when using `--tunnel-mode`)
- Automatic security updates with scheduled reboots

The script `bootstrap_hardening.sh` (v1.2.1) applies safe host-level baseline controls in this order:
1. Preflight checks and dependency install (including fail2ban)
2. NTP time synchronization verification
3. Swap file creation (configurable size, default 2G, OOM protection)
4. Disable unused network services (rpcbind, avahi-daemon, cups)
5. Admin account + SSH key enforcement
6. OpenSSH hardening drop-in + cipher/MAC/KexAlgorithm restrictions + Coolify localhost Match block + config validation
7. UFW baseline policy (tunnel-mode aware, Tailscale direct UDP)
8. Sysctl kernel hardening (BBR congestion control, SYN flood protection with backlog tuning, ICMP hardening, rp_filter, symlink/hardlink protection, ptrace restrictions, BPF restriction, kexec disable, SysRq restriction, full ASLR, suid_dumpable, swap tuning)
9. fail2ban SSH jail (banaction = ufw, ignoreip for localhost/::1)
10. DOCKER-USER chain hardening assets (IPv4 + IPv6, bridge rules, tunnel-mode aware)
11. Docker daemon log rotation (`daemon.json` with `local` driver, `live-restore`)
12. Journald persistence and configurable retention
13. Auditd baseline rules (identity, sudoers, Docker socket/config)
14. Unattended-upgrades policy
15. Login banner (`/etc/issue.net`)
16. Post-check verification (including AppArmor status warning) + report output

## Inputs

Required:
- `ADMIN_USER`: Linux admin username
- `ADMIN_PUBKEY`: SSH public key for `ADMIN_USER`

Optional:
- `WAN_IFACE` (auto-detected if unset)
- `SSH_PORT` (default `22`)
- `TAILSCALE_CIDR` (default `100.64.0.0/10`, informational)
- `TUNNEL_MODE` (default `false`) — when true, skips WAN 80/443 UFW and DOCKER-USER rules
- `SWAP_SIZE` (default `2G`, format `<N>G` or `<N>M`; `0` to skip swap creation)
- `ENABLE_AUTO_REBOOT` (default `true`)
- `AUTO_REBOOT_TIME` (default `03:30`)
- `JOURNAL_RETENTION` (default `3month`, any valid systemd time span)
- `DRY_RUN` (default `false`)
- `FORCE` (default `false`, required when overriding SSH-session safety gate)

## Run

Example command:

```bash
sudo ./bootstrap_hardening.sh \
  --admin-user coolifyadmin \
  --admin-pubkey "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... user@host" \
  --enable-auto-reboot true \
  --auto-reboot-time 03:30
```

With Cloudflare Tunnel (no inbound web ports):

```bash
sudo ./bootstrap_hardening.sh \
  --admin-user coolifyadmin \
  --admin-pubkey "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... user@host" \
  --tunnel-mode
```

Using an env file for automation:

```bash
# /etc/bootstrap-hardening.env (chmod 0600)
ADMIN_USER=coolifyadmin
ADMIN_PUBKEY="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... user@host"
TUNNEL_MODE=true
SSH_PORT=22

sudo ./bootstrap_hardening.sh --env-file /etc/bootstrap-hardening.env
```

CLI flags override env-file values. The env file uses the same variable names as environment variables.

With custom journal retention:

```bash
sudo ./bootstrap_hardening.sh \
  --admin-user coolifyadmin \
  --admin-pubkey "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... user@host" \
  --journal-retention 6month
```

Dry-run preview:

```bash
sudo ./bootstrap_hardening.sh \
  --admin-user coolifyadmin \
  --admin-pubkey "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... user@host" \
  --dry-run
```

## Tunnel Mode

When `--tunnel-mode` is set, the script assumes all web traffic arrives via an outbound tunnel (e.g. Cloudflare Tunnel). This means:
- **UFW**: No `80/tcp` or `443/tcp` ALLOW rules on the WAN interface. The VPS has zero inbound web ports open.
- **DOCKER-USER**: The `coolify-hardening-wan-web` ACCEPT rule is omitted. The WAN DROP rule remains, making Docker containers completely unreachable from WAN.
- **Tailscale UDP 41641**: Always allowed on WAN regardless of tunnel mode — enables direct peer-to-peer WireGuard connections instead of DERP relay fallback.

This eliminates the "direct-to-origin bypass" attack surface entirely.

## Outputs

- Main log: `/var/log/bootstrap-hardening.log`
- Verification report: `/var/log/bootstrap-hardening-report.json`
- State marker: `/var/lib/bootstrap-hardening/state`
- Sysctl drop-in: `/etc/sysctl.d/60-coolify-hardening.conf`
- fail2ban jail: `/etc/fail2ban/jail.d/coolify-hardening.local`
- Docker daemon config: `/etc/docker/daemon.json` (write-if-absent only)
- Login banner: `/etc/issue.net`

## Post-Run Verification

### Quick check with validate_hardening.sh

The companion script `validate_hardening.sh` runs all checks non-destructively:

```bash
sudo ./validate_hardening.sh          # Human-readable table
sudo ./validate_hardening.sh --json   # Machine-readable JSON
```

It reads `/var/lib/bootstrap-hardening/state` to determine tunnel mode, admin user, etc. Exits 0 if all checks pass, 1 if any fail. Safe to run from cron or during incident response.

### Manual checks

```bash
# SSH hardening (ciphers, MACs, algorithms) — default context
sudo sshd -T | egrep '^(port|permitrootlogin|passwordauthentication|permitemptypasswords|compression|ciphers|macs|kexalgorithms|hostkeyalgorithms|kbdinteractiveauthentication|pubkeyauthentication|authenticationmethods|allowusers) '

# SSH Match block — verify Coolify localhost root access (key-only)
sudo sshd -T -C addr=127.0.0.1,user=root,host=localhost,laddr=127.0.0.1 | grep permitrootlogin
# Expected: permitrootlogin prohibit-password

# SSH Match block — verify external root is still denied
sudo sshd -T -C addr=203.0.113.1,user=root,host=example.com,laddr=0.0.0.0 | grep permitrootlogin
# Expected: permitrootlogin no

# Firewall
sudo ufw status verbose
sudo iptables -t filter -S DOCKER-USER
sudo ip6tables -t filter -S DOCKER-USER

# Auditd (includes sudoers and docker rules)
sudo systemctl status auditd --no-pager
sudo auditctl -l

# Journald
sudo journalctl --disk-usage

# Sysctl kernel hardening (including CIS parameters + BBR + SYN backlog)
sudo sysctl net.ipv4.tcp_syncookies net.ipv4.ip_forward net.ipv4.conf.all.accept_redirects \
  net.ipv4.conf.all.rp_filter fs.protected_hardlinks fs.protected_symlinks \
  fs.suid_dumpable kernel.unprivileged_bpf_disabled kernel.kexec_load_disabled \
  kernel.sysrq kernel.randomize_va_space \
  net.ipv4.tcp_congestion_control net.core.default_qdisc \
  net.ipv4.tcp_max_syn_backlog net.ipv4.tcp_synack_retries

# Swap
free -m
swapon --show

# NTP
timedatectl status

# fail2ban (bans visible in ufw status)
sudo fail2ban-client status sshd
systemctl is-active fail2ban
sudo ufw status  # Shows fail2ban deny rules if any IPs banned

# Login banner
cat /etc/issue.net

# Disabled services
systemctl status rpcbind avahi-daemon cups 2>&1 | grep -E "masked|not-found"

# Docker daemon log rotation
cat /etc/docker/daemon.json

# AppArmor
sudo aa-status --enabled && echo "AppArmor enabled" || echo "AppArmor NOT enabled"

# Unattended upgrades
sudo systemctl status apt-daily-upgrade.timer --no-pager
```

### Expected outcomes

Standard mode:
- Root login disabled globally (`PermitRootLogin no`), but key-only root allowed from localhost/Docker bridge (`Match Address 127.0.0.1,::1,172.16.0.0/12` with `PermitRootLogin prohibit-password`) — required for Coolify self-management
- Password SSH disabled, empty passwords denied
- SSH ciphers restricted to chacha20-poly1305, aes256-gcm, aes128-gcm
- SSH MACs restricted to hmac-sha2-512-etm, hmac-sha2-256-etm
- SSH rule only on `tailscale0`
- Public `80/443` allowed on WAN interface
- Tailscale UDP `41641` allowed on WAN interface
- DOCKER-USER contains managed `coolify-hardening-*` rules (IPv4 + IPv6)
- DOCKER-USER includes bridge rules for container-to-container traffic
- Docker daemon configured with `local` log driver (10m x 3 rotation) and `live-restore` (write-if-absent; existing `daemon.json` preserved)
- Sysctl: `tcp_syncookies=1`, `ip_forward=1`, `rp_filter=2`, `protected_hardlinks=1`, `protected_symlinks=1`, `suid_dumpable=0`, `unprivileged_bpf_disabled=1`, `kexec_load_disabled=1`, `sysrq=4`, `randomize_va_space=2`, ICMP redirects disabled, `tcp_max_syn_backlog=2048`, `tcp_synack_retries=2`, `swappiness=10`
- BBR TCP congestion control active (if kernel supports `tcp_bbr` module), with `fq` qdisc
- Swap file active at `/swapfile` with `0600` permissions (default 2G, configurable via `--swap-size`)
- NTP time synchronization verified active
- fail2ban active with SSH jail enabled, bans visible in `ufw status`
- Audit rules loaded: identity, sudoers, sshd-config, Docker
- Journald persistent with configurable retention (default 3 months)
- AppArmor verified enabled (warning if disabled)
- Login banner present at `/etc/issue.net`
- Unused services (rpcbind, avahi, cups) masked

Tunnel mode (additional):
- No WAN `80/443` UFW rules present
- No `coolify-hardening-wan-web` DOCKER-USER ACCEPT rule (IPv4 or IPv6)
- WAN DROP rule still present — all inbound WAN traffic to Docker is blocked
