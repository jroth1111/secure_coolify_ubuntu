# Ubuntu 24.04.4 Hardening Procedure for Coolify VPS

This procedure targets a dedicated Coolify host on Ubuntu `24.04.4 LTS` with:
- SSH restricted to `tailscale0`
- Public web ingress on `80/443` (or no inbound web when using `--tunnel-mode`)
- Automatic security updates with scheduled reboots

The script `base/bootstrap.sh` (v1.2.4) applies 15 baseline controls in this order. (Note: These are logical control groups; the script's `main()` implements them via 31 function calls.)
1. Preflight checks and readiness verification (OS/root/session safety/interface detection/package prerequisites)
2. NTP time synchronization verification
3. Swap file creation (configurable size, default 2G, OOM protection)
4. Disable unused network services (rpcbind, avahi-daemon, cups)
5. Login banner (`/etc/issue.net`)
6. Admin account + SSH hardening (SSH key enforcement, OpenSSH drop-in, cipher/MAC/KexAlgorithm restrictions, Coolify localhost Match block, config validation)
7. Auditd baseline rules (identity, sudoers, Docker socket/config)
8. Sysctl kernel hardening (BBR congestion control, SYN flood protection with backlog tuning, ICMP hardening, rp_filter, symlink/hardlink protection, ptrace restrictions, BPF restriction, kexec disable, SysRq restriction, full ASLR, suid_dumpable, swap tuning)
9. UFW baseline policy (tunnel-mode aware, Tailscale direct UDP)
10. Docker daemon hardening (`daemon.json`: `json-file` driver/log rotation, `live-restore`, `default-ipc-mode=private`, `storage-driver=overlay2`, hardened `default-ulimits`; matches Coolify's expectation)
11. DOCKER-USER chain hardening assets (IPv4 + IPv6, bridge rules, tunnel-mode aware)
12. fail2ban SSH jail (banaction = ufw, ignoreip for localhost/::1)
13. Journald persistence and configurable retention
14. Unattended-upgrades policy
15. Post-check verification (including AppArmor status warning) + state/report output

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
- `ENABLE_AUTO_REBOOT` (default `false`)
- `AUTO_REBOOT_TIME` (default `03:30`)
- `UPDATE_PROFILE` (default `security-only`) — unattended-upgrades profile (`security-only` or `balanced`)
- `JOURNAL_RETENTION` (default `3month`, any valid systemd time span)
- `JOURNAL_MAX_USE` (default `2G`) — journald SystemMaxUse limit
- `UPGRADE_MAIL` (default empty) — email for unattended-upgrade failure notifications (`--upgrade-mail`)
- `DRY_RUN` (default `false`)
- `FORCE` (default `false`, required when overriding SSH-session safety gate)
- `INSTALL_TAILSCALE` (default `false`) — install Tailscale during hardening
- `TAILSCALE_AUTH_KEY` — Tailscale auth key (required when `INSTALL_TAILSCALE=true`)
- `TAILSCALE_DIRECT_WAN` (default `false`) — open WAN UDP 41641 for direct Tailscale paths
- `STRICT_DOCKER_SSH_CIDRS` (default `true`) — use discovered Docker bridge CIDRs for SSH/UFW allowlists (`false` uses broad compatibility CIDRs)
- `DOCKER_NPROC_HARD` (default `8192`) — Docker default `nproc` hard limit
- `DOCKER_NPROC_SOFT` (default `4096`) — Docker default `nproc` soft limit
- `INSECURE_ENV` (default `false`) — allow env files with loose permissions (not recommended)
- `BIND_DASHBOARD_TO_TAILSCALE` (default `false`) — install watchdog to re-enforce Tailscale-only UFW rules for management ports

## Run

Example command:

```bash
sudo ./base/bootstrap.sh \
  --admin-user coolifyadmin \
  --admin-pubkey "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... user@host" \
  --enable-auto-reboot true \
  --auto-reboot-time 03:30
```

With Cloudflare Tunnel (no inbound web ports):

```bash
sudo ./base/bootstrap.sh \
  --admin-user coolifyadmin \
  --admin-pubkey "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... user@host" \
  --tunnel-mode
```

Using an env file for automation:

```bash
# /etc/server-hardening.env (chmod 0600)
ADMIN_USER=coolifyadmin
ADMIN_PUBKEY="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... user@host"
TUNNEL_MODE=true
SSH_PORT=22

sudo ./base/bootstrap.sh --env-file /etc/server-hardening.env
```

CLI flags override env-file values. The env file uses the same variable names as environment variables.
`--env-file` is parsed as strict `KEY=VALUE` data and must be `0600`/`0400` unless `--insecure-env` is explicitly set.

With custom journal retention:

```bash
sudo ./base/bootstrap.sh \
  --admin-user coolifyadmin \
  --admin-pubkey "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... user@host" \
  --journal-retention 6month
```

Dry-run preview:

```bash
sudo ./base/bootstrap.sh \
  --admin-user coolifyadmin \
  --admin-pubkey "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... user@host" \
  --dry-run
```

## Tunnel Mode

When `--tunnel-mode` is set, the script assumes all web traffic arrives via an outbound tunnel (e.g. Cloudflare Tunnel). This means:
- **UFW**: No `80/tcp` or `443/tcp` ALLOW rules on the WAN interface. The VPS has zero inbound web ports open.
- **DOCKER-USER**: The `coolify-hardening-wan-web` ACCEPT rule is omitted. The WAN DROP rule remains, making Docker containers completely unreachable from WAN.
- **Tailscale UDP 41641**: Closed by default. Opt in with `TAILSCALE_DIRECT_WAN=true` (or `--tailscale-direct-wan`) to prefer direct peer-to-peer WireGuard paths over DERP relay fallback.

This eliminates the "direct-to-origin bypass" attack surface entirely.

## Outputs

- Main log: `/var/log/server-hardening.log`
- Verification report: `/var/log/server-hardening-report.json`
- State marker: `/var/lib/server-hardening/state`
- Sysctl drop-in: `/etc/sysctl.d/99-coolify-hardening.conf`
- fail2ban jail: `/etc/fail2ban/jail.d/coolify-hardening.local`
- Docker daemon config: `/etc/docker/daemon.json` (creates or merges with existing; hardening owns: `log-driver`, `log-opts`, `live-restore`, `default-ipc-mode`, `storage-driver`, `default-ulimits`)
- Login banner: `/etc/issue.net`

## Post-Run Verification

### Quick check with base/validate.sh

The companion script `base/validate.sh` runs all checks non-destructively:

```bash
sudo ./base/validate.sh          # Human-readable table
sudo ./base/validate.sh --json   # Machine-readable JSON
```

It reads `/var/lib/server-hardening/state` to determine tunnel mode, admin user, etc. Exits 0 if all checks pass, 1 if any fail. Safe to run from cron or during incident response.

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
- Tailscale UDP `41641` closed on WAN by default (allowed only when `TAILSCALE_DIRECT_WAN=true`)
- DOCKER-USER contains managed `coolify-hardening-*` rules (IPv4 + IPv6)
- DOCKER-USER includes bridge rules for container-to-container traffic
- `docker-user-hardening.service` configured with `PartOf=docker.service` + `WantedBy=docker.service` — rules automatically re-applied after any Docker daemon restart or security update
- Docker daemon configured with `json-file` log driver (10m x 3 rotation), `live-restore`, `default-ipc-mode=private`, `storage-driver=overlay2`, and hardened `default-ulimits` (`nofile`, `nproc`) (creates or merges with existing `daemon.json`; hardening owns these keys; Coolify may add `default-address-pools`)
- Sysctl: `tcp_syncookies=1`, `ip_forward=1`, `rp_filter=2`, `protected_hardlinks=1`, `protected_symlinks=1`, `suid_dumpable=0`, `unprivileged_bpf_disabled=2`, `kexec_load_disabled=1`, `sysrq=4`, `randomize_va_space=2`, ICMP redirects disabled, `tcp_max_syn_backlog=2048`, `tcp_synack_retries=2`, `swappiness=10`
- BBR TCP congestion control active (if kernel supports `tcp_bbr` module), with `fq` qdisc
- Swap file active at `/swapfile` with `0600` permissions (default 2G, configurable via `--swap-size`)
- NTP enabled and synchronized verified at hardening time
- fail2ban active with SSH jail enabled, bans visible in `ufw status`; `ignoreip` includes `100.64.0.0/10` (Tailscale CIDR) — prevents admin lockout from brute-force ban
- Audit rules loaded: identity, sudoers, sshd-config, Docker
- Journald persistent with configurable retention (default 3 months)
- AppArmor verified enabled (warning if disabled)
- Login banner present at `/etc/issue.net`
- Unattended-upgrades covers both Ubuntu security/updates **and** Docker CE packages (`origin=Docker,label=Docker CE`) — `docker-ce`, `containerd.io`, etc. receive security patches automatically
- `MinimalSteps` enabled — partial upgrade on power loss leaves packages in a consistent state
- Unused services (rpcbind, avahi, cups) masked
- `hardening-validate.timer` active — runs daily `base/validate.sh` to detect configuration drift

Split-horizon binding mode (additional, when `--bind-dashboard-to-tailscale`):
- `coolify-binding-guard.timer` active — runs `/usr/local/sbin/coolify-binding-guard.sh` every 5 minutes
- Guard re-applies and verifies UFW rules for ports `8000`, `6001`, and `6002` on `tailscale0` only

Tunnel mode (additional):
- No WAN `80/443` UFW rules present
- No `coolify-hardening-wan-web` DOCKER-USER ACCEPT rule (IPv4 or IPv6)
- WAN DROP rule still present — all inbound WAN traffic to Docker is blocked
