# AI Support Context — Coolify Hardening Stack

This document provides context for AI assistants (ChatGPT, Claude, Copilot, etc.) helping operators troubleshoot or modify a server hardened with `bootstrap_hardening.sh`.

**Paste this into your AI chat when asking for server help.**

---

## Architecture Summary

This server runs **Ubuntu 24.04** hardened for **Coolify** (self-hosted PaaS) with:

- **SSH access exclusively via Tailscale** (`tailscale0` interface). No SSH on public internet.
- **UFW** as the host firewall (deny incoming by default).
- **DOCKER-USER iptables chain** for container-level traffic control (IPv4 + IPv6).
- **fail2ban** with UFW ban action for SSH brute-force protection.
- **auditd** monitoring identity files, sudoers, SSH config, and Docker runtime.
- **journald** with persistent storage and configurable retention.
- **Unattended-upgrades** for automatic security patching.
- **BBR TCP congestion control** (if kernel supports it).
- **Swap file** for OOM protection (configurable, default 2G).
- **NTP synchronization** verified at boot.

## Key Files

| File | Purpose |
|------|---------|
| `/etc/ssh/sshd_config.d/00-coolify-hardening.conf` | SSH hardening drop-in (managed) |
| `/etc/sysctl.d/60-coolify-hardening.conf` | Kernel parameter hardening |
| `/etc/fail2ban/jail.d/coolify-hardening.local` | fail2ban SSH jail config |
| `/usr/local/sbin/docker-user-hardening.sh` | DOCKER-USER iptables rules script |
| `/etc/default/docker-user-hardening` | Environment for DOCKER-USER service |
| `/etc/systemd/system/docker-user-hardening.service` | Systemd unit for DOCKER-USER rules |
| `/etc/docker/daemon.json` | Docker log rotation + live-restore |
| `/etc/systemd/journald.conf.d/60-persistent.conf` | Journald persistence config |
| `/etc/audit/rules.d/60-coolify-baseline.rules` | Auditd baseline rules |
| `/var/lib/bootstrap-hardening/state` | Script state (version, settings) |
| `/var/log/bootstrap-hardening-report.json` | Last-run verification report |
| `/var/log/bootstrap-hardening.log` | Script execution log |

## Diagnostic Commands

```bash
# Overall health check
sudo ./validate_hardening.sh
sudo ./validate_hardening.sh --json

# SSH effective config
sudo sshd -T | grep -E '^(port|permitrootlogin|passwordauthentication|allowusers)'

# Firewall state
sudo ufw status verbose
sudo iptables -t filter -S DOCKER-USER
sudo ip6tables -t filter -S DOCKER-USER

# Audit rules
sudo auditctl -l

# fail2ban status
sudo fail2ban-client status sshd

# Sysctl values
sudo sysctl net.ipv4.tcp_congestion_control net.ipv4.tcp_syncookies net.ipv4.ip_forward

# Swap
free -m
swapon --show

# NTP
timedatectl status

# State file
cat /var/lib/bootstrap-hardening/state

# Report
cat /var/log/bootstrap-hardening-report.json
```

## Critical Safety Rules

When advising on this server, you **MUST** follow these rules:

### NEVER Do

- **NEVER suggest `iptables -F`** — this flushes the DOCKER-USER chain and removes all container-level protection. Docker will recreate its own chains but our managed hardening rules will be lost until the service restarts.
- **NEVER suggest opening SSH on a public interface** — SSH is Tailscale-only by design. Opening it publicly creates a lockout-prone attack surface.
- **NEVER suggest editing `/etc/ssh/sshd_config.d/00-coolify-hardening.conf` directly** — changes will be overwritten on next script run. Re-run `bootstrap_hardening.sh` with updated flags instead.
- **NEVER suggest `ufw disable`** without an immediate plan to re-enable — this drops all firewall protection including the DOCKER-USER chain coordination.
- **NEVER suggest `NOPASSWD:ALL`** in sudoers — this eliminates the last authentication barrier for compromised sessions.
- **NEVER suggest `set +e`** in hardening scripts — this silently hides failures in security-critical code.
- **NEVER suggest `rp_filter = 1`** (strict mode) — this breaks Docker asymmetric routing. The server correctly uses `rp_filter = 2` (loose).

### ALWAYS Do

- **ALWAYS recommend re-running `bootstrap_hardening.sh`** to change hardening configuration. The script is idempotent.
- **ALWAYS check Tailscale connectivity first** when diagnosing SSH issues (`tailscale status`, `tailscale ping <hostname>`).
- **ALWAYS check the DOCKER-USER chain** when diagnosing container connectivity issues, not just UFW.
- **ALWAYS verify with `validate_hardening.sh`** after making any manual changes.
- **ALWAYS check `/var/log/bootstrap-hardening.log`** for error context.

## Tunnel Mode

If the state file shows `tunnel_mode=true`, the server uses **Cloudflare Tunnel** (or similar outbound tunnel) for web traffic:
- No UFW rules for ports 80/443 on WAN.
- No DOCKER-USER ACCEPT rules for WAN web traffic.
- All web traffic arrives via the tunnel daemon, not direct public access.
- The only inbound WAN port is UDP 41641 for Tailscale direct connections.

## Coolify-Specific Notes

- Coolify connects to its own host as root via `localhost` / Docker bridge networks (`172.16.0.0/12`). The SSH `Match Address` block allows key-only root login from these addresses only.
- Docker's `local` log driver is used (not `json-file`) — it's faster and compressed.
- The `live-restore` Docker option keeps containers running during Docker daemon restarts.
- The `docker-user-hardening.service` runs at boot to reapply DOCKER-USER rules after Docker starts.
