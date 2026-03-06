# AI Support Context — Coolify Hardening Stack

This document provides context for AI assistants (ChatGPT, Claude, Copilot, etc.) helping operators troubleshoot or modify a server hardened with `bootstrap_hardening.sh`.

**Paste this into your AI chat when asking for server help.**

---

## Architecture Summary

This server runs **Ubuntu 24.04** hardened for **Coolify** (self-hosted PaaS) with:

- **SSH access exclusively via Tailscale** (`tailscale0` interface). No SSH on public internet.
- **UFW** as the host firewall (deny incoming by default).
- **DOCKER-USER iptables chain** for container-level traffic control (IPv4 + IPv6). Docker must use the iptables backend (not nftables).
- **fail2ban** with UFW ban action for SSH brute-force protection.
- **auditd** monitoring identity files, sudoers, SSH config, and Docker runtime.
- **journald** with persistent storage and configurable retention.
- **Unattended-upgrades** for automatic security patching.
- **BBR TCP congestion control** (if kernel supports it).
- **Swap file** for OOM protection (configurable, default 2G).
- **NTP synchronization** verified at boot.
- **Tunnel private-only profile (when enabled):** dashboard/realtime hostnames are blocked in cloudflared ingress and served privately via Tailscale-routed host DNS + managed Traefik routes.

## Key Files

| File | Purpose |
|------|---------|
| `/etc/ssh/sshd_config.d/00-coolify-hardening.conf` | SSH hardening drop-in (managed) |
| `/etc/sysctl.d/99-coolify-hardening.conf` | Kernel parameter hardening |
| `/etc/fail2ban/jail.d/coolify-hardening.local` | fail2ban SSH jail config |
| `/usr/local/sbin/docker-user-hardening.sh` | DOCKER-USER iptables rules script |
| `/etc/default/docker-user-hardening` | Environment for DOCKER-USER service |
| `/etc/systemd/system/docker-user-hardening.service` | Systemd unit for DOCKER-USER rules |
| `/etc/docker/daemon.json` | Docker hardening keys (`log-driver`, `log-opts`, `live-restore`, `default-ipc-mode`, `storage-driver`, `default-ulimits`) |
| `/etc/systemd/journald.conf.d/90-coolify-persistent.conf` | Journald persistence config |
| `/etc/audit/rules.d/60-coolify-baseline.rules` | Auditd baseline rules |
| `/usr/local/sbin/coolify-binding-guard.sh` | Optional watchdog script that re-applies management-port UFW rules on `tailscale0` |
| `/etc/systemd/system/coolify-binding-guard.timer` | Optional timer for the binding watchdog |
| `/etc/cloudflared/config.yml` | Tunnel ingress policy (must keep dashboard/realtime/terminal off public ingress in private-only mode) |
| `/data/coolify/proxy/dynamic/coolify-private-dashboard.yaml` | Managed private dashboard/realtime route file for Traefik |
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
sudo docker info | grep -iE 'iptables|firewall'

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

# Tunnel private-only posture (when tunnel_mode=true)
sudo systemctl status cloudflared --no-pager
sudo grep -E 'localhost:8000|localhost:6001|localhost:6002|http_status:404|ws\\.' /etc/cloudflared/config.yml
sudo test -f /data/coolify/proxy/dynamic/coolify-private-dashboard.yaml && echo "private route file present"
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
- **NEVER suggest Docker nftables backend** (`iptables=false` / `firewall=nftables`) — this breaks the DOCKER-USER iptables enforcement model used by these scripts.
- **NEVER suggest public cloudflared ingress to `localhost:8000`, `localhost:6001`, or `localhost:6002`** in private-only tunnel deployments.

### ALWAYS Do

- **ALWAYS recommend re-running `bootstrap_hardening.sh`** to change hardening configuration. The script is idempotent.
- **ALWAYS check Tailscale connectivity first** when diagnosing SSH issues (`tailscale status`, `tailscale ping <hostname>`).
- **ALWAYS check the DOCKER-USER chain** when diagnosing container connectivity issues, not just UFW.
- **ALWAYS verify with `validate_hardening.sh`** after making any manual changes.
- **ALWAYS check `/var/log/bootstrap-hardening.log`** for error context.
- **ALWAYS check cloudflared ingress + private route files** when debugging tunnel-mode dashboard/realtime behavior.

## Tunnel Mode

If the state file shows `tunnel_mode=true`, the server uses **Cloudflare Tunnel** (or similar outbound tunnel) for web traffic:
- No UFW rules for ports 80/443 on WAN.
- No DOCKER-USER ACCEPT rules for WAN web traffic.
- All web traffic arrives via the tunnel daemon, not direct public access.
- By default, there are no inbound WAN management/web ports; optional UDP 41641 can be enabled for direct Tailscale paths (`TAILSCALE_DIRECT_WAN=true`).
- Private dashboard/realtime behavior is enforced by:
  - cloudflared deny routes (`http_status:404`) for `DOMAIN` and `ws.DOMAIN`
  - managed private Traefik routes (HTTP + HTTPS) in `/data/coolify/proxy/dynamic/coolify-private-dashboard.yaml`
  - DNS-only `A` records for `DOMAIN` and `ws.DOMAIN` pointing to the server Tailscale IP
  - `PUSHER_HOST=ws.<domain>`, `PUSHER_PORT=443`, `PUSHER_SCHEME=https`

## Coolify-Specific Notes

- Coolify connects to its own host as root via `localhost` / Docker bridge networks (`172.16.0.0/12`). The SSH `Match Address` block allows key-only root login from these addresses only.
- Docker's `json-file` log driver is used (matches Coolify's expectation for compatibility) with rotation (10m x 3).
- The `live-restore` Docker option keeps containers running during Docker daemon restarts.
- The `docker-user-hardening.service` runs at boot to reapply DOCKER-USER rules after Docker starts.
- **daemon.json ownership:** Hardening owns `log-driver`, `log-opts`, `live-restore`, `default-ipc-mode`, `storage-driver`, and `default-ulimits`; Coolify may add `default-address-pools`.
- **Docker trust boundary:** named `docker` group members are not allowed. Validation treats any named member as a failure because Docker socket access is root-equivalent.
- **Strict Docker SSH CIDRs:** `STRICT_DOCKER_SSH_CIDRS=true` may temporarily use compatibility ranges before Docker exists, but after Docker install the sync service must replace them with discovered bridge CIDRs. Final validation fails if broad fallback CIDRs (`10.0.0.0/8`, `172.16.0.0/12`) remain.
- **Intentional daemon omissions:** the project does not force `no-new-privileges`, `userns-remap`, `icc=false`, or `userland-proxy=false` because those settings break supported Coolify workloads and host integration paths.
