# Secure Coolify Ubuntu

Turn a fresh Ubuntu VPS into a **production-hardened Coolify server** in ~15 minutes.

[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Ubuntu](https://img.shields.io/badge/Ubuntu-24.04%20LTS-E95420?logo=ubuntu)](https://ubuntu.com/)
[![Coolify](https://img.shields.io/badge/Coolify-v4+-purple?logo=docker)](https://coolify.io/)
[![Shellcheck](https://img.shields.io/badge/ShellCheck-passed-brightgreen)](https://www.shellcheck.net/)
[![LLM Friendly](https://img.shields.io/badge/LLM-friendly-blue)](AGENTS.md)

---

## What is This?

**[Coolify](https://coolify.io/)** is an open-source self-hosting platform — deploy apps, databases, and services with a UI (like a self-hosted Heroku). This project **secures a Coolify server** from scratch.

**What you start with:** A fresh Ubuntu 24.04 VPS with root access.

**What you end with:**
- ✅ Coolify running with private management access (`http://<tailscale-ip>:8000`)
- ✅ SSH + dashboard only accessible via Tailscale VPN (no public attack surface)
- ✅ Automatic Cloudflare routing for app subdomains (mode-specific DNS/tunnel behavior)
- ✅ Hardened kernel, firewall, audit logging, and auto-updates

---

## Why This Project?

Deploying Coolify on a fresh VPS leaves significant security gaps: root SSH enabled, default firewall rules, no audit logging, and the Coolify dashboard exposed to the internet. This project closes those gaps with a defense-in-depth approach:

| Problem | Solution |
|---------|----------|
| Root SSH + password auth | Key-only SSH, admin user, root login disabled |
| No firewall policy | UFW default-deny, DOCKER-USER chain rules |
| Dashboard publicly accessible | Restrict management ports to `tailscale0` via UFW + private routes |
| No intrusion detection | Auditd rules for privileged operations, fail2ban |
| Kernel defaults | SYN cookies, ASLR, ptrace restrictions, BBR |
| Manual security patches | Unattended-upgrades with scheduled reboots |

**Result:** A hardened server where the only way to SSH or access the Coolify dashboard is through your Tailscale VPN — zero public attack surface on management interfaces.

---

## Architecture

```
                  Internet
                     │
              ┌──────┴──────┐
              │  Cloudflare  │  ← Universal SSL (*.example.com)
              │    Edge      │
              └──────┬──────┘
                     │
          ┌──────────┼──────────┐
          │ Tunnel   │ Standard │
          │ (default)│          │
          ▼          │          ▼
     outbound-only   │    ports 80/443
     connection      │    (firewalled)
          │          │          │
          └──────────┼──────────┘
                     │
              ┌──────┴──────┐
              │   Server    │
              │ ┌─────────┐ │
              │ │ Traefik  │ │  ← Host-header routing
              │ │ (Coolify)│ │
              │ └─────────┘ │
              │              │
              │ Tailscale ◄──┼── Admin SSH + Dashboard (100.x.x.x)
              │ (VPN)        │
              └──────────────┘
                No public SSH
                No public dashboard
```

---

## How It Works

The deployment runs in 5 phases:

```
Phase 1: Upload scripts & harden server (SSH as root → public IP)
          ↓
Phase 2: Gate checks (verify hardening passed, get Tailscale IP)
          ↓
Phase 3: Install Docker & Coolify
          ↓
Phase 4: Configure binding + Cloudflare DNS/Tunnel
          ↓
Phase 5: Final reachability + security verification
```

**Which script should I use?**

| Script | When to use | What it does |
|--------|-------------|--------------|
| `deploy.sh` | From your laptop, fresh VPS | Full automation: SSH in, harden, install Coolify, configure DNS |
| `setup.sh` | Already SSH'd into server | Same as deploy.sh but runs locally (no root password needed) |
| `base/bootstrap.sh` | You only want hardening, no Coolify | Just the 15 security controls, nothing else |

### AI-Assisted Deployment

This project is designed to be LLM-friendly. If you're using Claude, GPT-5 Codex, or another AI assistant to help deploy:

- **[AGENTS.md](AGENTS.md)** — Canonical governance + deployment operator instructions for AI agents
- **Clear phase structure** — Each phase has explicit inputs, outputs, and verification gates
- **Idempotent operations** — Safe to re-run if interrupted or if the AI needs to retry
- **Validation at every step** — `base/validate.sh` provides machine-readable JSON output

Point your AI assistant to `AGENTS.md` and it can guide you through the entire process.

---

## Prerequisites

**Before you start**, you need:

| Requirement | How to get it |
|-------------|---------------|
| **Ubuntu 24.04 VPS** | Any provider (Hetzner, DigitalOcean, Linode, etc.) — 2GB+ RAM, 40GB+ disk |
| **Domain on Cloudflare** | [Move your domain to Cloudflare](https://developers.cloudflare.com/dns/zone-setups/) (free) |
| **Tailscale account** | Sign up at [tailscale.com](https://tailscale.com) (free for personal use) |
| **Tailscale auth key** | [Generate here](https://login.tailscale.com/admin/settings/keys) — use "Reusable" and "Ephemeral" |
| **Cloudflare API token(s)** | [Create here](https://dash.cloudflare.com/profile/api-tokens): either one combined token (`Zone:Zone:Read` + `Zone:DNS:Edit` + `Account:Cloudflare Tunnel:Edit`) or two split tokens (DNS token + Tunnel token) |
| **SSH key pair** | Run `ssh-keygen -t ed25519` if you don't have one |
| **Server timezone (IANA)** | Decide before deploy (examples: `Australia/Melbourne`, `UTC`) and pass via `--server-timezone` |
| **Bash 4+** | Required by scripts. macOS `/bin/bash` (3.2) is unsupported; install with `brew install bash` and invoke scripts via `/opt/homebrew/bin/bash` |

<details>
<summary>📦 Installing sshpass (macOS)</summary>

Required for `deploy.sh` only (automates SSH with root password):

```bash
brew install hudochenkov/sshpass/sshpass
```

</details>

---

## Quick Start

### One-Liner Deploy

From your laptop — everything automated:

```bash
curl -fsSL https://raw.githubusercontent.com/YOUR_USERNAME/secure-ubuntu-paas/main/deploy.sh | bash -s -- \
  --server-ip <vps-ip> \
  --root-pass-file /secure/path/root.pass \
  --tailscale-auth-key tskey-auth-... \
  --server-timezone Australia/Melbourne \
  --domain app.example.com \
  --cf-api-token-file /secure/path/cf_api.token \
  --yes
```

### Interactive Deploy

```bash
git clone https://github.com/YOUR_USERNAME/secure-ubuntu-paas.git
cd secure-ubuntu-paas
/opt/homebrew/bin/bash deploy.sh   # macOS
# or: ./deploy.sh (if your PATH resolves `bash` to version 4+)
```

Interactive mode prompts for `Server timezone` (default `UTC`) if you do not pass `--server-timezone`.

Already SSH'd into the server? Use `setup.sh` instead — same flags, runs locally (no root password flag needed).

---

## Post-Deploy Setup

After `deploy.sh` or `setup.sh` completes, three manual steps enable automatic SSL + subdomains:

1. **Cloudflare: SSL/TLS > Overview** — set encryption mode to **Full** (not Flexible)
2. **Coolify: Servers > your server > Wildcard Domain** — set to your zone root (e.g., `example.com`)
3. **Coolify: resource domains** — use `http://` protocol, not `https://`

After this, every new app gets: auto-assigned subdomain → wildcard DNS → Cloudflare edge SSL → tunnel/proxy → Traefik → container. Zero per-app configuration.

---

## Deployment Modes

| | Tunnel (default) | Standard |
|---|---|---|
| **Flag** | `--mode tunnel` (default) | `--mode standard` |
| **Inbound ports** | None | 80, 443 |
| **Traffic path** | Outbound tunnel to Cloudflare edge | Direct to origin (Cloudflare-proxied) |
| **Attack surface** | Zero public HTTP/S | Origin IP exposed behind Cloudflare |
| **Per-subdomain bypass** | Not possible | DNS-only ("grey cloud") available |

`--tunnel-mode` / `--mode tunnel` select the same private-only exposure model (`base/bootstrap.sh` vs `deploy.sh`/`setup.sh`).

**Tunnel is the default** because it eliminates direct-to-origin bypass entirely.

### Tunnel Mode Limitations

Evaluate these before choosing:

- **100MB upload limit** — Cloudflare Free/Pro plans cap request bodies. Apps with large uploads (Nextcloud, Immich) need chunked upload support or standard mode.
- **Nested subdomain TLS** — Universal SSL covers `*.example.com` but not `*.app.example.com`. Use single-level subdomains.
- **Media streaming** — Heavy video streaming (Jellyfin, Plex) may violate Cloudflare CDN terms. Use standard mode with DNS-only for media subdomains.
- **Cloudflare Access + webhooks** — If you add Zero Trust auth later, create IP-based bypass policies for CI/CD webhook paths.

If these apply, use `--mode standard`.

### TLS Architecture

| Mode | Edge TLS | Edge > Origin | Origin cert needed? |
|------|----------|---------------|---------------------|
| Tunnel (apps via wildcard) | Universal SSL | Encrypted tunnel (no TLS check) | No wildcard cert needed |
| Tunnel (private dashboard/realtime hostnames) | Direct Tailscale HTTPS to origin | TLS terminates on Traefik | Yes, auto-issued via DNS-01 by script |
| Standard (Full SSL) | Universal SSL | HTTPS, any cert accepted | Any (self-signed OK) |

Wildcard DNS (`*.example.com`) and tunnel ingress rules are created automatically.

---

## What Gets Hardened

`base/bootstrap.sh` applies **15 security controls**. See [HARDENING_PROCEDURE.md](HARDENING_PROCEDURE.md) for full technical detail.

| # | Control | Key details |
|---|---------|-------------|
| 1 | **Preflight** | OS validation, SSH session safety, interface detection |
| 2 | **NTP + timezone** | Time synchronization plus explicit timezone configuration |
| 3 | **Swap** | Configurable (default 2G), OOM protection |
| 4 | **Service cleanup** | Disables rpcbind, avahi-daemon, cups |
| 5 | **Login banner** | Authorized access warning |
| 6 | **SSH hardening** | Key-only, modern ciphers, root login disabled |
| 7 | **Auditd** | Tracks identity changes, sudoers, Docker socket |
| 8 | **Kernel hardening** | SYN cookies, BBR, ASLR, ICMP hardening, ptrace restricted |
| 9 | **UFW firewall** | Default deny, Tailscale CIDR, tunnel-mode aware |
| 10 | **Docker daemon** | `json-file` logs, `live-restore`, `default-ipc-mode=private`, `storage-driver=overlay2`, hardened `default-ulimits` |
| 11 | **DOCKER-USER rules** | IPv4/IPv6 chain hardening, bridge rules |
| 12 | **Fail2ban** | SSH jail with UFW ban action |
| 13 | **Journald** | Persistent logging with configurable retention |
| 14 | **Auto-updates** | Unattended security patches with scheduled reboots |
| 15 | **Post-checks** | Verification + JSON report |

---

## Usage Examples

### Env File (recommended for automation)

Keeps secrets out of shell history:

```bash
cat > /etc/bootstrap-hardening.env << 'EOF'
ADMIN_USER=coolifyadmin
ADMIN_PUBKEY="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... user@host"
TUNNEL_MODE=true
SWAP_SIZE=4G
TIMEZONE=Australia/Melbourne
ENABLE_AUTO_REBOOT=false
AUTO_REBOOT_TIME=04:00
JOURNAL_RETENTION=3month
EOF
chmod 0600 /etc/bootstrap-hardening.env

sudo ./base/bootstrap.sh --env-file /etc/bootstrap-hardening.env
```

`--env-file` is parsed as strict `KEY=VALUE` data (not shell-evaluated code).  
Accepted permissions are `0600` or `0400` by default (`--insecure-env` bypasses this check).

### Tailscale + Dashboard Binding

Install Tailscale and restrict Coolify dashboard to VPN only:

```bash
sudo ./base/bootstrap.sh \
  --admin-user coolifyadmin \
  --admin-pubkey "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... user@host" \
  --install-tailscale \
  --tailscale-auth-key "tskey-auth-xxxxx" \
  --bind-dashboard-to-tailscale
```

### Dry Run

Preview what would change without applying:

```bash
sudo ./base/bootstrap.sh \
  --admin-user coolifyadmin \
  --admin-pubkey "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... user@host" \
  --dry-run
```

---

## Validation & Testing

```bash
# Validate hardening (text output)
sudo ./base/validate.sh

# Validate hardening (JSON, for automation/CI)
sudo ./base/validate.sh --json
```

### Test Suite

Uses [BATS](https://github.com/bats-core/bats-core):

```bash
make setup-bats          # Install BATS locally
make test-unit-local     # Unit tests (fast, no Docker)
make test-all            # Full suite with Docker
```

| Make Target | Purpose |
|-------------|---------|
| `test-ci-pr` | Alias of `test-ci-max` (full lint + unit + contracts + integration matrix) |
| `test-ci-main` | Main branch: full suite |
| `test-dry-run` | Dry-run integration |
| `test-full-standard` | Full hardening, standard mode |
| `test-full-tunnel` | Full hardening, tunnel mode |
| `test-validate` | Validation script |
| `test-idempotency` | Re-run safety |

---

## CLI Reference

### What You Actually Need To Decide

| Workflow | Required inputs | Optional with defaults | Not required |
|----------|-----------------|------------------------|--------------|
| `deploy.sh` fresh run | `--server-ip`, `--domain`, root password (prompt or `--root-pass-file`), `--tailscale-auth-key`, Cloudflare API token (`CF_API_TOKEN` or `--cf-api-token-file`), server timezone choice (`--server-timezone`; mandatory with `--yes`) | `--admin-user` (`coolifyadmin`), `--pubkey-file` (`~/.ssh/id_ed25519.pub`), `--mode` (`tunnel`), `--app-domain-mode` (`apex`), `--swap-size` (`2G`), `--tailscale-direct-wan` (off), `--cf-zone`, `--cf-zone-id`, `--cf-account-id`, optional split tunnel token (`--cf-tunnel-api-token-file`) | `--ts-ip` |
| `deploy.sh --ts-ip <ip>` resume | `--server-ip`, `--domain`, `--ts-ip`, Cloudflare API token (`CF_API_TOKEN` or `--cf-api-token-file`), server timezone choice (`--server-timezone`; mandatory with `--yes`) | Same optional defaults as fresh run | root password / `--root-pass-file`, `--tailscale-auth-key` |
| `setup.sh` server-local run | `--server-ip`, `--admin-user`, `--pubkey-file`, `--domain`, Cloudflare API token (`CF_API_TOKEN` or `--cf-api-token-file`), `--tailscale-auth-key` unless `--preflight-only`, server timezone choice (`--server-timezone`; mandatory with `--yes`) | `--mode` (`tunnel`), `--app-domain-mode` (`apex`), `--swap-size` (`2G`), `--tailscale-direct-wan` (off), `--cf-zone`, `--cf-zone-id`, `--cf-account-id`, optional split tunnel token (`--cf-tunnel-api-token-file`) | root password / `--root-pass-file`, `--ts-ip` |

Recommended defaults (if undecided):
- `--mode tunnel`
- `--app-domain-mode apex`
- `--admin-user coolifyadmin`
- `--pubkey-file ~/.ssh/id_ed25519.pub`
- `--swap-size 2G`
- `--no-tailscale-direct-wan`

Minimal commands by workflow:

```bash
# deploy.sh fresh run
/opt/homebrew/bin/bash deploy.sh --server-ip <ip> --domain <fqdn> --root-pass-file <path> \
  --tailscale-auth-key <tskey-auth-...> --server-timezone <IANA> \
  --cf-api-token-file <path> --yes

# deploy.sh resume from phase 2
/opt/homebrew/bin/bash deploy.sh --server-ip <ip> --domain <fqdn> --ts-ip <100.x.x.x> \
  --server-timezone <IANA> --cf-api-token-file <path> --yes

# setup.sh server-local
sudo /opt/homebrew/bin/bash setup.sh --server-ip <ip> --admin-user <name> --pubkey-file <path> \
  --domain <fqdn> --tailscale-auth-key <tskey-auth-...> --server-timezone <IANA> \
  --cf-api-token-file <path> --yes
```

Decision tree:
- Exposure model: `tunnel` (private-only dashboard/realtime, no inbound 80/443) or `standard` (public 80/443).
- App hostnames: `apex` (`appname.<zone>`) or `vps` (`appname.<domain>`).
- Token model: combined token (single API token) or split tokens (DNS token + tunnel token).

Important:
- With `--yes`, set `--server-timezone <IANA>` (or `SERVER_TIMEZONE`) explicitly.
- Removed on purpose: `--cf-api-token`, `--cf-tunnel-api-token`. Use env vars or `--*-token-file`.

Resume semantics:
- `--ts-ip` skips phase 1 hardening.
- In `--ts-ip` mode, root password and Tailscale auth key are not required.

Pre-run checklist:
- Confirm execution surface: `deploy.sh` on laptop, `setup.sh` on server.
- Confirm server target: public IPv4 and (for resume) Tailscale IPv4.
- Confirm domain target and deployment mode.
- Confirm app-domain mode (`apex` or `vps`).
- Confirm timezone value (IANA string).
- Confirm token source (env vars or token file path(s)).

<details>
<summary>📋 deploy.sh flags</summary>

| Flag | Default | Description |
|------|---------|-------------|
| `--server-ip <ip>` | *(required)* | Server public IPv4 |
| `--root-pass-file <path>` | optional | Read root password from file (recommended for automation) |
| `--tailscale-auth-key <key>` | *(required)* | Tailscale auth key (`tskey-auth-...`) |
| `--domain <fqdn>` | *(required)* | Domain name for Coolify |
| `--cf-api-token-file <path>` | optional* | Cloudflare API token file (`*`required unless `CF_API_TOKEN` env var or interactive prompt) |
| `--cf-tunnel-api-token-file <path>` | optional | Cloudflare tunnel API token file (defaults to API token when omitted) |
| `--admin-user <name>` | `coolifyadmin` | Admin username |
| `--pubkey-file <path>` | `~/.ssh/id_ed25519.pub` | SSH public key file |
| `--mode <tunnel\|standard>` | `tunnel` | Deployment mode |
| `--app-domain-mode <vps\|apex>` | `apex` | App URL scope: `apex`=`appname.<zone>`, `vps`=`appname.<domain>` |
| `--cf-zone <zone>` | derived from domain | Cloudflare zone |
| `--cf-zone-id <id>` | none | Cloudflare zone ID override (32-char hex) |
| `--cf-account-id <id>` | none | Cloudflare account ID override (32-char hex) |
| `--swap-size <size>` | `2G` | Swap file size |
| `--server-timezone <IANA>` | prompted (default `UTC`) | Server timezone (required in non-interactive mode) |
| `--tailscale-direct-wan` | `false` | Open WAN UDP 41641 for direct Tailscale paths (optional optimization) |
| `--no-tailscale-direct-wan` | `true` | Keep WAN UDP 41641 closed (default behavior) |
| `--preflight-only` | `false` | Run local + Cloudflare checks only (no server changes) |
| `--ts-ip <ip>` | none | Skip phase 1 hardening and resume deployment using known server Tailscale IP |
| `--yes` | `false` | Skip confirmation prompts |

Legacy flags removed (breaking change): `--cf-api-token`, `--cf-tunnel-api-token`.

</details>

<details>
<summary>📋 base/bootstrap.sh flags</summary>

| Flag | Default | Description |
|------|---------|-------------|
| `--admin-user <name>` | *(required)* | Admin username to create |
| `--admin-pubkey "<key>"` | *(required)* | SSH public key for admin |
| `--tunnel-mode` | `false` | Skip WAN 80/443 (Cloudflare Tunnel) |
| `--swap-size <size>` | `2G` | Swap size (`0` to skip) |
| `--timezone <IANA>` | `UTC` | System timezone (IANA name, e.g. `Australia/Melbourne`) |
| `--ssh-port <port>` | `22` | SSH port |
| `--tailscale-cidr <cidr>` | `100.64.0.0/10` | Tailscale network CIDR |
| `--wan-iface <iface>` | auto-detected | WAN interface |
| `--tailscale-direct-wan` | `false` | Open WAN UDP 41641 for direct Tailscale paths (optional optimization) |
| `--no-tailscale-direct-wan` | `true` | Keep WAN UDP 41641 closed (default behavior) |
| `--install-tailscale` | `false` | Install Tailscale |
| `--tailscale-auth-key <key>` | — | Tailscale auth key (with `--install-tailscale`) |
| `--bind-dashboard-to-tailscale` | `false` | Enable watchdog re-enforcement of Tailscale-only UFW rules for 8000/6001/6002 |
| `--enable-auto-reboot <bool>` | `false` | Auto-reboot after security updates |
| `--auto-reboot-time <HH:MM>` | `03:30` | Reboot schedule |
| `--update-profile <name>` | `security-only` | Unattended-upgrades profile: `security-only` or `balanced` |
| `--journal-retention <span>` | `3month` | Journald retention period |
| `--strict-docker-ssh-cidrs` | `true` | Limit SSH/UFW bridge allowlists to discovered Docker bridge CIDRs |
| `--compat-docker-ssh-cidrs` | `false` | Use broad Docker bridge CIDR compatibility ranges |
| `--docker-nproc-hard <num>` | `8192` | Docker default `nproc` hard limit |
| `--docker-nproc-soft <num>` | `4096` | Docker default `nproc` soft limit |
| `--upgrade-mail <address>` | — | Email for upgrade failure reports |
| `--env-file <path>` | — | Load options from file |
| `--insecure-env` | `false` | Allow env files with looser permissions (dangerous) |
| `--dry-run` | `false` | Preview without changes |
| `--force` | `false` | Override safety gates |

All flags have corresponding environment variables (e.g., `ADMIN_USER`, `TUNNEL_MODE`). CLI flags override env-file values.

</details>

---

## Project Structure

```
secure-ubuntu-paas/
├── deploy.sh                    # Laptop-side deployment orchestrator
├── setup.sh                     # Server-side deployment orchestrator
├── base/
│   ├── bootstrap.sh             # Security hardening script (15 controls)
│   ├── validate.sh              # Post-hardening verification
│   ├── modules/                 # Hardening modules (ssh, ufw, auditd, ...)
│   └── checks/                  # Validation checks
├── overlays/
│   ├── coolify/
│   │   ├── coolify-common.sh    # Shared utilities (Cloudflare API, validation)
│   │   ├── modules/             # Binding, watchdog
│   │   └── checks/              # Coolify-specific validation checks
│   └── docker-host/
│       ├── modules/             # Docker SSH CIDR, daemon config
│       └── checks/              # Docker-specific validation checks
├── lib/
│   ├── common.sh                # Core utilities (log, die, is_true, ...)
│   ├── tailscale.sh             # Tailscale install/detect helpers
│   └── overlay-loader.sh        # Overlay topo-sort and dispatch
├── HARDENING_PROCEDURE.md       # Detailed hardening technical reference
├── docs/
│   ├── DEPLOYMENT_RUNBOOK.md    # Manual step-by-step deployment guide
│   └── testing.md               # Test documentation
├── tests/
│   ├── helpers/helpers.bash     # BATS test helpers
│   ├── base/                    # Base tier tests (unit + integration)
│   ├── overlays/coolify/        # Coolify overlay tests
│   └── orchestrator/            # Deploy/setup orchestrator tests
├── Makefile                     # Test automation
└── scripts/
    └── check_workflow_consistency.sh
```

---

## Troubleshooting

<details>
<summary>🔍 Common Issues</summary>

### SSH Connection Refused After Hardening

**Cause:** You're trying to SSH to the public IP instead of the Tailscale IP.

**Solution:** Connect via Tailscale:
```bash
ssh admin@100.x.x.x  # Use the Tailscale IP output by the script
```

### Dashboard Not Accessible

**Cause:** Management ports are restricted to the `tailscale0` interface by UFW.

**Solution:**
1. Ensure Tailscale is running on your laptop: `tailscale status`
2. Access via `https://<your-domain>` (trusted cert) or fallback `http://100.x.x.x:8000` (Tailscale IP)

### Cloudflare Tunnel Not Working

**Cause:** API token missing required permissions.

**Solution:** Use either:
- Combined token: `Zone:Zone:Read` + `Zone:DNS:Edit` + `Account:Cloudflare Tunnel:Edit`
- Split tokens: DNS token with `Zone:Zone:Read` + `Zone:DNS:Edit`, and tunnel token with `Account:Cloudflare Tunnel:Edit`

### "Cannot connect to real-time service" in Coolify UI

**Cause:** Realtime is not configured to use the private websocket hostname over TLS.

**Solution (tunnel mode, private-only default):**
1. Check Coolify env: `PUSHER_HOST=ws.<your-domain>`, `PUSHER_PORT=443`, `PUSHER_SCHEME=https`
2. Check `/etc/cloudflared/config.yml` does **not** route `localhost:8000`, `localhost:6001`, or `localhost:6002`
3. Check `/data/coolify/proxy/dynamic/coolify-private-dashboard.yaml` has both HTTP and HTTPS routers for `DOMAIN` and `ws.DOMAIN`
4. Check Cloudflare DNS has `A` records for `DOMAIN` and `ws.DOMAIN` pointing to the server `100.x` Tailscale IP with proxy disabled (DNS-only)

### Validation Failures

Run `sudo ./base/validate.sh` for details. Common fixes:
- **UFW inactive:** `sudo ufw enable`
- **Auditd not running:** `sudo systemctl enable --now auditd`
- **Docker not installed:** Hardening-only mode doesn't install Docker; use `deploy.sh` for full setup

</details>

---

## Contributing

Contributions are welcome! Please read the following before submitting:

1. **Test your changes:** Run `make test-ci-pr` before opening a PR
2. **Follow the style:** ShellCheck-clean, consistent formatting
3. **Document changes:** Update relevant `.md` files

### Development Setup

```bash
git clone https://github.com/YOUR_USERNAME/secure-ubuntu-paas.git
cd secure-ubuntu-paas
make setup-bats
make test-unit-local
```

---

## Security Policy

### Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, please use [GitHub Security Advisories](https://github.com/YOUR_USERNAME/secure-ubuntu-paas/security/advisories/new).

You should receive a response within 48 hours. If the vulnerability is confirmed:
- We'll work on a fix and coordinate disclosure with you
- Credit will be given in the advisory unless you prefer to remain anonymous

### Supported Versions

| Version | Supported |
| ------- | --------- |
| main    | ✅        |
| < 1.0   | ❌        |

---

## License

[MIT License](LICENSE)

---

## Acknowledgments

- [Coolify](https://coolify.io/) — The self-hosting platform this project secures
- [Tailscale](https://tailscale.com/) — Zero-config VPN for secure access
- [Cloudflare](https://cloudflare.com/) — Edge security and tunneling
- [BATS](https://github.com/bats-core/bats-core) — Bash testing framework
