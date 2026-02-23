# Secure Coolify Ubuntu

Turn a fresh Ubuntu VPS into a **production-hardened Coolify server** in ~15 minutes.

[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Ubuntu](https://img.shields.io/badge/Ubuntu-24.04%20LTS-E95420?logo=ubuntu)](https://ubuntu.com/)
[![Coolify](https://img.shields.io/badge/Coolify-v4+-purple?logo=docker)](https://coolify.io/)
[![Shellcheck](https://img.shields.io/badge/ShellCheck-passed-brightgreen)](https://www.shellcheck.net/)
[![LLM Friendly](https://img.shields.io/badge/LLM-friendly-blue)](AGENTS_DEPLOY.md)

---

## What is This?

**[Coolify](https://coolify.io/)** is an open-source self-hosting platform — deploy apps, databases, and services with a UI (like a self-hosted Heroku). This project **secures a Coolify server** from scratch.

**What you start with:** A fresh Ubuntu 24.04 VPS with root access.

**What you end with:**
- ✅ Coolify running and accessible at `https://your-domain.com`
- ✅ SSH + dashboard only accessible via Tailscale VPN (no public attack surface)
- ✅ Automatic SSL for all apps via Cloudflare
- ✅ Hardened kernel, firewall, audit logging, and auto-updates

---

## Why This Project?

Deploying Coolify on a fresh VPS leaves significant security gaps: root SSH enabled, default firewall rules, no audit logging, and the Coolify dashboard exposed to the internet. This project closes those gaps with a defense-in-depth approach:

| Problem | Solution |
|---------|----------|
| Root SSH + password auth | Key-only SSH, admin user, root login disabled |
| No firewall policy | UFW default-deny, DOCKER-USER chain rules |
| Dashboard publicly accessible | Bind to Tailscale VPN IP only |
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
Phase 4: Configure Cloudflare DNS/Tunnel + wildcard subdomain
          ↓
Phase 5: Bind dashboard to Tailscale IP + final verification
```

**Which script should I use?**

| Script | When to use | What it does |
|--------|-------------|--------------|
| `deploy.sh` | From your laptop, fresh VPS | Full automation: SSH in, harden, install Coolify, configure DNS |
| `setup.sh` | Already SSH'd into server | Same as deploy.sh but runs locally (no root password needed) |
| `bootstrap_hardening.sh` | You only want hardening, no Coolify | Just the 15 security controls, nothing else |

### AI-Assisted Deployment

This project is designed to be LLM-friendly. If you're using Claude, GPT-5 Codex, or another AI assistant to help deploy:

- **[AGENTS_DEPLOY.md](AGENTS_DEPLOY.md)** — Detailed instructions for AI agents to execute the deployment
- **Clear phase structure** — Each phase has explicit inputs, outputs, and verification gates
- **Idempotent operations** — Safe to re-run if interrupted or if the AI needs to retry
- **Validation at every step** — `validate_hardening.sh` provides machine-readable JSON output

Just point your AI assistant to `AGENTS_DEPLOY.md` and it can guide you through the entire process.

---

## Prerequisites

**Before you start**, you need:

| Requirement | How to get it |
|-------------|---------------|
| **Ubuntu 24.04 VPS** | Any provider (Hetzner, DigitalOcean, Linode, etc.) — 2GB+ RAM, 40GB+ disk |
| **Domain on Cloudflare** | [Move your domain to Cloudflare](https://developers.cloudflare.com/dns/zone-setups/) (free) |
| **Tailscale account** | Sign up at [tailscale.com](https://tailscale.com) (free for personal use) |
| **Tailscale auth key** | [Generate here](https://login.tailscale.com/admin/settings/keys) — use "Reusable" and "Ephemeral" |
| **Cloudflare API token** | [Create here](https://dash.cloudflare.com/profile/api-tokens) with permissions: `Zone:DNS:Edit` + `Account:Cloudflare Tunnel:Edit` |
| **SSH key pair** | Run `ssh-keygen -t ed25519` if you don't have one |

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
curl -fsSL https://raw.githubusercontent.com/YOUR_USERNAME/secure_coolify_ubuntu/main/deploy.sh | bash -s -- \
  --server-ip <vps-ip> \
  --root-pass <root-password> \
  --tailscale-auth-key tskey-auth-... \
  --domain app.example.com \
  --cf-api-token <cloudflare-token> \
  --yes
```

### Interactive Deploy

```bash
git clone https://github.com/YOUR_USERNAME/secure_coolify_ubuntu.git
cd secure_coolify_ubuntu
bash deploy.sh
```

Already SSH'd into the server? Use `setup.sh` instead — same flags, runs locally (no `--root-pass` needed).

---

## Post-Deploy Setup

After `deploy.sh` or `setup.sh` completes, three manual steps enable automatic SSL + subdomains:

1. **Cloudflare: SSL/TLS > Overview** — set encryption mode to **Full** (not Flexible, not Full Strict)
2. **Coolify: Servers > your server > Wildcard Domain** — set to your zone root (e.g., `example.com`)
3. **Coolify: resource domains** — use `http://` protocol, not `https://`

After this, every new app gets: auto-assigned subdomain → wildcard DNS → Cloudflare edge SSL → tunnel/proxy → Traefik → container. Zero per-app configuration.

---

## Deployment Modes

| | Tunnel (default) | Standard |
|---|---|---|
| **Flag** | `--tunnel-mode` / `--mode tunnel` | `--mode standard` |
| **Inbound ports** | None | 80, 443 |
| **Traffic path** | Outbound tunnel to Cloudflare edge | Direct to origin (Cloudflare-proxied) |
| **Attack surface** | Zero public HTTP/S | Origin IP exposed behind Cloudflare |
| **Per-subdomain bypass** | Not possible | DNS-only ("grey cloud") available |

**Tunnel is the default** because it eliminates direct-to-origin bypass entirely.

### Tunnel Mode Limitations

Evaluate these before choosing:

- **100MB upload limit** — Cloudflare Free/Pro plans cap request bodies. Apps with large uploads (Nextcloud, Immich) need chunked upload support or standard mode.
- **Nested subdomain TLS** — Universal SSL covers `*.example.com` but not `*.app.example.com`. Use single-level subdomains.
- **Media streaming** — Heavy video streaming (Jellyfin, Plex) may violate Cloudflare CDN terms. Use standard mode with DNS-only for media subdomains.
- **Cloudflare Access + webhooks** — If you add Zero Trust auth later, create IP-based bypass policies for CI/CD webhook paths.

If these apply, use `--mode standard`.

### TLS Architecture

Both modes use Cloudflare's edge for user-facing TLS. No wildcard certificate is needed on the origin.

| Mode | Edge TLS | Edge > Origin | Origin cert needed? |
|------|----------|---------------|---------------------|
| Tunnel | Universal SSL | Encrypted tunnel (no TLS check) | No |
| Standard (Full SSL) | Universal SSL | HTTPS, any cert accepted | Any (self-signed OK) |

Wildcard DNS (`*.example.com`) and tunnel ingress rules are created automatically.

---

## What Gets Hardened

`bootstrap_hardening.sh` applies **15 security controls**. See [HARDENING_PROCEDURE.md](HARDENING_PROCEDURE.md) for full technical detail.

| # | Control | Key details |
|---|---------|-------------|
| 1 | **Preflight** | OS validation, SSH session safety, interface detection |
| 2 | **NTP** | Time synchronization |
| 3 | **Swap** | Configurable (default 2G), OOM protection |
| 4 | **Service cleanup** | Disables rpcbind, avahi-daemon, cups |
| 5 | **Login banner** | Authorized access warning |
| 6 | **SSH hardening** | Key-only, modern ciphers, root login disabled |
| 7 | **Auditd** | Tracks identity changes, sudoers, Docker socket |
| 8 | **Kernel hardening** | SYN cookies, BBR, ASLR, ICMP hardening, ptrace restricted |
| 9 | **UFW firewall** | Default deny, Tailscale CIDR, tunnel-mode aware |
| 10 | **Docker daemon** | `json-file` log driver with rotation, `live-restore` |
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
ENABLE_AUTO_REBOOT=true
AUTO_REBOOT_TIME=04:00
JOURNAL_RETENTION=3month
EOF
chmod 0600 /etc/bootstrap-hardening.env

sudo ./bootstrap_hardening.sh --env-file /etc/bootstrap-hardening.env
```

### Tailscale + Dashboard Binding

Install Tailscale and restrict Coolify dashboard to VPN only:

```bash
sudo ./bootstrap_hardening.sh \
  --admin-user coolifyadmin \
  --admin-pubkey "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... user@host" \
  --install-tailscale \
  --tailscale-auth-key "tskey-auth-xxxxx" \
  --bind-dashboard-to-tailscale
```

### Dry Run

Preview what would change without applying:

```bash
sudo ./bootstrap_hardening.sh \
  --admin-user coolifyadmin \
  --admin-pubkey "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... user@host" \
  --dry-run
```

---

## Validation & Testing

```bash
# Validate hardening (text output)
sudo ./validate_hardening.sh

# Validate hardening (JSON, for automation/CI)
sudo ./validate_hardening.sh --json
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
| `test-ci-pr` | PR gate: unit + dry-run + validate + consistency |
| `test-ci-main` | Main branch: full suite |
| `test-dry-run` | Dry-run integration |
| `test-full-standard` | Full hardening, standard mode |
| `test-full-tunnel` | Full hardening, tunnel mode |
| `test-validate` | Validation script |
| `test-idempotency` | Re-run safety |

---

## CLI Reference

<details>
<summary>📋 deploy.sh flags</summary>

| Flag | Default | Description |
|------|---------|-------------|
| `--server-ip <ip>` | *(required)* | Server public IPv4 |
| `--root-pass <pass>` | *(required)* | Root password for initial SSH |
| `--tailscale-auth-key <key>` | *(required)* | Tailscale auth key (`tskey-auth-...`) |
| `--domain <fqdn>` | *(required)* | Domain name for Coolify |
| `--cf-api-token <token>` | *(required)* | Cloudflare API token |
| `--admin-user <name>` | `coolifyadmin` | Admin username |
| `--pubkey-file <path>` | `~/.ssh/id_ed25519.pub` | SSH public key file |
| `--mode <tunnel\|standard>` | `tunnel` | Deployment mode |
| `--cf-zone <zone>` | derived from domain | Cloudflare zone |
| `--swap-size <size>` | `2G` | Swap file size |
| `--yes` | `false` | Skip confirmation prompts |

</details>

<details>
<summary>📋 bootstrap_hardening.sh flags</summary>

| Flag | Default | Description |
|------|---------|-------------|
| `--admin-user <name>` | *(required)* | Admin username to create |
| `--admin-pubkey "<key>"` | *(required)* | SSH public key for admin |
| `--tunnel-mode` | `false` | Skip WAN 80/443 (Cloudflare Tunnel) |
| `--swap-size <size>` | `2G` | Swap size (`0` to skip) |
| `--ssh-port <port>` | `22` | SSH port |
| `--tailscale-cidr <cidr>` | `100.64.0.0/10` | Tailscale network CIDR |
| `--wan-iface <iface>` | auto-detected | WAN interface |
| `--install-tailscale` | `false` | Install Tailscale |
| `--tailscale-auth-key <key>` | — | Tailscale auth key (with `--install-tailscale`) |
| `--bind-dashboard-to-tailscale` | `false` | Bind Coolify dashboard to Tailscale IP |
| `--enable-auto-reboot <bool>` | `true` | Auto-reboot after security updates |
| `--auto-reboot-time <HH:MM>` | `03:30` | Reboot schedule |
| `--journal-retention <span>` | `3month` | Journald retention period |
| `--upgrade-mail <address>` | — | Email for upgrade failure reports |
| `--env-file <path>` | — | Load options from file |
| `--dry-run` | `false` | Preview without changes |
| `--force` | `false` | Override safety gates |

All flags have corresponding environment variables (e.g., `ADMIN_USER`, `TUNNEL_MODE`). CLI flags override env-file values.

</details>

---

## Project Structure

```
secure_coolify_ubuntu/
├── deploy.sh                    # Laptop-side deployment orchestrator
├── setup.sh                     # Server-side deployment orchestrator
├── bootstrap_hardening.sh       # Security hardening script (15 controls)
├── validate_hardening.sh        # Post-hardening verification
├── configure_coolify_binding.sh # Split-horizon dashboard binding
├── lib/
│   └── coolify-common.sh        # Shared utilities (Cloudflare API, validation)
├── HARDENING_PROCEDURE.md       # Detailed hardening technical reference
├── docs/
│   ├── DEPLOYMENT_RUNBOOK.md    # Manual step-by-step deployment guide
│   └── testing.md               # Test documentation
├── tests/
│   ├── unit/                    # Fast unit tests
│   └── integration/             # Docker-based integration tests
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

**Cause:** Dashboard is bound to Tailscale IP only.

**Solution:**
1. Ensure Tailscale is running on your laptop: `tailscale status`
2. Access via `http://100.x.x.x:8000` (Tailscale IP, not public IP)

### Cloudflare Tunnel Not Working

**Cause:** API token missing required permissions.

**Solution:** Ensure token has both:
- `Zone:DNS:Edit`
- `Account:Cloudflare Tunnel:Edit`

### Validation Failures

Run `sudo ./validate_hardening.sh` for details. Common fixes:
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
git clone https://github.com/YOUR_USERNAME/secure_coolify_ubuntu.git
cd secure_coolify_ubuntu
make setup-bats
make test-unit-local
```

---

## Security Policy

### Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, please use [GitHub Security Advisories](https://github.com/YOUR_USERNAME/secure_coolify_ubuntu/security/advisories/new).

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
