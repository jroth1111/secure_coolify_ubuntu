# Secure Coolify Ubuntu

Production-ready security hardening for Ubuntu 24.04 servers running [Coolify](https://coolify.io/).

[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Ubuntu](https://img.shields.io/badge/Ubuntu-24.04%20LTS-E95420?logo=ubuntu)](https://ubuntu.com/)

---

## Overview

Go from a fresh Ubuntu 24.04 VPS to a hardened, production Coolify instance with automatic SSL and wildcard subdomains. One script handles everything: server hardening, Tailscale VPN, Docker, Coolify, Cloudflare DNS, and dashboard lockdown.

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

**Two deployment paths:**

| Path | Script | Run from | Use case |
|------|--------|----------|----------|
| **Full deploy** | `deploy.sh` | Your laptop | Fresh VPS to working Coolify in ~15 min |
| **Hardening only** | `bootstrap_hardening.sh` | The server | Just the security controls, no Coolify orchestration |

---

## Prerequisites

| Requirement | Details |
|-------------|---------|
| **Server** | Ubuntu 24.04 LTS, 2GB+ RAM (4GB+ recommended), 40GB+ SSD |
| **Tailscale** | Account + auth key ([tailscale.com](https://tailscale.com)) |
| **Cloudflare** | Domain on Cloudflare DNS + API token with `Zone:DNS:Edit` and `Account:Cloudflare Tunnel:Edit` |
| **SSH key** | Ed25519 recommended: `ssh-keygen -t ed25519` |
| **Local tools** | `ssh`, `curl`, `jq`, `sshpass` (for `deploy.sh` only) |

---

## Quick Start

### Full Automated Deploy

From your laptop — hardening, Tailscale, Docker, Coolify, Cloudflare Tunnel, DNS, and dashboard lockdown:

```bash
bash deploy.sh \
  --server-ip <vps-ip> \
  --root-pass <root-password> \
  --tailscale-auth-key tskey-auth-... \
  --domain app.example.com \
  --cf-api-token <cloudflare-token> \
  --yes
```

Or run interactively (prompts for each value):

```bash
bash deploy.sh
```

Already SSH'd into the server? Use `setup.sh` instead — same flags, runs locally (no `--root-pass` needed).

See [docs/DEPLOYMENT_RUNBOOK.md](docs/DEPLOYMENT_RUNBOOK.md) for the manual step-by-step procedure.

### Hardening Only

If you just want the security controls without the full Coolify orchestration:

```bash
sudo ./bootstrap_hardening.sh \
  --admin-user coolifyadmin \
  --admin-pubkey "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... user@host" \
  --tunnel-mode

# Verify
sudo ./validate_hardening.sh
```

---

## Post-Deploy Setup

After `deploy.sh` or `setup.sh` completes, three manual steps enable automatic SSL + subdomains for every app you deploy:

1. **Cloudflare: SSL/TLS > Overview** — set encryption mode to **Full** (not Flexible, not Full Strict)
2. **Coolify: Servers > your server > Wildcard Domain** — set to your zone root (e.g., `example.com`)
3. **Coolify: resource domains** — use `http://` protocol, not `https://`

After this, every new app gets: auto-assigned subdomain > wildcard DNS > Cloudflare edge SSL > tunnel/proxy > Traefik > container. Zero per-app configuration.

---

## Deployment Modes

| | Tunnel (default) | Standard |
|---|---|---|
| **Flag** | `--tunnel-mode` / `--mode tunnel` | `--mode standard` |
| **Inbound ports** | None | 80, 443 |
| **Traffic path** | Outbound tunnel to Cloudflare edge | Direct to origin (Cloudflare-proxied) |
| **Attack surface** | Zero public HTTP/S | Origin IP exposed behind Cloudflare |
| **Per-subdomain bypass** | Not possible | DNS-only ("grey cloud") available |

**Tunnel is the default** because it eliminates direct-to-origin bypass entirely. The server has no publicly reachable HTTP/S ports.

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

Wildcard DNS (`*.example.com`) and tunnel ingress rules are created automatically by the scripts. Coolify's Traefik handles Host-header routing to containers.

**Optional:** For Full (Strict) SSL or DNS-only subdomains where Traefik terminates TLS, configure Traefik's DNS-01 challenge in the Coolify UI (Servers > Proxy). See [Coolify wildcard cert docs](https://coolify.io/docs/knowledge-base/proxy/traefik/wildcard-certs).

---

## What Gets Hardened

`bootstrap_hardening.sh` applies 15 security controls. See [HARDENING_PROCEDURE.md](HARDENING_PROCEDURE.md) for full technical detail.

| # | Control | Key details |
|---|---------|-------------|
| 1 | **Preflight** | OS validation, SSH session safety, interface detection |
| 2 | **NTP** | Time synchronization |
| 3 | **Swap** | Configurable (default 2G), OOM protection |
| 4 | **Service cleanup** | Disables rpcbind, avahi-daemon, cups |
| 5 | **Login banner** | Authorized access warning |
| 6 | **SSH hardening** | Key-only, modern ciphers (`chacha20-poly1305`, `aes256-gcm`), root login disabled |
| 7 | **Auditd** | Tracks identity changes, sudoers, Docker socket |
| 8 | **Kernel hardening** | SYN cookies, BBR, ASLR, ICMP hardening, kexec disabled, ptrace restricted |
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
# Validate hardening (text)
sudo ./validate_hardening.sh

# Validate hardening (JSON, for automation)
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
| `test-workflow-consistency` | Workflow/doc contract checks |

---

## CLI Reference

### deploy.sh

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

### bootstrap_hardening.sh

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

---

## Project Structure

```
secure_coolify_ubuntu/
├── deploy.sh                    # Laptop-side deployment orchestrator
├── setup.sh                     # Server-side deployment orchestrator
├── bootstrap_hardening.sh       # Security hardening script (15 controls)
├── validate_hardening.sh        # Post-hardening verification
├── configure_coolify_binding.sh # Split-horizon dashboard binding
├── AGENTS_DEPLOY.md             # LLM agent deployment instructions
├── HARDENING_PROCEDURE.md       # Detailed hardening technical reference
├── Makefile                     # Test automation
├── scripts/
│   └── check_workflow_consistency.sh
├── docs/
│   ├── DEPLOYMENT_RUNBOOK.md    # Manual step-by-step deployment guide
│   ├── testing.md
│   ├── bootstrap_functionality_test_matrix.md
│   ├── deploy_setup_functionality_test_matrix.md
│   └── workflow_contract.yaml
├── tests/
│   ├── unit/                    # Fast unit tests
│   ├── integration/             # Docker-based integration tests
│   └── lib/                     # BATS support libraries
├── Dockerfile.tier1             # Lightweight test container
└── Dockerfile.test              # Full systemd test container
```

---

## Contributing

1. Fork the repository
2. Create a feature branch
3. Run tests: `make test-ci-pr`
4. Submit a pull request

---

## License

[MIT License](LICENSE)
