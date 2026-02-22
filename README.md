# Secure Coolify Ubuntu

**Production-ready security hardening for Ubuntu 24.04 servers running Coolify.**

[![Version](https://img.shields.io/badge/version-1.2.1-blue.svg)](https://github.com/yourusername/secure_coolify_ubuntu)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Ubuntu](https://img.shields.io/badge/Ubuntu-24.04%20LTS-E95420?logo=ubuntu)](https://ubuntu.com/)

---

## TL;DR

**What it does:** Automatically hardens a fresh Ubuntu 24.04 server for running [Coolify](https://coolify.io/) (self-hosted PaaS) with best-practice security controls.

**Who it's for:** DevOps engineers, sysadmins, and developers deploying Coolify who want production-grade server security without manually configuring firewalls, SSH hardening, and audit logging.

**Key features:**

- 16 automated hardening steps in a single script
- SSH key-only authentication with modern cipher suites
- UFW firewall with Docker-aware rules
- Fail2ban integration for SSH brute-force protection
- Kernel hardening (SYN flood protection, BBR, ASLR)
- Auditd rules for security monitoring
- Unattended security updates with scheduled reboots
- Supports Cloudflare Tunnel mode (no inbound web ports)
- Tailscale integration for secure admin access
- Comprehensive BATS test suite

---

## What It Does

The `bootstrap_hardening.sh` script applies security hardening in this order:

| Step | Description |
|------|-------------|
| 1 | **Preflight checks** — OS validation, root requirement, SSH session safety |
| 2 | **Dependencies** — Installs UFW, auditd, fail2ban, unattended-upgrades |
| 3 | **Time sync** — Ensures NTP is active |
| 4 | **Swap** — Creates swap file (default 2G, configurable) |
| 5 | **Service cleanup** — Disables rpcbind, avahi-daemon, cups |
| 6 | **Admin account** — Creates user with SSH key access |
| 7 | **SSH hardening** — Key-only auth, modern ciphers, root disabled |
| 8 | **UFW firewall** — Baseline rules with tunnel-mode support |
| 9 | **Kernel hardening** — sysctl configs (SYN flood, BBR, ASLR, ptrace) |
| 10 | **Fail2ban** — SSH jail with UFW integration |
| 11 | **Docker rules** — DOCKER-USER chain hardening |
| 12 | **Docker daemon** — Log rotation and live-restore |
| 13 | **Journald** — Persistent logging with retention |
| 14 | **Auditd** — Rules for identity, sudoers, Docker monitoring |
| 15 | **Auto-updates** — Security patches with configurable reboots |
| 16 | **Login banner** — Authorized access warning |

### Deployment Modes

| Mode | Description | Use Case |
|------|-------------|----------|
| **Standard** | Opens WAN ports 80/443 for web traffic | Traditional VPS with public ingress |
| **Tunnel** (`--tunnel-mode`) | No inbound web ports | Cloudflare Tunnel, Tailscale Funnel |

---

## Quick Start

### Prerequisites

- Ubuntu 24.04 LTS server
- Root or sudo access
- SSH public key for admin user

### Run Hardening

```bash
# Clone the repository
git clone https://github.com/yourusername/secure_coolify_ubuntu.git
cd secure_coolify_ubuntu

# Run with required options
sudo ./bootstrap_hardening.sh \
  --admin-user coolifyadmin \
  --admin-pubkey "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... user@host"
```

### Verify Hardening

```bash
sudo ./validate_hardening.sh
```

---

## Usage Examples

### Standard Deployment

For a VPS with public web ingress on ports 80/443:

```bash
sudo ./bootstrap_hardening.sh \
  --admin-user coolifyadmin \
  --admin-pubkey "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... user@host" \
  --enable-auto-reboot true \
  --auto-reboot-time 03:30
```

### Cloudflare Tunnel Mode

No inbound web ports — all traffic via outbound tunnel:

```bash
sudo ./bootstrap_hardening.sh \
  --admin-user coolifyadmin \
  --admin-pubkey "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... user@host" \
  --tunnel-mode
```

### Using an Env File

For automation and keeping secrets out of shell history:

```bash
# Create env file (chmod 0600 to protect)
cat > /etc/bootstrap-hardening.env << 'EOF'
ADMIN_USER=coolifyadmin
ADMIN_PUBKEY="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... user@host"
TUNNEL_MODE=true
SSH_PORT=22
SWAP_SIZE=4G
ENABLE_AUTO_REBOOT=true
AUTO_REBOOT_TIME=04:00
JOURNAL_RETENTION=3month
EOF

chmod 0600 /etc/bootstrap-hardening.env

# Run with env file
sudo ./bootstrap_hardening.sh --env-file /etc/bootstrap-hardening.env
```

### Tailscale Integration

Install Tailscale and bind Coolify dashboard to Tailscale IP only:

```bash
sudo ./bootstrap_hardening.sh \
  --admin-user coolifyadmin \
  --admin-pubkey "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... user@host" \
  --install-tailscale \
  --tailscale-auth-key "tskey-auth-xxxxx" \
  --bind-dashboard-to-tailscale
```

### Dry Run (Preview Changes)

See what would be changed without applying:

```bash
sudo ./bootstrap_hardening.sh \
  --admin-user coolifyadmin \
  --admin-pubkey "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... user@host" \
  --dry-run
```

---

## What Gets Secured

### SSH Hardening

- Password authentication disabled
- Root login disabled (except Coolify's localhost/Docker bridge Match block)
- Modern ciphers only: `chacha20-poly1305@openssh.com`, `aes256-gcm@openssh.com`
- Strong MACs and KEX algorithms
- Key-only authentication enforced

### Firewall Configuration

- Default deny incoming, allow outgoing
- SSH allowed from Tailscale CIDR (configurable)
- WAN 80/443 allowed (standard mode only)
- Tailscale direct UDP allowed
- Docker-aware DOCKER-USER chain rules

### Kernel Hardening

| Setting | Purpose |
|---------|---------|
| `net.ipv4.tcp_syncookies` | SYN flood protection |
| `net.core.default_qdisc=fq` + `net.ipv4.tcp_congestion_control=bbr` | BBR congestion control |
| `net.ipv4.icmp_*` | ICMP hardening |
| `net.ipv4.conf.all.rp_filter=1` | Strict reverse path filtering |
| `fs.protected_hardlinks`, `fs.protected_symlinks` | Link attack prevention |
| `kernel.kexec_load=0` | Kexec disabled |
| `kernel.kptr_restrict=2` | Kernel pointer restriction |
| `kernel.dmesg_restrict=1` | Dmesg access restricted |
| `kernel.randomize_va_space=2` | Full ASLR |

### Docker Security

- DOCKER-USER chain rules for IPv4/IPv6
- Bridge network rules
- Daemon log rotation with `local` driver
- Live-restore enabled for container survival during daemon restart

### Monitoring & Audit

- **Fail2ban**: SSH jail with UFW ban action
- **Auditd**: Rules tracking identity changes, sudoers modifications, Docker socket access
- **Journald**: Persistent logging with configurable retention

---

## Validation & Testing

### Validate Hardening

After running the script, verify everything is configured correctly:

```bash
# Text output
sudo ./validate_hardening.sh

# JSON output (for automation)
sudo ./validate_hardening.sh --json
```

### Run Tests

The project uses [BATS](https://github.com/bats-core/bats-core) for automated testing:

```bash
# Setup BATS locally
make setup-bats

# Run unit tests (fast, no Docker)
make test-unit-local

# Run all tests with Docker
make test-all

# Run specific test categories
make test-dry-run        # Dry-run integration tests
make test-full-standard  # Full hardening, standard mode
make test-full-tunnel    # Full hardening, tunnel mode
make test-validate       # Validation script tests
make test-idempotency    # Re-run safety tests
```

### CI Integration

| Target | Purpose | Tests Included |
|--------|---------|----------------|
| `make test-ci-pr` | PR gate | unit + dry-run + validate |
| `make test-ci-main` | Main branch gate | full suite |

---

## Project Structure

```
secure_coolify_ubuntu/
├── bootstrap_hardening.sh    # Main hardening script
├── validate_hardening.sh     # Post-hardening verification
├── Makefile                  # Test automation
├── HARDENING_PROCEDURE.md    # Detailed procedure docs
├── docs/
│   ├── testing.md            # Testing guide
│   └── bootstrap_functionality_test_matrix.md
├── tests/
│   ├── unit/                 # Unit tests (fast)
│   ├── integration/          # Integration tests (Docker)
│   └── lib/                  # BATS support libraries
├── Dockerfile.tier1          # Lightweight test container
└── Dockerfile.test           # Full systemd test container
```

---

## CLI Options Reference

### Required

| Option | Description |
|--------|-------------|
| `--admin-user <name>` | Admin username to create |
| `--admin-pubkey "<key>"` | SSH public key for admin user |

### Optional

| Option | Default | Description |
|--------|---------|-------------|
| `--tailscale-cidr <cidr>` | `100.64.0.0/10` | Tailscale network CIDR |
| `--ssh-port <port>` | `22` | SSH port |
| `--wan-iface <iface>` | auto | WAN interface |
| `--tunnel-mode` | `false` | Skip WAN 80/443 (Cloudflare Tunnel) |
| `--swap-size <size>` | `2G` | Swap size (`0` to skip) |
| `--enable-auto-reboot <bool>` | `true` | Auto-reboot after updates |
| `--auto-reboot-time <HH:MM>` | `03:30` | Reboot time |
| `--journal-retention <span>` | `3month` | Journal retention period |
| `--bind-dashboard-to-tailscale` | `false` | Bind Coolify to Tailscale IP |
| `--install-tailscale` | `false` | Install Tailscale |
| `--tailscale-auth-key <key>` | — | Tailscale auth key |
| `--env-file <path>` | — | Load options from file |
| `--dry-run` | `false` | Preview without changes |
| `--force` | `false` | Override safety gates |

All CLI options have corresponding environment variables (e.g., `ADMIN_USER`, `TUNNEL_MODE`).

---

## Requirements & Compatibility

| Requirement | Details |
|-------------|---------|
| **OS** | Ubuntu 24.04 LTS (use `--force` for other versions) |
| **Access** | Root or sudo |
| **Architecture** | amd64, arm64 |

### Before Running

1. Fresh Ubuntu 24.04 installation recommended
2. Have your SSH public key ready
3. (Optional) Tailscale auth key if using Tailscale integration
4. (Optional) Cloudflare Tunnel already configured if using tunnel mode

---

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Run tests: `make test-all`
4. Submit a pull request

See [HARDENING_PROCEDURE.md](HARDENING_PROCEDURE.md) for technical details.

---

## License

[MIT License](LICENSE)

---

## Acknowledgments

- [Coolify](https://coolify.io/) — Self-hosted PaaS
- [BATS](https://github.com/bats-core/bats-core) — Bash Automated Testing System
