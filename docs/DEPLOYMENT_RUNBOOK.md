# Deployment Runbook — Bare Server to Working Coolify

This guide walks through the complete journey from a fresh Ubuntu 24.04 VPS to a hardened, working Coolify deployment accessible only via Tailscale.

## Automated Alternative

For a fully automated deployment, use `deploy.sh` (from your laptop) or `setup.sh` (from the server). These scripts automate hardening, gate checks, Cloudflare Tunnel creation, and DNS configuration:

```bash
# Tunnel mode (default — recommended)
bash deploy.sh --server-ip <ip> --root-pass <pass> --tailscale-auth-key <key> \
  --domain <fqdn> --cf-api-token <token> --yes

# Standard mode (open public 80/443)
bash deploy.sh --server-ip <ip> --root-pass <pass> --tailscale-auth-key <key> \
  --domain <fqdn> --cf-api-token <token> --mode standard --yes
```

See `deploy.sh --help` for all options. The manual procedure below remains the reference for understanding each step.

---

## Safety Gates (Mandatory)

Treat this runbook as a gated procedure. Do not proceed to the next phase until the current gate passes.

- **Gate A (before hardening):** Root SSH over Tailscale works.
- **Gate B (immediately after hardening):** Admin SSH over Tailscale works from a new terminal before closing the root session.
- **Gate C (before Docker/Coolify):** `validate_hardening.sh` exits `0` with no FAIL checks.
- **Gate D (after Docker install):** `docker-user-hardening.service` is active and managed DOCKER-USER rules exist.
- **Gate E (after split-horizon binding):** Coolify dashboard is reachable on Tailscale IP and not reachable on public IP.

If any gate fails: stop, fix the issue, and re-run the same gate.

### Automated Gate Mapping

Automated scripts (`deploy.sh`/`setup.sh`) use this gate mapping:

- `deploy.sh` Gate A/B/C/D/E correspond to admin SSH over Tailscale, identity check, hardening validation, DOCKER-USER service+rules, and dashboard exposure boundary checks.
- `setup.sh` Gate A and Gate E are operator-confirmed laptop checks (prompted), while Gate B/C/D are script-enforced checks.
- Manual phase labels in this runbook remain authoritative for the manual procedure; automated scripts enforce equivalent control intent with script-specific checkpoints.

## Prerequisites

- A VPS provider account (Hetzner, DigitalOcean, Vultr, etc.)
- A [Tailscale](https://tailscale.com) account
- An SSH key pair (ed25519 recommended: `ssh-keygen -t ed25519`)
- A domain name (for Coolify SSL/reverse proxy)
- Two local terminals available (one can stay connected while validating new access paths)

---

## Phase 0: Local Preparation

### 0.1 Generate SSH Key (if needed)

```bash
ssh-keygen -t ed25519 -C "your-email@example.com"
cat ~/.ssh/id_ed25519.pub
# Copy this — you'll need it for Phase 2
```

### 0.2 Create Tailscale Account

1. Sign up at [tailscale.com](https://tailscale.com)
2. Install Tailscale on your local machine
3. Note your Tailscale auth key or plan to use interactive login on the server

---

## Phase 1: Server Provisioning

### 1.1 Create VPS

- **OS**: Ubuntu 24.04 LTS
- **RAM**: 2GB minimum (4GB+ recommended for Coolify)
- **Storage**: 40GB+ SSD
- **Region**: Choose based on your needs

### 1.2 Initial SSH Access

```bash
# Use the provider's SSH key or root password for initial access
ssh root@<server-public-ip>
```

### 1.3 Install Tailscale

Install via the official apt repository (not `curl | sh`):

```bash
# Add Tailscale's GPG key and repository
curl -fsSL https://pkgs.tailscale.com/stable/ubuntu/noble.noarmor.gpg \
  | sudo tee /usr/share/keyrings/tailscale-archive-keyring.gpg >/dev/null
curl -fsSL https://pkgs.tailscale.com/stable/ubuntu/noble.tailscale-keyring.list \
  | sudo tee /etc/apt/sources.list.d/tailscale.list

# Install
sudo apt-get update
sudo apt-get install -y tailscale

# Authenticate (interactive — opens a URL to authorize)
sudo tailscale up

# Verify
tailscale status
tailscale ip -4
# Note the 100.x.x.x IP — you'll use this for all future SSH access
```

### 1.4 Gate A: Verify Tailscale SSH Access

From your local machine (which should also be on Tailscale):

```bash
ssh root@<tailscale-ip>
```

If this works, Gate A passes. **From this point forward, use the Tailscale IP for all SSH connections.**

---

## Phase 2: Hardening

### 2.1 Upload the Script

```bash
scp bootstrap_hardening.sh root@<tailscale-ip>:/root/
scp validate_hardening.sh root@<tailscale-ip>:/root/
ssh root@<tailscale-ip>
chmod +x /root/bootstrap_hardening.sh /root/validate_hardening.sh
```

### 2.2 Run Hardening

**Tunnel mode (recommended)** — no inbound web ports; public traffic via Cloudflare Tunnel:

```bash
sudo ./bootstrap_hardening.sh \
  --admin-user coolifyadmin \
  --admin-pubkey "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... your-key" \
  --tunnel-mode \
  --swap-size 2G
```

**Standard mode** — direct web traffic on ports 80/443 (use only if Cloudflare Tunnel is not an option):

```bash
sudo ./bootstrap_hardening.sh \
  --admin-user coolifyadmin \
  --admin-pubkey "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... your-key" \
  --swap-size 2G
```

**With env file** (for automation):

```bash
cat > /etc/bootstrap-hardening.env << 'EOF'
ADMIN_USER=coolifyadmin
ADMIN_PUBKEY="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... your-key"
TUNNEL_MODE=true
SWAP_SIZE=2G
EOF
chmod 600 /etc/bootstrap-hardening.env

sudo ./bootstrap_hardening.sh --env-file /etc/bootstrap-hardening.env
```

Keep this root session open until Gate B and Gate C pass.

### 2.3 Gate B: Verify SSH Access Post-Hardening

**Important:** Before closing your current SSH session, verify you can connect via Tailscale as the admin user:

```bash
# From your LOCAL machine (new terminal):
ssh coolifyadmin@<tailscale-ip>
```

If this succeeds, Gate B passes. The old root SSH access from public IPs is now blocked.

### 2.4 Gate C: Validate Hardening Before Stack Install

Run validation from the server and require a zero exit code:

```bash
sudo ./validate_hardening.sh
echo $?
```

Expected: `0`. If the script reports FAIL items or exits non-zero, stop and remediate before Docker/Coolify installation.

---

## Phase 3: Stack Installation

### 3.1 Install Docker

SSH in as your admin user via Tailscale:

```bash
ssh coolifyadmin@<tailscale-ip>
```

Install Docker using the official script:

```bash
curl -fsSL https://get.docker.com | sudo sh
sudo systemctl enable --now docker

# Verify
sudo docker run hello-world
```

If Docker was absent during Phase 1, `bootstrap_hardening.sh` installs the policy but does not create `/etc/docker/daemon.json` yet. Coolify's installer may then create/update `daemon.json` (for Docker address pools). The automated `deploy.sh`/`setup.sh` workflows reconcile this file immediately after Coolify install to enforce hardening keys while preserving Coolify's settings.

**daemon.json Ownership:**
- **Hardening owns:** `log-driver` (set to `json-file` to match Coolify's expectation), `log-opts`, `live-restore`
- **Coolify may add:** `default-address-pools` and other settings
- **Drift detection:** The reconcile functions warn if hardening keys were changed (e.g., by a Coolify update)

### 3.2 Gate D: Restart and Verify DOCKER-USER Hardening

After Docker is installed, activate the pre-installed DOCKER-USER rules:

```bash
sudo systemctl start docker-user-hardening.service
sudo systemctl status docker-user-hardening.service

# Verify rules are applied
sudo iptables -t filter -S DOCKER-USER | grep coolify-hardening
```

For standard mode, expect a `coolify-hardening-wan-web` rule.
For tunnel mode, ensure `coolify-hardening-wan-web` is absent while `coolify-hardening-wan-drop` is present.

### 3.3 Install Coolify

```bash
curl -fsSL https://cdn.coollabs.io/coolify/install.sh | sudo bash
```

Coolify will be available at `http://<tailscale-ip>:8000` by default.

---

## Phase 4: Post-Hardening Configuration

### 4.1 Split-Horizon Dashboard Binding (Recommended)

By default, Coolify binds to `0.0.0.0:8000`, making it accessible on all interfaces. To restrict the dashboard to Tailscale only, use the companion script:

```bash
scp configure_coolify_binding.sh coolifyadmin@<tailscale-ip>:/root/
ssh coolifyadmin@<tailscale-ip>

sudo ./configure_coolify_binding.sh
```

This binds Coolify's management ports to your Tailscale IP only. Verify:

```bash
sudo ss -tlnp | grep 8000
# Should show 100.x.x.x:8000 instead of 0.0.0.0:8000
```

### 4.2 Gate E: Confirm Dashboard Exposure Boundaries

```bash
# Should succeed
curl -s -o /dev/null -w '%{http_code}' http://<tailscale-ip>:8000

# Should fail when split-horizon binding is enabled
curl -s -o /dev/null -w '%{http_code}' http://<public-ip>:8000
```

Gate E passes when the dashboard is reachable over Tailscale and not reachable over public IP.

### 4.3 DNS Configuration

- **Tunnel mode (default)**: `deploy.sh`/`setup.sh` automatically creates a CNAME for your domain **and** a wildcard CNAME (`*.example.com`) pointing to `<tunnel-id>.cfargotunnel.com`. The tunnel ingress config also includes a wildcard hostname rule. This means apps deployed on subdomains (`app1.example.com`, `app2.example.com`) work immediately — no manual DNS or tunnel configuration needed.
- **Standard mode**: `deploy.sh`/`setup.sh` automatically creates an A record for your domain **and** a wildcard A record (`*.example.com`) pointing to the server's public IP (Cloudflare-proxied).

### 4.4 Post-Deploy: Enable Automatic SSL + Subdomains

After deployment, complete these three steps to enable fully automatic subdomain + SSL for every app:

1. **Cloudflare dashboard → SSL/TLS → Overview**: Set encryption mode to **Full**. Do not use Flexible (sends plaintext to origin) or Full Strict (tunnel does not present an origin certificate).

2. **Coolify UI → Servers → your server → Wildcard Domain**: Set to your zone root (e.g., `example.com`). This tells Coolify to auto-assign subdomains like `myapp.example.com` to every new resource you deploy. Since the scripts already created wildcard DNS records and tunnel ingress rules, each subdomain gets SSL (via Cloudflare Universal SSL) and routing (via Traefik Host-header matching) automatically — zero per-app DNS or cert configuration.

3. **Resource domains in Coolify**: Use `http://` protocol — not `https://`. Cloudflare terminates TLS at the edge and sends HTTP through the tunnel. Using `https://` causes `TOO_MANY_REDIRECTS`.

After these steps, the end-to-end flow for every new app is: deploy in Coolify → auto-assigned `<name>.example.com` → DNS resolves via wildcard → Cloudflare edge SSL → tunnel/proxy → Traefik → container. Fully automatic.

**Monitoring**: `cloudflared` runs as a systemd service with auto-restart. If it stops, all public web traffic stops (admin access via Tailscale is unaffected). Check status: `sudo systemctl status cloudflared`.

### 4.5 TLS Architecture

Both deployment modes use Cloudflare's edge for user-facing TLS via Universal SSL (`*.example.com`). No wildcard certificate is needed on the origin server:

- **Tunnel mode**: Cloudflare terminates TLS at the edge. The tunnel delivers HTTP to `localhost:80` (Traefik). No origin cert required.
- **Standard mode** (proxied + Full SSL): Cloudflare terminates edge TLS and connects to the origin via HTTPS, but Full mode accepts any cert — including self-signed or Traefik's default. No wildcard cert required.

**Optional: origin wildcard certs.** If you need Full (Strict) SSL or DNS-only subdomains where Traefik terminates TLS, configure Traefik's DNS-01 challenge with your Cloudflare API token in the Coolify UI (Servers > Proxy). See [Coolify wildcard cert docs](https://coolify.io/docs/knowledge-base/proxy/traefik/wildcard-certs). Add `CF_DNS_API_TOKEN` as an environment variable in the Traefik container. This is a Coolify-level config change — our hardening scripts do not modify it.

### 4.6 Tunnel Mode Limitations

Be aware of these constraints when running in tunnel mode:

- **100MB upload limit**: Cloudflare Free/Pro plans cap request bodies at 100MB. Apps with large uploads (Nextcloud, Immich) need chunked upload support, or use `--mode standard` and set the upload subdomain to DNS-only in Cloudflare.
- **Nested subdomain TLS**: Universal SSL (free plan) covers `*.example.com` but not `*.app.example.com`. Avoid deeply nested subdomains for Coolify PR previews, or purchase Advanced Certificate Manager.
- **Media streaming TOS**: Heavy video streaming (Jellyfin, Plex) through Cloudflare may violate CDN-specific terms. Use standard mode with DNS-only for media subdomains.
- **Cloudflare Access + webhooks**: If you add Cloudflare Access later, create IP-based bypass policies for CI/CD webhook paths.

If these constraints affect your workload, redeploy with `--mode standard`.

### 4.7 Manual Cloudflare Tunnel Setup (if not using deploy.sh)

If you ran hardening manually and need to set up the tunnel by hand:

```bash
# Install cloudflared
sudo apt-get install -y cloudflared

# Authenticate and create tunnel
cloudflared tunnel login
cloudflared tunnel create coolify-tunnel

# Route DNS: exact domain + wildcard for subdomains
cloudflared tunnel route dns coolify-tunnel your-domain.com
cloudflared tunnel route dns coolify-tunnel "*.your-domain.com"
```

Then write `/etc/cloudflared/config.yml` with wildcard ingress:

```yaml
tunnel: <tunnel-id>
credentials-file: /etc/cloudflared/<tunnel-id>.json

ingress:
  - hostname: your-domain.com
    service: http://localhost:80
  - hostname: "*.your-domain.com"
    service: http://localhost:80
  - service: http_status:404
```

Start the service:

```bash
sudo cloudflared service install
sudo systemctl enable --now cloudflared
```

See [Cloudflare Tunnel docs](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/get-started/) for details.

---

## Phase 5: Verification

### 5.1 Run Validation Script

```bash
sudo ./validate_hardening.sh
```

All checks should show PASS. Review any FAIL or INFO items.

### 5.2 JSON Report

```bash
sudo ./validate_hardening.sh --json | python3 -m json.tool
```

### 5.3 Smoke Tests

```bash
# SSH: verify Tailscale-only access
ssh coolifyadmin@<tailscale-ip>           # Should work
ssh coolifyadmin@<public-ip> 2>&1 || true # Should fail/timeout

# Coolify dashboard (after split-horizon binding):
curl -s -o /dev/null -w '%{http_code}' http://<tailscale-ip>:8000  # Should return 200
curl -s -o /dev/null -w '%{http_code}' http://<public-ip>:8000     # Should fail

# Tunnel mode: verify cloudflared is running and no public HTTP ports
sudo systemctl status cloudflared        # Should be active
sudo ufw status verbose                  # Should NOT show 80/443 ALLOW on WAN
curl -s -o /dev/null -w '%{http_code}' https://<your-domain>  # Should return 200 (via tunnel)

# Standard mode: verify public web access
curl -s -o /dev/null -w '%{http_code}' http://<public-ip>     # Should return 200 (or redirect)

# Firewall state
sudo ufw status verbose
sudo iptables -t filter -S DOCKER-USER

# Swap
free -m
swapon --show

# NTP
timedatectl status

# BBR (if available)
sysctl net.ipv4.tcp_congestion_control
```

## Phase 6: Capture State Artifacts

Capture current hardening state and report output for incident response and handoff:

```bash
cat /var/lib/bootstrap-hardening/state
cat /var/log/bootstrap-hardening-report.json
```

---

## Maintenance

### Re-running Hardening

The script is idempotent. To change settings:

```bash
sudo ./bootstrap_hardening.sh \
  --admin-user coolifyadmin \
  --admin-pubkey "ssh-ed25519 ..." \
  --swap-size 4G \
  --journal-retention 6month
```

### Checking Status

```bash
sudo ./validate_hardening.sh
cat /var/lib/bootstrap-hardening/state
cat /var/log/bootstrap-hardening-report.json
```

### Viewing Logs

```bash
# Hardening script log
sudo cat /var/log/bootstrap-hardening.log

# fail2ban bans
sudo fail2ban-client status sshd

# Audit events
sudo ausearch -k identity --start recent
sudo ausearch -k sudoers-change --start recent
```
