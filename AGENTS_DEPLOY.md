# Deploy Skill — LLM Agent Instructions

## When to Use

- User asks to deploy, provision, or set up a new Coolify server
- User asks to harden a VPS for Coolify
- User wants to go from bare Ubuntu 24.04 to working hardened Coolify

## Collection Sequence

Follow this order. Do NOT ask for secrets until prerequisites pass and mode is decided.

### Step 1: Check operator machine (no user input — run these yourself)

Silently verify before asking the user anything:

```bash
# Check Tailscale is running
tailscale status

# Check SSH key exists
ls ~/.ssh/id_ed25519.pub

# Check required tools
command -v sshpass && command -v jq && command -v curl
```

If any fail, **stop and fix before proceeding**:
- No Tailscale: guide through setup (see Tailscale Setup Guide below)
- No SSH key: offer to generate one (`ssh-keygen -t ed25519`)
- No `sshpass`: install it:
  - macOS: `brew install hudochenkov/sshpass/sshpass`
  - Ubuntu/Debian: `sudo apt-get install -y sshpass`
  - Fedora: `sudo dnf install -y sshpass`
- No `jq`: `brew install jq` / `sudo apt-get install -y jq`

### Step 2: Domain and server (non-secret basics)

Ask for these first — they define what we're deploying and where:

> "What **domain** will this Coolify instance serve? (e.g., `example.com` or `app.example.com` — must be on a Cloudflare-managed zone)
>
> And what's the **server public IP**?"

If the domain is a subdomain like `app.example.com`, note that apps will get subdomains like `myapp.example.com` (siblings at the zone root), not `myapp.app.example.com` (nested — which would break free-tier Universal SSL).

### Step 3: Mode recommendation (informed by domain + workload)

Now that you know the domain, recommend tunnel mode with its constraints:

> "I'll use **tunnel mode** (recommended — zero inbound ports, Cloudflare handles TLS). This works for most apps, but has a few constraints:
> - 100MB upload limit per request (affects Nextcloud, Immich)
> - Media streaming (Jellyfin, Plex) may violate Cloudflare TOS
>
> Will you be hosting any of these? If not, tunnel mode is the way to go."

- If no constraints apply → `tunnel` (default, don't pass `--mode`)
- If constraints apply → `--mode standard`

### Step 4: Credentials (secrets — no defaults possible)

Now collect the values that only the user can provide:

| Input | Example | Notes |
|-------|---------|-------|
| Root password | *(secret)* | For initial SSH to the VPS |
| Tailscale auth key | `tskey-auth-xxxxx` | From Tailscale admin console > Settings > Keys. Must start with `tskey-auth-`. |
| Cloudflare API token | *(secret)* | Must have Zone:DNS:Edit **and** Account:Cloudflare Tunnel:Edit permissions |

**Do not guess or fabricate** any of these — ask explicitly for each.

**State these defaults — don't ask unless user wants to change:**

> "I'll use these defaults unless you want to change any:
> - Admin username: `coolifyadmin`
> - SSH key: `~/.ssh/id_ed25519.pub`
> - Swap size: `2G`"

### Step 5: Confirm and run

Show the full configuration summary (with secrets masked) and confirm before executing.

## Optional Inputs (have defaults)

| Input | Default | Notes |
|-------|---------|-------|
| Mode | `tunnel` | Determined in Step 2. Only pass `--mode standard` if explicitly chosen. |
| Admin username | `coolifyadmin` | Linux user created on server |
| SSH pubkey file | `~/.ssh/id_ed25519.pub` | Path on the machine running the script |
| Swap size | `2G` | Format: `<N>G` or `<N>M` |
| Cloudflare zone | derived from domain | Override if domain's zone differs |

## Operator Machine Prerequisites

Full reference for Step 1 checks:

1. **Tailscale running and connected** — the operator's machine must be on the same tailnet that the server will join. Gates A/B/E require Tailscale connectivity between the laptop and server. Check: `tailscale status` should show "Running".
2. **SSH key pair exists** — default: `~/.ssh/id_ed25519.pub` + `~/.ssh/id_ed25519`. If missing, generate: `ssh-keygen -t ed25519 -C "user@host"`. The script needs both the public key (uploaded to server) and private key (used for post-hardening SSH).
3. **Required CLI tools** — `ssh`, `scp`, `curl`, `jq`, `sshpass`, `ssh-keygen`, `openssl`. The script checks all of these at pre-flight and dies if any are missing.
4. **`sshpass` installation** — this is the most commonly missing tool:
   - macOS: `brew install sshpass` (may need `brew install hudochenkov/sshpass/sshpass` if not in default tap)
   - Ubuntu/Debian: `sudo apt-get install -y sshpass`
   - Fedora: `sudo dnf install -y sshpass`
5. **Working directory** — run `deploy.sh` from the repo root directory (where `bootstrap_hardening.sh`, `validate_hardening.sh`, and `configure_coolify_binding.sh` are located). The script locates companion scripts relative to its own path.

## Tailscale Setup Guide

If the user doesn't have Tailscale yet, walk them through the steps below.

**Key concept:** The operator installs Tailscale on their laptop manually. The script installs Tailscale on the server automatically — `bootstrap_hardening.sh --install-tailscale` installs the Tailscale package via apt, then uses the auth key to join the tailnet non-interactively (`tailscale up --auth-key <key>`). The agent does NOT need to SSH into the server to set up Tailscale.

The flow:
1. Operator sets up Tailscale on laptop (manual — steps below)
2. Operator generates an auth key (manual — step 4 below)
3. `deploy.sh` passes the auth key to `bootstrap_hardening.sh` on the server
4. Server installs Tailscale, joins the tailnet using the auth key, gets a 100.x.x.x IP
5. All subsequent deploy phases SSH to the server via its Tailscale IP

### 1. Create account (if needed)

> "Sign up at [tailscale.com](https://tailscale.com) — free tier supports up to 100 devices, which is more than enough."

### 2. Install on operator's laptop

- **macOS**: `brew install tailscale` or download from [tailscale.com/download](https://tailscale.com/download)
- **Linux**: `curl -fsSL https://tailscale.com/install.sh | sh`
- **Windows**: download from [tailscale.com/download](https://tailscale.com/download)

### 3. Connect the laptop

```bash
# Authenticate (opens browser for login)
sudo tailscale up

# Verify — should show "Running" and your machine's Tailscale IP
tailscale status
```

### 4. Generate an auth key for the server

The deploy script uses this key to join the server to the same tailnet automatically. The user does NOT need to install or configure Tailscale on the server — the script handles that.

> "Go to the Tailscale admin console:
> 1. Open [login.tailscale.com/admin/settings/keys](https://login.tailscale.com/admin/settings/keys)
> 2. Click **Generate auth key**
> 3. Settings: **Reusable** = off, **Ephemeral** = off, **Pre-approved** = on
> 4. Click **Generate key**
> 5. Copy the `tskey-auth-...` value — you'll need it in Step 4 of the Collection Sequence"

**Pre-approved = on** is important: the server joins the tailnet immediately without manual approval in the admin console.

**Ephemeral = off** is important: ephemeral nodes are removed when they go offline, which is wrong for a server.

### 5. Verify after deployment

After `deploy.sh` completes, both machines should appear in `tailscale status`:

```bash
tailscale status
# Should show your laptop AND the server with its 100.x.x.x IP
```

## Cloudflare API Token Guide

If the user has a Cloudflare account but no API token with the right permissions:

> "Create a token at [dash.cloudflare.com/profile/api-tokens](https://dash.cloudflare.com/profile/api-tokens):
> 1. Click **Create Token**
> 2. Start with the **Edit zone DNS** template
> 3. Under **Permissions**, add a second permission: **Account** > **Cloudflare Tunnel** > **Edit**
> 4. Under **Zone Resources**, select **All zones** (or the specific zone for your domain)
> 5. Click **Continue to summary** → **Create Token**
> 6. Copy the token value — you'll need it in Step 4"

The token needs exactly two permissions:
- **Zone : DNS : Edit** — for creating A/CNAME records (including wildcard)
- **Account : Cloudflare Tunnel : Edit** — for creating the tunnel (tunnel mode only, but always included since tunnel is the default)

## Invocation

### From operator laptop (preferred)

```bash
# Tunnel mode (default — recommended)
bash deploy.sh \
  --server-ip <ip> \
  --root-pass <pass> \
  --admin-user <user> \
  --pubkey-file <path> \
  --tailscale-auth-key <key> \
  --domain <fqdn> \
  --cf-api-token <token> \
  --yes

# Standard mode (if user explicitly requests open 80/443)
bash deploy.sh \
  --server-ip <ip> \
  --root-pass <pass> \
  --admin-user <user> \
  --pubkey-file <path> \
  --tailscale-auth-key <key> \
  --mode standard \
  --domain <fqdn> \
  --cf-api-token <token> \
  --yes
```

### From the server directly

```bash
sudo bash setup.sh \
  --server-ip <ip> \
  --admin-user <user> \
  --pubkey-file <path> \
  --tailscale-auth-key <key> \
  --domain <fqdn> \
  --cf-api-token <token> \
  --yes
```

The `--yes` flag is required for non-interactive (agent) execution — it skips confirmation prompts.

Omitting `--mode` defaults to `tunnel`. Only pass `--mode standard` if the user explicitly asks for open public ports.

## Expected Output

- Each phase prints `[N/5] Phase description` with color-coded progress
- Gates print `PASS` or `FAIL` with details
- Final summary box shows: Tailscale IP, dashboard URL, DNS record, admin user, SSH command

## Phases

1. **Pre-flight** — validates tools, SSH pubkey, Cloudflare token + zone + account, SSH connectivity
2. **Harden** — uploads scripts, runs `bootstrap_hardening.sh` with `--tunnel-mode`, captures Tailscale IP
3. **Gates** — verifies SSH transition to admin@tailscale-IP (Gate A-B), runs `validate_hardening.sh --json` for hardening verification (Gate C)
4. **Docker + Coolify** — installs Docker, starts DOCKER-USER rules, installs Coolify
5. **DNS + Verify** — configures dashboard binding, creates Cloudflare Tunnel + CNAME + wildcard DNS (or A + wildcard A in standard mode), final checks

## Post-Deploy Steps (Required — Inform the User)

After the script completes, the operator must do these three things to enable automatic SSL + subdomains for every app:

1. **Cloudflare dashboard: SSL/TLS > Overview** — set encryption mode to **Full** (not Flexible, not Full Strict)
2. **Coolify UI: Servers > your server > Wildcard Domain** — set to the zone root (e.g., `example.com`). This tells Coolify to auto-assign subdomains like `myapp.example.com` to every new resource. Since the scripts already created wildcard DNS + tunnel ingress, each subdomain gets SSL and routing automatically — zero per-app DNS or cert work.
3. **Coolify resource domains** — must use `http://` protocol (not `https://`), because Cloudflare terminates TLS at the edge

After these three steps, every new app deployed in Coolify gets a subdomain + SSL automatically.

Inform the user of these steps after deployment completes.

## TLS Architecture

Both modes use Cloudflare's edge for user-facing TLS. No wildcard cert is needed on the origin:

- **Tunnel mode**: Cloudflare terminates TLS. Tunnel delivers HTTP to `localhost:80` (Traefik). No origin cert.
- **Standard mode** (proxied + Full SSL): Cloudflare terminates edge TLS. Full mode accepts any origin cert (self-signed OK).

The `--cf-api-token` is used for DNS record management via Cloudflare's REST API. Wrangler CLI is not applicable (it only manages Workers/R2/D1/Pages — no DNS commands).

If the user asks about origin wildcard certs (Traefik DNS-01 with Cloudflare token): this requires editing Coolify's Traefik proxy config in the Coolify UI (Servers > Proxy), not our scripts. The same `--cf-api-token` works as `CF_DNS_API_TOKEN` in Traefik. See [Coolify wildcard cert docs](https://coolify.io/docs/knowledge-base/proxy/traefik/wildcard-certs).

## Execution Notes

- **Timeout**: the script takes 10–20 minutes end-to-end (hardening + Docker + Coolify install are the slow phases). Set Bash tool timeout to at least 1200000ms (20 min). Running in background is recommended so you can monitor progress.
- **Output**: the script prints a summary box at the end with Tailscale IP, dashboard URL, DNS records, admin user, and SSH command. Relay this to the user.
- **Re-runs**: all scripts are idempotent. If a run fails partway, fix the issue and re-run the same command. One caveat: if a Cloudflare Tunnel was already created (name collision), the API will return an error. The tunnel name is derived from the domain (`<domain-prefix>-coolify`). If this happens, delete the stale tunnel in Cloudflare dashboard (Zero Trust > Networks > Tunnels) and re-run.
- **Secrets in process list**: `--root-pass` and `--cf-api-token` will briefly appear in `ps` output during invocation. The script uses `SSHPASS` env var internally (not CLI args) for SSH operations. This is acceptable for single-operator laptops but the user should be aware.

## Error Handling

- If a gate fails, the script stops with diagnostic output
- All scripts are idempotent — safe to re-run to retry after fixing the issue
- Never attempt to edit `bootstrap_hardening.sh` or `validate_hardening.sh` to work around failures
- Pre-flight failures exit immediately with no server-side changes

## Tunnel Mode Limitations (important — ask the user about these)

Before defaulting to tunnel mode, check whether these constraints affect the user's workload:

1. **100MB upload limit** — Cloudflare Free/Pro plans cap request bodies at 100MB. Apps accepting large file uploads (Nextcloud, Immich photo/video backup) will get `413 Payload Too Large` for files over 100MB. With standard mode, specific subdomains can be set to DNS-only ("grey cloud") to bypass this. With tunnel mode, there is no bypass.
2. **Nested subdomain TLS** — Free-plan Universal SSL covers `*.example.com` but not `*.app.example.com`. If Coolify generates deeply nested PR preview subdomains, they will fail TLS. Use single-level subdomains or Advanced Certificate Manager.
3. **Media streaming** — Heavy video streaming (Jellyfin, Plex) through Cloudflare may violate their CDN-specific terms of service and trigger throttling or account action. If the user hosts media servers, recommend `--mode standard` with DNS-only for media subdomains.
4. **Cloudflare Access + webhooks** — If the user plans to add Cloudflare Access (Zero Trust auth) later, GitHub/GitLab webhooks will break unless they create IP-based bypass policies for webhook paths.

## Decision Tree

Follow the Collection Sequence above. This tree handles branching decisions:

1. **Operator machine ready?** (Collection Step 1) -> if not, fix prerequisites first
2. **Mode choice** (Collection Step 2):
   - Default to `tunnel` unless any of the following apply:
   - User hosts file-upload-heavy apps (Nextcloud, Immich) with files >100MB -> `standard`
   - User hosts media streaming apps (Jellyfin, Plex) -> `standard`
   - User needs per-subdomain edge bypass flexibility (grey-cloud) -> `standard`
   - User has non-Cloudflare domains that need direct origin access -> `standard`
   - If none apply, `tunnel` is the best choice (zero inbound ports, no IP exposure)
3. **Missing external accounts?** (Collection Step 4):
   - No Tailscale -> walk through Tailscale Setup Guide above (account + install + auth key)
   - No Cloudflare API token -> they need to create one at [dash.cloudflare.com/profile/api-tokens](https://dash.cloudflare.com/profile/api-tokens) with **Zone:DNS:Edit** and **Account:Cloudflare Tunnel:Edit** permissions
4. **Laptop or server?**
   - Laptop -> `deploy.sh` (needs `--root-pass`)
   - Server -> `setup.sh` (no root password needed)
5. Run with `--yes` for non-interactive execution

## Troubleshooting

| Symptom | Likely Cause | Fix |
|---------|-------------|-----|
| Pre-flight fails: `sshpass` not found | `sshpass` not installed on operator machine | macOS: `brew install hudochenkov/sshpass/sshpass`; Linux: `apt install sshpass` |
| Pre-flight fails: SSH key not found | No key at `~/.ssh/id_ed25519.pub` | Generate: `ssh-keygen -t ed25519`, or pass `--pubkey-file <path>` |
| Gate A fails (SSH timeout) | Tailscale not running on operator laptop, or not on same tailnet | Run `tailscale status` on laptop; ensure both machines are on same Tailnet |
| Gate C fails (validation) | Hardening step partially failed | Check `/var/log/bootstrap-hardening.log` on server; run `sudo /root/validate_hardening.sh --json` to see which checks failed |
| Gate D fails (no DOCKER-USER rules) | Docker not fully started | Run `sudo systemctl restart docker` then `sudo systemctl start docker-user-hardening.service` |
| Cloudflare zone not found | Domain not on Cloudflare or wrong zone | Use `--cf-zone` to specify the root zone explicitly |
| Tunnel creation fails (permissions) | API token lacks Account:Tunnels:Edit | Regenerate token with correct permissions |
| Tunnel creation fails (name exists) | Previous partial run created a tunnel | Delete stale tunnel in Cloudflare dashboard (Zero Trust > Networks > Tunnels), re-run |
| `cloudflared` won't start | Credentials file mismatch | Check `/etc/cloudflared/config.yml` and credentials JSON |
| `TOO_MANY_REDIRECTS` on app | Resource domain using `https://` in Coolify | Change to `http://` — Cloudflare handles TLS at edge |
| Apps unreachable after deploy | SSL/TLS mode set to Flexible | Change to Full in Cloudflare dashboard |
| `413 Payload Too Large` on upload | Cloudflare 100MB limit (Free/Pro) | Use chunked uploads in app, or redeploy with `--mode standard` and grey-cloud the subdomain |
| `ERR_SSL_VERSION_OR_CIPHER_MISMATCH` | Nested subdomain (`*.app.example.com`) not covered by Universal SSL | Use single-level subdomains, or purchase Advanced Certificate Manager |
| GitHub webhooks fail after adding Cloudflare Access | Access blocks unauthenticated POST requests | Create bypass policy for webhook paths, allowlisting GitHub IPs from `https://api.github.com/meta` |
