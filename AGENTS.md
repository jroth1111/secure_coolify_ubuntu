# AGENTS.md — Agent Governance Spec

---

## Deploy Skill

Before deploying or provisioning a Coolify server, read [`AGENTS_DEPLOY.md`](AGENTS_DEPLOY.md)
for the full collection sequence, invocation reference, and troubleshooting guide.

---

## 1. Intent → Atomic Tasks

Decompose user requests into tasks.

---

## 2. State Transitions

Work follows claim → execute → verify → close. Project-specific additions:

- **Never start a deployment task** without first verifying operator machine prerequisites
- **Never start phase 4** (Docker+Coolify) unless Gate C JSON shows `"fail":0`.
- **Never close a deployment task** without recording the gate output in the task notes.
- **Never close a script-change task** without `bash -n <script>` passing and the result recorded.

---

## 3. Quality Gates (Machine-Checkable)

### Pre-Work Gate (run before starting any task)

```bash
bash -n deploy.sh setup.sh \
     lib/coolify-common.sh \
     validate_hardening.sh \
     bootstrap_hardening.sh \
     configure_coolify_binding.sh
```

Must be clean. If syntax check fails on an unmodified file, stop and escalate — do not proceed
until the cause is understood.

### Pre-Close Gate (run before closing a task)

| Task type | Required evidence |
|-----------|------------------|
| Script edited | `bash -n <script>` → zero errors; recorded in task notes |
| Gate C ran | `validate_hardening.sh --json` output with `"fail":0`; recorded in task notes |
| DNS/tunnel changed | CF API GET confirms record exists with correct value; recorded in task notes |
| Full deploy completed | Final `validate_hardening.sh --json` with `"fail":0`; summary box captured in task notes |

---

## 4. Invariants — Do Not Break

These are external contracts and security properties. Treat them as read-only unless an
invariant change is the explicit, user-confirmed goal.

### Machine-Readable API Contracts

| Contract | Defined in | Consumed by |
|----------|-----------|-------------|
| `validate_hardening.sh --json` schema: `{"pass":N,"fail":N,"info":N,"checks":[...]}` | `validate_hardening.sh` | `report_validation_result()` in `lib/coolify-common.sh` |
| `HARDEN_RESULT_TAILSCALE_IP=<ip>` sentinel — last stdout line of bootstrap | `bootstrap_hardening.sh` | `deploy.sh` phase 1 via `tee` capture (only channel after UFW blocks root SSH) |
| State file at `/var/lib/bootstrap-hardening/state` — key=value, sourced at runtime | `bootstrap_hardening.sh write_state()` | `validate_hardening.sh` — field names are implicit API |
| Tunnel name `${DOMAIN%%.*}-coolify` — used for stale-tunnel lookup by name | `lib/coolify-common.sh cf_create_tunnel()` | Same function on re-run (DELETE by name before CREATE) |

Changing any of these without updating all consumers is a breaking change. Changes to
`validate_hardening.sh` JSON fields require matching changes to `report_validation_result()`.
Changes to the sentinel name require matching changes in `deploy.sh` phase 1.

### Security Invariants — Must Not Weaken

- **UFW**: default-deny incoming; SSH only on `tailscale0`; dashboard ports (8000/6001/6002)
  only on `tailscale0`; WAN 80/443 absent in tunnel mode.
- **DOCKER-USER**: WAN ingress dropped in tunnel mode; bridge traffic returned; no WAN bypass.
- **SSH**: global `PermitRootLogin no`; key-only root login only from localhost + Docker bridge
  (127.0.0.1, 172.16.0.0/12, 10.0.0.0/8) via the `Match Address` block.
- **fail2ban**: ignores Tailscale CIDR (100.64.0.0/10); bans WAN brute-force.

### Idempotency Contract

Every operation in every script must be safe to re-run on an already-provisioned server.
Companion scripts are re-uploaded and re-run every time `--ts-ip` resumes a deployment
(via `sync_companion_scripts()` in phase 2). Any non-idempotent logic is a bug.

---

## 5. Auditability

Every task close must include evidence, not just intent. Example:

```
Fixed fstab grep pattern in validate_hardening.sh swap_check;
bash -n exits 0; Gate C passed on resume with --ts-ip 100.x.x.x (0 failures)
```

Append raw gate output to task notes for deployment tasks. Trace each code change back to a
task. No ad-hoc edits outside the task loop.

---

## 6. Destructive Operations — Confirm Before Executing

These affect live infrastructure and are difficult or impossible to reverse:

| Operation | Impact |
|-----------|--------|
| Running `deploy.sh` or `setup.sh` against a server | Irreversible system changes (UFW reset, SSH hardening) |
| Deleting a Cloudflare Tunnel | Drops live traffic for all tunnel-routed apps immediately |
| Deleting or modifying Cloudflare DNS records | Drops or misdirects live traffic |
| `ufw --force reset` on a live server | Removes all firewall rules; may lock out all SSH access |
| Editing `/data/coolify` files or querying `coolify-db` | Risk of Coolify data corruption |

State the exact command and its effect before running. Wait for explicit user confirmation.

---

## Script Edit Policy

The shell scripts are frozen — tested against a live deployment. **Do not edit any `.sh` file**
without an explicit instruction:

- `bootstrap_hardening.sh`
- `validate_hardening.sh`
- `configure_coolify_binding.sh`
- `deploy.sh`
- `setup.sh`
- `lib/coolify-common.sh`

Files free to edit: `AGENTS_DEPLOY.md`, `AGENTS.md`.

**Exception — Gate C false positives**: If Gate C fails and the failing check does not correspond
to any real server misconfiguration, the cause may be a bug in `validate_hardening.sh`
(wrong grep pattern, missing format variant). Protocol:

1. Confirm on the server that the expected state actually holds (e.g., `swapon --show`,
   `cat /etc/fstab`) before concluding it is a false positive.
2. Fix `validate_hardening.sh` locally — this is a legitimate edit.
3. Resume with `--ts-ip <ip>` — the corrected script is re-synced automatically via
   `sync_companion_scripts()` in phase 2.
4. **Never comment out or weaken a check to suppress a real failure.**

---

## Recovery Rules

### Phase 1 output gap (3–5 min silence in background output file)
Normal. `tee` block-buffers when stdout is not a terminal. `unattended-upgrades` and Tailscale
install produce no output while running. Wait for `PASS Hardening completed` followed by
`PASS Server Tailscale IP: 100.x.x.x`.

### Wrong root password (`sshpass` exit code 5)
VPS providers auto-generate a new root password after a rebuild. Verify the current password
in the VPS control panel. Re-run with the correct `--root-pass`.

### Gate A/B fails (SSH timeout)
Check `tailscale status` on operator machine. If the server appears in the Tailscale admin
panel with a `100.x.x.x` IP, resume with `--ts-ip <ip>`.

### Gate C fails
Distinguish cause before touching anything:

1. **Real server failure**: read `/var/log/bootstrap-hardening.log` on server; run
   `sudo /root/validate_hardening.sh --json` and inspect `"checks"` array for failing items.
   Fix the server condition, then resume with `--ts-ip`.
2. **Script false positive**: verify the expected state directly on the server. If correct,
   fix `validate_hardening.sh` locally (see Script Edit Policy exception above).

### No ready tasks mid-deployment
If phase 1 completed (server has a Tailscale IP), create a task to resume from phase 2
via `--ts-ip <ip>` and proceed.

### Escalation trigger
If two consecutive recovery attempts produce no progress — stop, document current state in
task notes, and surface a decision request to the user before continuing.
