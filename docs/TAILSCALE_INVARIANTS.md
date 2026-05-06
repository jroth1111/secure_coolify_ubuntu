# Tailscale Invariants — DO NOT TOUCH

These settings are load-bearing for Tailscale. They must not be removed, disabled, or
inverted by any hardening module.

## Sysctls (set, never removed)

- `net.ipv4.ip_forward = 1` — required for Tailscale subnet routing
- `kernel.unprivileged_userns_clone = 1` — required for tailscaled userspace networking

## systemd units

- `tailscaled.service` and its drop-ins (notably `NotifyAccess=all`)
- Never override or mask these

## Network plane

- `tailscale0` interface and associated routes
- `ts-input`, `ts-forward`, `ts-postrouting` iptables/nftables chains
- Never block `100.64.0.0/10` in UFW
- Never bind sshd exclusively to a public IP (Tailscale SSH path must remain open)

## Tailscale prefs

- `RunSSH=false` — Tailscale SSH is deliberately disabled; it would bypass hardening
- MagicDNS disabled
- IPC socket permissions as set by tailscaled

## Runtime stdout token

- `HARDEN_RESULT_TAILSCALE_IP=<ip>` emitted by `lib/tailscale.sh` end-of-run
- Consumed by `deploy.sh` to route subsequent SSH through Tailscale
