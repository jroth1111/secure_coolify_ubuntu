# Cloudflare Wildcard DNS + SSL (Free Plan) with Coolify

## Summary
- Cloudflare wildcard DNS records are available on all plans, including Free.
- Cloudflare Universal SSL (Free) covers the apex and first-level subdomains only.
- On a typical full Cloudflare zone, `appname.vps.example.com` is a second-level subdomain and is not covered by Universal SSL.
- For a Free-plan, proxied setup with Coolify, prefer `appname.example.com` (or another first-level pattern).

## Findings

### 1) Cloudflare wildcard DNS behavior
- You can create wildcard DNS records (proxied or DNS-only) on all plans.
- Cloudflare supports wildcard records at deeper labels too (for example, `*.www`).
- Specific records take precedence over wildcard records.

Source:
- https://developers.cloudflare.com/dns/manage-dns-records/reference/wildcard-dns-records/

### 2) Cloudflare Universal SSL limits on Free plan
- Universal SSL is free and available on Free/Pro/Business/Enterprise.
- In full DNS setup, Universal SSL covers apex + first-level only.
- For second-level and deeper hostnames (for example, `dev.www.example.com`), Cloudflare requires either:
  - Advanced Certificate Manager (paid add-on), or
  - uploaded custom certs on Business/Enterprise.

Sources:
- https://developers.cloudflare.com/ssl/edge-certificates/universal-ssl/
- https://developers.cloudflare.com/ssl/edge-certificates/universal-ssl/enable-universal-ssl/
- https://developers.cloudflare.com/ssl/edge-certificates/universal-ssl/limitations/
- https://developers.cloudflare.com/ssl/edge-certificates/advanced-certificate-manager/

### 3) Coolify domain and SSL behavior
- Coolify supports regular and wildcard DNS patterns, and can auto-generate domains when server wildcard domain is configured.
- Coolify auto-requests Let's Encrypt certs for `https://` domains.
- If Cloudflare proxy interferes with HTTP/TLS-ALPN validation, Coolify docs say to use DNS challenge or disable proxy.
- For wildcard certs in Traefik, Coolify requires DNS challenge.

Sources:
- https://coolify.io/docs/knowledge-base/dns-configuration
- https://coolify.io/docs/knowledge-base/domains
- https://coolify.io/docs/troubleshoot/dns-and-domains/lets-encrypt-not-working
- https://coolify.io/docs/knowledge-base/proxy/traefik/wildcard-certs
- https://letsencrypt.org/docs/challenge-types/

### 4) Free-plan practical impact
- `appname.example.com` = first-level under zone apex → covered by Universal SSL (when proxied).
- `appname.vps.example.com` = second-level under zone apex → not covered by Universal SSL on Free plan.

## Decision
- If you want Cloudflare proxy + SSL on Free plan, use:
  - `appname.example.com` (recommended), not `appname.vps.example.com`.

## Exceptions
- `appname.vps.example.com` can still work if you:
  - run it DNS-only (grey cloud) and terminate TLS at origin (Coolify/Traefik/Let's Encrypt), or
  - buy Advanced Certificate Manager (paid), or
  - use an alternate zone design where `vps.example.com` is a separately delegated/activated zone.
