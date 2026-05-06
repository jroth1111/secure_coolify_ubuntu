# Free SSL Providers For Direct Tailscale Custom-Domain Access

## Executive Summary

For this deployment model, the practical free-provider choice set is much narrower than it first appears.

The goal is not merely to obtain a certificate. The goal is to obtain a browser-trusted certificate for direct HTTPS and WSS access to custom domains such as `vps.example.com` and `ws.vps.example.com`, where the browser reaches the VPS over Tailscale and Traefik terminates TLS locally.

Under that model:

- **Best default**: Let’s Encrypt
- **Best immediate fallback**: ZeroSSL
- **Best outside option**: wait for the Let’s Encrypt retry window
- **Only weaker reserve alternative found**: SSL.com
- **Not valid for this architecture**: Cloudflare Origin CA
- **No longer viable**: Buypass Go SSL

The key conclusion is narrower than it first appears: if you need recovery before the current Let’s Encrypt rate-limit window clears, **ZeroSSL is the best free fallback only after you have ruled out DNS-01 and CAA issues**. If you can tolerate the wait, **staying on Let’s Encrypt is cleaner and lower-risk operationally**.

## Context

This research is anchored to the live deployment state in this repository:

- direct browser targets:
  - `vps.example.com`
  - `ws.vps.example.com`
- TLS terminator:
  - Traefik
- validation mechanism:
  - Cloudflare DNS-01
- current failure mode:
  - Let’s Encrypt exact-set rate limiting, observed in live recovery logs

Relevant local evidence:

- `logs/deploy_runs/recovery_20260307_122130_private_tls_reconcile.log`
- `logs/deploy_runs/deploy_20260307_121600_resume_after_tls_fix.log`

## Evaluation Criteria

Providers were evaluated against the requirements that actually matter here:

1. Browser-trusted public certificate for direct client access
2. Works for arbitrary custom domains, not only provider-owned names
3. Free for issuance and renewal
4. Compatible with Traefik automation
5. Works with Cloudflare DNS-01
6. Operationally credible for unattended renewals
7. Suitable as a same-day recovery path from Let’s Encrypt rate limiting

## Survey

### 1. Let’s Encrypt

**Verdict:** still the best default, but currently blocked by rate limits in this incident.

#### Why it fits

- Publicly trusted by browsers
- Native Traefik compatibility
- No EAB requirement
- Best-documented operational model and rate limits
- Strongest ecosystem support

#### Why it is failing today

The live deployment exhausted the **exact-set** issuance limit. Let’s Encrypt documents a limit of **5 certificates per exact same set of identifiers every 7 days**. This is the current hard blocker for the `vps...` and `ws...` names in the live system.

#### Implications

- A new Let’s Encrypt account does **not** solve this specific limit.
- Let’s Encrypt staging can validate the flow before retry, but its certificates are not browser-trusted.
- If time is acceptable, waiting for the retry window is the cleanest path because it avoids adding provider-specific EAB secrets and fallback logic.

#### Sources

- https://letsencrypt.org/docs/rate-limits/
- https://letsencrypt.org/docs/staging-environment/
- https://letsencrypt.org/docs/integration-guide/
- https://doc.traefik.io/traefik/reference/install-configuration/tls/certificate-resolvers/acme/

### 2. ZeroSSL

**Verdict:** best free fallback when immediate recovery is required.

#### Why it fits

- Publicly trusted browser certificate
- Standard ACME support
- Traefik-compatible through:
  - `caServer`
  - EAB `kid`
  - EAB `hmacEncoded`
- Compatible with DNS-01 workflows
- Free DV certificates with a credible automation path

#### Operational cost

ZeroSSL is not a drop-in replacement for Let’s Encrypt. It introduces extra moving parts:

- EAB credential provisioning and secure storage
- CAA review if the zone uses CAA, because authorization may need to allow `sectigo.com`
- More vendor-specific behavior than Let’s Encrypt

#### Confidence level

High on basic technical viability. Medium on long-run operational predictability relative to Let’s Encrypt, because ZeroSSL’s public documentation is less transparent about rate limits and service semantics.

#### Recommendation

If same-day recovery matters more than configuration simplicity, ZeroSSL is the right fallback to implement in Traefik for this project.

#### Sources

- https://zerossl.com/documentation/acme/
- https://zerossl.com/documentation/acme/generate-eab-credentials/
- https://help.zerossl.com/hc/en-us/articles/360060119973-CAA-record-configuration
- https://doc.traefik.io/traefik/reference/install-configuration/tls/certificate-resolvers/acme/

### 3. SSL.com

**Verdict:** plausible reserve option, but weaker than ZeroSSL.

#### Why it is interesting

- Free 90-day public certificates
- Browser trust coverage claims are credible
- ACME is supported
- Traefik can interoperate because SSL.com also exposes ACME plus EAB

#### Why it ranks below ZeroSSL

- More awkward account bootstrap
- Documentation is less clean and sometimes internally inconsistent on free ACME behavior
- The free product shape appears more naturally aligned to a single hostname than a multi-name SAN certificate
- It is credible enough to test, but not strong enough to make the first fallback choice for unattended recovery logic

#### Recommendation

Keep SSL.com as a reserve fallback only if ZeroSSL is unavailable or unacceptable.

#### Sources

- https://www.ssl.com/certificates/free/
- https://help.ssl.com/knowledge/how-to/order-free-90-day-ssl-tls-certificates-with-acme
- https://www.ssl.com/guide/ssl-tls-certificate-issuance-and-revocation-with-acme/
- https://reseller.ssl.com/certificates/free/buy
- https://www.ssl.com/browser_compatibility/
- https://doc.traefik.io/traefik/reference/install-configuration/tls/certificate-resolvers/acme/

### 4. Cloudflare Origin CA

**Verdict:** not a valid substitute for this use case.

Cloudflare Origin CA solves a different problem. It secures the connection between Cloudflare and your origin. It does **not** provide a browser-trusted public certificate for clients who connect directly to the origin. Cloudflare’s own documentation warns that direct visitors may see trust errors and advises using a publicly trusted certificate when direct origin access is possible.

That means Origin CA is useful only if the architecture changes so that browsers never connect directly to the VPS and Cloudflare always terminates client TLS.

#### Sources

- https://developers.cloudflare.com/ssl/origin-configuration/origin-ca/
- https://developers.cloudflare.com/ssl/origin-configuration/origin-ca/troubleshooting/
- https://developers.cloudflare.com/ssl/origin-configuration/ssl-modes/full-strict/

### 5. Tailscale HTTPS

**Verdict:** not a substitute for custom-domain TLS in this architecture.

Tailscale HTTPS is useful for `*.ts.net` names it controls. It does not solve public browser trust for arbitrary custom domains such as `vps.example.com`.

#### Sources

- https://tailscale.com/kb/1153/enabling-https
- https://tailscale.com/kb/1312/serve

### 6. Buypass Go SSL

**Verdict:** remove from consideration.

Buypass has publicly ended GoSSL issuance and labels TLS/SSL products as discontinued. It is not a practical free fallback for new issuance.

#### Sources

- https://community.buypass.com/t/y4y130p/buypass-terminates-issuance-of-gossl-certificates
- https://www.buypass.com/

## Decision Matrix

| Provider | Browser-trusted for direct custom-domain access | Free | Traefik-compatible | Extra bootstrap friction | Confidence | Rank |
|---|---|---:|---|---|---|---:|
| Let’s Encrypt | Yes | Yes | Yes | Low | High | 1 |
| ZeroSSL | Yes | Yes | Yes | Medium | Medium-high | 2 |
| SSL.com | Yes | Yes | Yes | High | Medium | 3 |
| Cloudflare Origin CA | No | Yes | N/A | Medium | High | Not viable |
| Tailscale HTTPS | Not for custom domains | N/A | N/A | Low | High | Not viable |
| Buypass | No longer viable | N/A | N/A | N/A | High | Removed |

## Recommended Course

### If immediate recovery is required

Implement **ZeroSSL** as an alternate Traefik certificate resolver for the private hosts.

Do this only after confirming the current failure is actually Let’s Encrypt rate limiting rather than:

- Cloudflare token scope error
- wrong zone selection
- DNS TXT propagation/timing issue
- CAA policy blocking alternate issuers

Minimum requirements:

- ZeroSSL ACME directory URL
- reusable EAB `kid`
- reusable EAB `hmacEncoded`
- existing Cloudflare DNS-01 integration
- CAA check for `sectigo.com` if CAA records are present

### If delay is acceptable

Stay on **Let’s Encrypt** and wait for the retry window. This is the cleaner operating model and avoids introducing new provider-specific secrets and config branches.

### If ZeroSSL is rejected

Use **SSL.com** only after a small live test proves:

- account bootstrap is complete
- EAB works from Traefik
- free issuance behavior is stable for the hostname pattern you need
- renewal semantics are acceptable

## What Would Change The Recommendation

- If Cloudflare became the only client-facing TLS endpoint and the origin were never directly browsed, Cloudflare Origin CA would become viable for the origin leg.
- If Let’s Encrypt rate-limit pressure disappeared and ACME state churn were fixed, the recommendation would revert fully to Let’s Encrypt-only.
- If SSL.com published clearer current limits and a simpler free ACME onboarding path, it could become a more serious fallback competitor to ZeroSSL.

## Bottom Line

For **this exact deployment model**, there is one clean default and one credible emergency fallback:

- **Default**: Let’s Encrypt
- **Emergency fallback**: ZeroSSL

Everything else is either a different architecture choice, too weakly documented for confident unattended use, or no longer viable.
