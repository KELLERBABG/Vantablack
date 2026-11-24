# Anti-Abuse & Threat-Shield Architecture

Strong privacy and censorship-resistant transport software is inherently dual-use. Rather than weakening encryption or adding surveillance hooks, Vantablack can reduce abuse and protect users through **exit-trust boundaries**, **default egress guardrails**, **local peer reputation**, and a **local Threat / Malware Shield**.

---

## 1. Threat Model Boundaries

- **Transport vs. endpoint:** Hybrid PQ encryption, multi-hop routing, and erasure coding protect data in transit and raise the cost of passive surveillance, but do not secure compromised endpoints or malicious applications.
- **Scale & correlation:** Anonymity claims depend on relay population and path diversity (see `ghost::v2::xray` and `ghost::v2::regime`).

---

## 2. Exit-Node & Relay Abuse Prevention

In a peer-to-peer mesh, **public exit nodes** carry the primary legal and abuse-complaint risk (spam, scraping, malicious traffic).

- **Trust-scoped exits:** Keep exiting opt-in and scoped to trusted peers (`trusted_exits`), self-hosted home exits (`boomerang`), or private `fleet` groups rather than acting as an open exit for anonymous strangers.
- **Default exit egress policy:**
  - Block outbound **TCP/25 (SMTP)** on exits by default to prevent spam-relay abuse.
  - Block **SSRF / LAN-pivot targets** (`169.254.169.254` cloud metadata, loopback `127.0.0.0/8`, and private RFC1918 ranges) unless explicitly permitted for home-exit or LAN-over-WAN access.
- **Flood & Sybil defense:** Gate handshake/relay admission under load with `WanRateLimiter` and flood-triggered Proof-of-Work (`ghost::net::pow`).
- **Local & privacy-preserving reputation:**
  - Prefer **local/subjective peer scoring** (`PoissonReputationMatrix` in `src/ghost/net/routing.rs`) and signed `RevocationList` entries (`src/ghost/net/security.rs`) over a global identity-linked reputation ledger.
  - Share coarse, k-anonymous anomaly aggregates (`ghost::net::collective_defense`) strictly as a **soft routing penalty** combined with local `PoissonReputationMatrix` scores — never as an automatic hard ban — to resist Sybil/report-poisoning attacks.

---

## 3. Threat / Malware Shield (Best-Effort Local Blocking)

Blocking known malicious infrastructure (phishing, malware distribution, botnet C2) reuses the same local pipeline as `src/ghost/net/adblock.rs`:

1. **DNS + CNAME Uncloaking + DoH/DoT Guard:** Return `NXDOMAIN` for blocked domains, CNAME-cloaked targets, and DNS-bypass endpoints (port `853` / known DoH resolvers when enabled). Works across both Full Mesh and standalone Android **Local Ad-Shield** mode.
2. **TLS `ClientHello` SNI & SOCKS5 `CONNECT` Filtering:** Drop connections to blocked hostnames even when DNS was cached (applies on `VpnHub` Full Mesh and `SOCKS5`, where TCP streams transit the node).
3. **Dedicated C2 / Hijacked CIDR Blocking:** Match raw-IP connections locally against high-confidence botnet C2 and hijacked netblock lists on `VpnHub` / `SOCKS5`.

### Design Rules
- **100% local evaluation:** Refresh lists periodically in the background or bundle snapshots at build time. Never query a remote reputation API or actively probe a destination IP per connection (which leaks user intent and adds latency).
- **$O(\text{labels})$ & CIDR lookup structures:** Use a `HashSet` / sorted binary-search suffix index (matching `a.b.c` -> `a.b.c`, `b.c`, `c`) and a sorted CIDR prefix table rather than linear scans before loading 100k+ domain feeds.
- **No TLS MitM:** Do not install a root CA or decrypt HTTPS payloads to inspect page content; TLS 1.3 encrypts server certificates as well, and active content scraping risks false positives on shared CDNs/VPS IPs.
- **User control & transparency:** Keep Threat/Malware Shield as a separate toggle from Ad & Tracker Blocking, paired with a **local user allowlist** (for false positives) and an **in-memory recent-blocks ring buffer** (never persisted in amnesia mode).

---

## 4. Starting-Point Public Threat Feeds & Hygiene

- **HaGeZi Threat Intelligence Feed (TIF)** — DNS-curated, deduplicated domain list combining URLhaus, ThreatFox, PhishTank, and OpenPhish (avoids naive domain extraction from shared hosts like `github.io`, `pages.dev`, or `docs.google.com`).
- **abuse.ch** *(Swiss security research project)*:
  - **URLhaus** — active malware distribution domains/URLs (requires shared-host allowlist filtering if consumed directly).
  - **Feodo Tracker** — active botnet C2 server IPs.
  - **ThreatFox** — malicious domains and IPs.
- **Spamhaus DROP** — hijacked and cybercriminal-controlled IPv4/IPv6 CIDR blocks (EDROP was merged into DROP in 2024; very low false-positive rate).
- **OpenPhish / PhishTank** — verified phishing feeds (consume via DNS-curated TIF or filter shared hosting domains).
- **CERT / CISA / FBI Advisories** — IOCs published via STIX/TAXII/MISP advisories and partner feeds (such as Shadowserver), which also flow into the community feeds above.

### Feed Safety & Staleness
- **Signed snapshots:** Background-refreshed lists should be **Ed25519-signed** with a pinned Vantablack key before loading.
- **C2 IP expiry:** Botnet C2 IPs rotate quickly; enforce an **expiry/TTL** on IP-based C2 blocks so stale snapshots do not block reassigned innocent IPs if background refreshes fail.
