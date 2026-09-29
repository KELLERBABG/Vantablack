# Security Policy & Vulnerability Disclosure Program

Vantablack (Global Ghost Net) is an autonomous, post-quantum overlay network and privacy fabric. We welcome independent security researchers, cryptographers, and penetration testers to inspect, audit, and probe our codebase.

---

## 1. Reporting a Vulnerability

Please report potential security vulnerabilities privately. **Do not create public GitHub issues for sensitive security findings.**

* **Primary Security Contact:** `security@kellersystems.dev` / `contact@kellersystems.dev`
* **PGP Key Fingerprint:** Available upon request or signed via Ed25519 repository commits.
* **Encrypted Dispatch:** If you are running a Vantablack node, you may send an end-to-end encrypted mesh message directly to the developer fingerprint: `KELLERBABG`.

### Information to Include
- Detailed description of the vulnerability (proof of concept, script, or reproduction steps).
- Impact assessment:
  - Cryptographic breakdown (e.g. key recovery, lattice weakness, nonce reuse).
  - Anonymity de-anonymization / timing correlation.
  - Remote code execution / memory corruption.
  - Denial of Service / Relay exhaustion.
- Affected component or layer (L0–L10, `src/main.rs`, Wintun adapter, or API).

---

## 2. Scope & Target Boundaries

### In-Scope
* **Cryptographic Core:**
  - Hybrid ML-KEM-768 + X25519 key encapsulation.
  - ML-DSA-65 + Ed25519 hybrid signatures.
  - ChaCha20-Poly1305 / XChaCha20-Poly1305 AEAD sealing and direction-bound nonce handling.
  - Double Ratchet state transitions and key derivation (`HKDF-SHA256`).
* **Transport & Framing:**
  - Reed-Solomon RS(2,1) erasure coding and shard reconstruction.
  - 3-hop onion relay circuits and blind ticket verification (`EXITAUTH`).
  - Deep Packet Inspection (DPI) resistance (frame length invariant, entropy analysis).
* **Networking & VPN Subsystems:**
  - Windows Wintun driver FFI, Linux `/dev/net/tun`, and macOS `utun` handling.
  - SOCKS5 proxy server and Control Center REST API (`127.0.0.1:2270`).
  - Zero-Admin userspace transparent routing mode.

### Out-of-Scope
* Social engineering or phishing targeting repository contributors.
* Physical side-channel attacks requiring physical possession of a running device without memory encryption.
* Denial of service attacks targeting third-party STUN or DNS fallback infrastructure.

---

## 3. Safe Harbor Policy

We consider security research conducted under this policy to be authorized. We will not pursue legal action against researchers who:
1. Make a good faith effort to avoid privacy violations, data destruction, and service interruption.
2. Allow reasonable time for remediation before public disclosure (standard 90-day responsible disclosure window).
3. Do not exploit vulnerabilities beyond the minimum necessary to demonstrate proof-of-concept.

---

## 4. Bug Bounty Recognition & Tiers

We recognize and reward qualifying vulnerability reports according to severity:

| Severity Tier | CVSS Range | Qualifying Findings |
|---|:---:|---|
| **Critical** | 9.0 – 10.0 | Remote Code Execution (RCE) in daemon, complete post-quantum session key recovery, or remote identity spoofing. |
| **High** | 7.0 – 8.9 | Breaking 3-hop onion circuit anonymity, timing-correlation de-anonymization without omniscient observation, or persistent memory corruption. |
| **Medium** | 4.0 – 6.9 | Unauthenticated relay crash / DoS, bypassing SOCKS5 split-tunnel filtering, or local privilege escalation. |
| **Low** | 0.1 – 3.9 | Theoretical side-channel leaks, non-exploitable memory leaks, or minor specification deviations. |

All researchers with valid accepted findings are permanently inducted into the **Vantablack Hall of Fame** and receive credit in repository release notes.
