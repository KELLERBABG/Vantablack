# Vantablack — Commercialization & Systems Roadmap (Target 9/10 & 10/10)

**Project:** Vantablack — Post-Quantum Layered WAN Mesh Router & High-Assurance TUN VPN  
**Current Version:** `0.8.11`  
**Current Readiness Score:** **7/10 (Hardened Core System)**  
**Target Milestone:** **9/10 (Commercially Shippable / Zero-Friction Product)**  
**Long-Term Milestone:** **10/10 (Field-Tested Production with 24/7 Mesh Telemetry)**

---

## 1. Executive Summary & Philosophy

Vantablack provides post-quantum cryptographically layered mesh routing (ML-KEM-512, ChaCha20-Poly1305, Reed-Solomon dispersion, and physical fallback layers like ABOS skywave and ETSI QKD). The recent lint-hardening pass eliminated 221 compiler warnings across 57 files and locked down strict `-D warnings` CI enforcement.

To advance from **7/10 to 9/10**, Vantablack must transition from a developer-compiled repository into a turnkey background service with signed OS installers, bundled TUN drivers, automated network recovery, and 1-click mobile QR pairing.

---

## 2. Current Verified Baseline (v0.8.11)

- **Cryptographic Stack:** 10-layer onion encryption (L0 identity to L10 physical anchor) with zero runtime panics.
- **Cross-Platform Surface:** Desktop Frameless GUI (Tao + Wry), headless server daemon, and Android JNI library (`cdylib`).
- **Codebase Hygiene:** 100% clean `cargo clippy --all-targets -- -D warnings` compliance with exactly 3 auditable architecture exemptions.
- **Mobile Integration:** Dual-stack socket address canonicalization, sweep re-handshake leases, and Android 14 foreground service support.

---

## 3. Milestone 1: Turnkey Service Installers & Packaging (Target 9/10)

```
[Windows Operator] ──> Vantablack-Installer.exe ──> Registers Windows Service + Bundles wintun.dll
[Linux Server] ──────> apt install vantablack.deb ──> systemctl enable --now vantablack
[Android Client] ────> F-Droid / GitHub Releases ───> Vantablack-v0.8.12.apk
```

- [ ] **Windows Service Daemon Command:**
  - Implement `vantablack service install` and `vantablack service uninstall` using `windows-service` crate.
  - Automatically bundle and extract signed `wintun.dll` into the driver path during installation.
- [ ] **Automated GitHub Actions Binary Matrix:**
  - Build and sign release assets for:
    - Windows x86_64: `vantablack-setup.exe` (with Authenticode signature).
    - Linux x86_64 / aarch64: `.deb` and `.rpm` packages with systemd unit files.
    - Android: Signed release APK with reproducible Gradle build.
- [ ] **Apple Silicon macOS Support:**
  - Build signed `.dmg` utilizing `utun` interface drivers with notarization.

---

## 4. Milestone 2: Self-Healing Network Watchdog (Target 9/10)

- [ ] **Interface Stall Watchdog:**
  - Detect dead gateway transitions (e.g. laptop waking from sleep, mobile switching from Wi-Fi to LTE, or TUN buffer lockups).
  - Automatically recycle TUN sockets and re-establish KEM handshakes within 2.5 seconds without operator intervention.
- [ ] **Congestion & Path MTU Auto-Discovery:**
  - Implement dynamic Path MTU discovery (PMTUD) to prevent fragmentation stalls across aggressive ISP cellular networks.

---

## 5. Milestone 3: Seamless Operator UX & Pairing (Target 9/10)

- [ ] **1-Click Mobile QR Pairing:**
  - Render an encrypted peer-pairing QR code directly in the desktop control center.
  - Scan via mobile APK to instantly exchange public identity keys, rendezvous endpoints, and route hints.
- [ ] **Real-Time Telemetry Dashboard:**
  - Expose live cryptographic health metrics in the UI: active peer count, post-quantum key age, packet loss, and physical fallback carrier status (SDR / QKD).

---

## 6. Milestone 4: Enterprise Documentation & Portal (Target 9/10)

- [ ] **Live Documentation Portal Deployment:**
  - Build and deploy `vantablack.kellersystems.dev` with an interactive architecture explorer, threat model analysis, and multi-cloud setup guide.
- [ ] **Air-Gapped Network Deployment Manual:**
  - Publish `docs/AIRGAP_DEPLOYMENT.md` detailing sovereign deployment for critical infrastructure isolated from public root DNS.

---

## 7. Milestone 5: Path to 10/10 (Field-Tested Mesh Telemetry)

10/10 requires continuous multi-node real-world operation under adversarial conditions:

1. **50-Node Long-Haul Mesh:**
   - Maintain a 24/7 operational mesh across 50 heterogeneous nodes (cloud servers, home routers, laptops, and Android phones) across 4 continents.
2. **Stress & Adversarial Resilience:**
   - Subject the network to automated DPI blocking, packet drops, and node churn for 30 consecutive days with zero connection drops on active sessions.
3. **Formal Security Audit:**
   - Engage an external post-quantum cryptography audit on the L1–L4 session ratcheting implementation.
