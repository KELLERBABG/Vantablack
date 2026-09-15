# Global Ghost Net — SOTA Roadmap (v0.4.1 → v1.0)

> Opinionated, prioritized plan to make every plane **undisputed state-of-the-art** at open-source launch. Each plane is scored brutally honestly; each phase has a gate that must be green before the next starts. Owners are roles, not people — assign names at kickoff. Effort = calendar time for a focused 2–3 person cell on that plane (not total project).

Source of truth: this file. `roadmap/index.html` is a rendered summary. `roadmap/INVENTION.md` is the parallel invention track — pick 2-week spikes from there while this file ships v1.0. `docs/THINKTANK-BIN.md §9` + `docs/UNWIRED.md §4` are the raw backlogs — reconcile deltas against this file, not the other way round.

---

## 0. Scoreboard today (v0.4.1 + `vpn` feature)

| Plane | Claim | Reality | Gap to SOTA | Priority |
|---|---|---:|---|---|
| **Crypto (L0–L2, L6)** | hybrid `X25519+ML-KEM-512`, ChaCha20-Poly1305, SessionGuard | Real `ml-kem 0.3 / x25519-dalek / chacha20poly1305 / ed25519-dalek`, PSK→HKDF salt, `nonce=[sh[0..2]\|dir\|ctr BE]` correct, 128b sliding window, `prototcol` replay/TAMPER scenarios. But **identity is Ed25519-only** (Shor-breaks → all hybrid handshakes moot), no `ML-DSA/SLH-DSA`, no ratchet/rekey except counter-warn + watchdog re-handshake; `MAX_SAFE_COUNTER = u32::MAX-1000` only warns (THINKTANK 2.1/2.2 seal-at-drain still open). `nonce_from_counter_u64` exists, wire uses `u32`. | `P0` — fix before any audit |
| **Network (NAT/relay/transport)** | zero-config mesh | **Phase 1 landed the traversal stack.** RFC 8489 STUN + RFC 8445 ICE replace the port-guessing loop (`punch_hole` reports success only on a completed, measured check; `selected_rtt()` is a real measurement); TURN allocation, DERP-style blind relay and the `direct → mesh relay → TURN` ladder are wired (`net/fallback.rs`); UPnP-IGD/NAT-PMP supply an opportunistic candidate; `ContactPlan::latency()` is a real propagation model and `Journey` is populated by earliest-arrival Dijkstra, which `send3_adaptive` now consults; `FlowController` is still a policy ceiling but `cc::TransitGovernor` shapes it from measured path capacity. QUIC is an optional carrier under GTF (`--features quic`, `GHOST_QUIC=1`). **Remaining:** multipath-QUIC (Wi-Fi + LTE) is not built; router-side NAT behaviour (endpoint-independent mapping *and* filtering) is modelled and unit-tested but pinned by no published reference vector; every traversal test is loopback or in-process — no real gateway, TURN server or middlebox has been exercised. | `P1` — the P0 adoption block is cleared; proof on real paths is the gap |
| **Anonymity / traffic** | DPI-resistant | `512B GTF + 0–64B unauthenticated jitter tail` → `512–576B` variable (still fingerprintable). No constant-rate cover, no mixing (`Nym`-class), `RLY!` is 1-hop outer encryption not 3-hop circuit, `dispatch_shards_multipath` unwired. | `P1` |
| **Hardening (L8/L9)** | memory + HSM + time | `LockedMemory`/`SecureMemGuard<UnsafeCell>` + `XtsMemoryEncryptor` now wired, `PoissonReputationMatrix::is_byzantine` enforced, `RevocationList::revoke_with_issuer_pk` Ed25519-verified. But `l8_memsec.rs` duplicated 3× verbatim, `HsmBackend`/`Tpm2Backend::open()=Err`, `sign=[0;64]`, `SecureTimeKeeper` never read, `Kepler/DeltaV/Doppler` scaffolding. `SoftwareTpm` defined 3×, `frame_shard` 3×. | `P1` — wiring + dedup |
| **Platform** | desktop + mobile | Desktop `wry/tao` frameless + tray + `ghost.log` solid. **Windows ships no `wintun.dll`** (dev Tailscale copy, licensing gap), needs Administrator for real TUN, no auto-update/code-sign, no macOS `NetworkExtension`/Linux `.deb`. Android `GhostVpnService.kt` boots `tun0 10.66.0.10` but `WiFi→LTE` handover mid-TCP unproven, DNS leak/`10.66.0.1` + IPv6 blackhole pending. | `P1` |
| **Verification** | audit-ready | `cargo test --features vpn` → 370 green (267 lib + 103 integration), plus `--features quic` gates (4) and unit tests (2); `vpn_loopback_test.sh` PASS, fuzz targets real. Phase 1 gates run with no network and no privileges (`tests/p1_nat.rs`, `tests/p1_relay.rs`, `tests/p1_quic.rs`); `scripts/nat_gate_iptables.sh` checks the NAT model against the real kernel (Linux + root, never run here); `scripts/bench_transport.sh` compares the carriers. Still missing: `Tamarin/ProVerif` model, `TemporalIsolator` = 10 dummy `decapsulate` loops rather than a constant-time proof, and a real two-machine NAT44/CGNAT + LTE run — the Phase 1 *gate* is defined on that and is not satisfied by loopback. | `P1` |

**Verdict:** v0.4.1+vpn is the most *honest* mesh research prototype in the open — gaps are catalogued and measured — but `undisputed SOTA = beat Mullvad/Tailscale + Tor + WireGuard + Nym simultaneously`. Phases below close that in order.

---

## 1. Phasing (ship gates, not dates)

### Phase 0 — Stops-the-line (1–2 weeks, single cell)

Gate: `cargo test --features vpn` and `vpn_loopback_test.sh` stay green, no doc/code drift reintroduced, CI actually builds `vpn` + `hardware-tpm/pkcs11`.

* **P0-1 Dedup & feature hygiene.** Collapse `SoftwareTpm×3` → single `net/security/hsm.rs` re-export, `frame_shard/unframe×3` → `net/mod.rs` canonical, `l8_memsec.rs` de-triplicate (keep one `XtsMemoryEncryptor+VerifiedRingBuffer+XdpDispatcher+BundleHeader+Doppler` block). Declare `hardware-tpm`/`pkcs11` as real features (or delete gates) and add `cargo check --features hardware-tpm,pkcs11` to CI. Delete `tests/virtual_net.rs` stale vs `tests/common/virtual_net.rs`. Owner: **Core / Build**. Effort: `2–3d`.
* **P0-2 Wire `seal-at-drain` + pre-wrap rekey.** THINKTANK 2.1/2.2: egress queue carries `(overlay IpPacket, fp)` and `poll_egress()` seals at drain with live `epoch+ctr`; watchdog + hub housekeeping enforce `CTR_REKEY_AT` re-handshake (epoch rotation → `V_MAX=0`). Owner: **VPN cell**. Effort: `4–6d`. Verify: `counter_exhaustion_triggers_rehandshake_before_wrap`.
* **P0-3 Poison allowlist at mesh layer.** THINKTANK 2.3: handshake path (`main.rs` `ctr==0`, `vpn_mode==Hub`) rejects non-allowlisted `fp` before `Session::new`, counted drop + `PoissonReputationMatrix::record_interaction(false)`. Keep `vpn` feature scoping. Owner: **VPN/Security**. Effort: `1–2d`.

### Phase 1 — Makes the mesh *reachable* (3–5 weeks, 2 cells in parallel)

Gate: **two real machines behind residential NAT44/CGNAT + phone on LTE** establish a tunnel with `GHOST_VPN=hub/client` *without* port forwarding and sustain `ping`/`curl`/`iperf` through a symmetric-NAT handover.

> **Status (implementation):** all three workstreams are built and gated by tests that need no
> network and no privileges; the *gate as written* requires two real machines and a phone, which
> has not been run. P1-1 and P1-3 are complete in code; P1-2 is complete except multipath-QUIC.
> See `docs/THINKTANK-BIN.md §1.1` for the item-by-item record and `docs/UNWIRED.md` for what is
> wired-but-unproven (B23: multipath-QUIC).

* **P1-1 Real ICE (STUN/TURN) + DERP fallback.** Replace prediction loop with RFC 8489 STUN binding + RFC 8445 ICE candidate gathering/prioritization/connectivity-check + local TURN allocation. Add encrypted DERP-style relay through any mesh peer via `relay.rs` `BundleBuffer`/`build_relay_packet` when direct fails — sealed GTF forwarded as blind ciphertext (relays learn nothing). Add UPnP-IGD/PMP as opportunistic candidate. Owner: **Net cell**. Effort: `2–3w`. Touch: `net/mesh.rs`, `net/relay.rs`, `net/orbit.rs` (plane constraint stays). Test: `tests/mesh_smoke_test.sh` extended with `iptables` symmetric-NAT topology.
* **P1-2 QUIC + congestion.** QUIC (e.g. `quinn`) as optional transport under GTF for lossy/censored paths; multipath-QUIC when multi-homed (Wi-Fi+LTE). BBR/CUBIC over `FlowController`, proper `AckEngine::on_ack` AIMD fix (B2 already closed, but promote to real CC). Owner: **Transport cell**. Effort: `2–3w`. Verify: `GTF_bulk` vs `QUIC` bench `scripts/bench_transport.sh`.
* **P1-3 True CGR routing.** Populate `ContactPlan` from real contacts (beacons, TLE propagation via `TleDistributor::should_gossip/build_gossip_message`), Dijkstra `find_earliest_arrival` with real `latency(e,t)` (laser `c`/`range`), integrate `DeltaV`/`DisjointRouteConstraint` enforcement already wired for shards. Owner: **Routing cell**. Effort: `1–2w`.

### Phase 2 — Makes the crypto *future-proof* (3–4 weeks, overlaps P1)

Gate: `cargo test --features vpn,hardware-tpm` + formal model checks `tamarin/proverif` for session unforgeability, forward secrecy, PQ hybrid — no mock primitives in proof scope.

* **P2-1 PQ signatures + agility.** Add `ML-DSA-65` (or `SLH-DSA`) alongside Ed25519 for identity (`GhostIdentity` enum → verifies both during migration), pin `l0_identity.rs` proofs in GTF/signed-beacon/REVOKE paths. Add cipher-suite agility (`X25519Kyber768` option, `HKDF("GHOST_NET_MASTER_KEY_v3")` domain separation). Owner: **Crypto cell**. Effort: `2w`. Needs `cargo.toml` `ml-dsa` (e.g. `ml-dsa`/`pqcrypto` audit) + `fuzz/`.
* **P2-2 Double Ratchet + XChaCha20.** Session ratchet (X3DH-like + DH ratchet) from hybrid KEM; `XChaCha20-Poly1305` (96-bit random nonce) eliminates `u32` counter ceiling; 64-bit `SessionGuardU64` becomes primary. Rekey ratchet step on every 1M datagrams + explicit `Rekey` PDU. Owner: **Crypto/Session**. Effort: `2w`. Verify: `test_double_ratchet_forward_secrecy`.
* **P2-3 Constant-time & HSM-real.** Replace `TemporalIsolator` dummy loop with `subtle::ConstantTimeEq` + `ml-kem` ct-verify audit; wire `HsmBackend` through `tss-esapi`/`cryptoki` behind `hardware-tpm`/`pkcs11` (real `open/sign/verify/derive_session_key`, `LockedMemory` fallback only when `#[cfg(not(...))]`). Add `DPE/TPM attestation` envelope. Owner: **Hardening cell**. Effort: `2–3w`.

### Phase 3 — Makes the anonymity *real* (2–3 weeks)

Gate: standard DPI classifier + timing correlator (`scripts/pentest_ggn.sh`) cannot distinguish idle / `iperf` / `SOCKS` over GTF better than random; single-relay compromise leaks zero plaintext (verified by `attack_harness`).

* **P3-1 Uniform frames + mixing.** Replace variable `512–576B` tail with **constant 576B** `GTF` (16B tag authenticated *over* `frame_shard` length; jitter region is `chacha` pad *inside* the tag). Add constant-rate cover traffic (e.g. `2 pkt/s` Poisson when idle, padded with `Dummy` flag `0x04`) + optional Nym-style `Sphinx` mix batch. `dispatch_shards_multipath` + `DisjointRouteConstraint` enforced for all 3 shards when `≥3` peers; decoy shard when `<3`. Owner: **Privacy/Transport**. Effort: `1.5–2w`.
* **P3-2 3-hop onion + exit policy.** Extend `RLY!` to 3 layers (guard→middle→exit) via nested `build_relay_packet` with per-hop `ChaCha20-Poly1305` and fixed-size `Sphinx`-like header; directory via `TleDistributor`/`ContactPlan` not central authority. Exit allowlist (`EXITAUTH`) as capability voucher (`cap_voucher.rs`) with TTL. Owner: **Relay/Security**. Effort: `1–2w`.

### Phase 4 — Makes the product *shippable* (2–3 weeks, overlaps P3)

Gate: signed Windows `.exe`/`.msi` installs per-user without Administrator for SOCKS path, with real TUN only when elevated; macOS `NetworkExtension` + Linux `.deb` pass; Android `WiFi→LTE` mid-SSH no drop; `ghost_vpn_*` dashboard green.

* **P4-1 Windows packaging correct.** Vendor official `wintun 0.14.x` zip (no Tailscale copy), `scripts/build_installer.ps1` stages it, `installer/ggn.iss` `PrivilegesRequired=lowest` stays; real TUN probes `wintun.dll` presence and degrades to `FakeTun` + banner when absent. Add code-sign + auto-update (e.g. `velvet`/`tauri updater` or `winget`). Owner: **Desktop/Packaging**. Effort: `1w`.
* **P4-2 Platform shells.** macOS `NetworkExtension` / `SystemExtension` packet tunnel (reuses `VpnConfig`/`LeaseTable`/`netstack`), Linux `tun` via `net/tun.rs` + systemd unit. `tray.rs`/`webview.rs` native status dashboard (already `wry/tao` frameless — polish + `GHOST_VPN_FAKE_TUN` banner). Owner: **Desktop/Mobile**. Effort: `1.5–2w`.
* **P4-3 Mobile handover + DNS hygiene.** Android `GhostVpnService` re-anchors `endpoint` via `LeaseTable::observe_tunnel_packet` `WindowAdvance`/`SilenceFallback` ladder already correct — add active path migration (rebind `UdpSocket` on `ConnectivityManager` callback, `SO_BINDTODEVICE` when present), enforce `10.66.0.1`/hub DNS + search-domain push verified on each platform, hard IPv6 blackhole until overlay v6. iOS `NetworkExtension` mirrors Android. Owner: **Mobile cell**. Effort: `1.5w`.

---

## 2. Cross-cutting owners

| Role | Owns | Review gate |
|---|---|---|
| **Crypto lead** | P2-1/P2-2, `l1_kem`, `l2_aead`, `session/mod`, fuzz | Tamarin/ProVerif + `cargo audit` + `subtle` ct review |
| **Transport/Net lead** | P1-1/P1-2/P1-3, `net/mesh`, `net/relay`, `net/mod`, `vpn/netstack` | `mesh_smoke` under `tc netem` + `iperf` loss matrix |
| **Hardening lead** | P2-3, `net/security`, `layers/l8`, `layers/l9`, `security/hsm` | `cargo test --features hardware-tpm,pkcs11` + `mlock` failure injection |
| **Product/Desktop** | P4-1/P4-2, `icon.rs`, `webview.rs`, `tray.rs`, `installer/*` | Windows `windows-installer` CI job + real install/uninstall/repair |
| **Mobile** | P4-3, `net/vpn/android_jni`, `android/*`, iOS ext | Xiaomi + iPhone handover rig (`WiFi→LTE` mid-`ssh`) |

Every PR: `cargo build` + `cargo build --features vpn` + `cargo test --locked --features vpn` + `clippy -- -D warnings`. New `vpn`/`crypto` code requires a `tests/vpn_*.rs` or `tests/layer_tests.rs` addition. No `unwrap()`/`expect()` on untrusted input — map to `warn! + stats.drops`.

---

## 3. What deliberately *doesn't* block v1.0

Preserved as clean specs with no wiring debt before launch (documented in `docs/UNWIRED.md`):

* Kepler/TLE/DTN orbital mesh (`orbit.rs`, `DeltaVTracker`, `DopplerShiftSimulator`, `ContactPlan` space semantics) — terrestrial mesh ships first; orbital path gated on real ephemeris feed + laser link hardware.
* Full `eBPF/XDP` kernel bypass beyond `LocklessDispatcher`/`VerifiedRingBuffer`/`XdpDispatcher` software simulation — NIC offload when `AF_XDP` fleet exists.
* Sovereign seed mesh / volunteer exit ASN spread (`roadmap` item 12) — post-v1.0 operations, not code.

---

## 4. How to use this file

1. Pick a `P0` item — file its PR against this doc's acceptance criteria (the **Gate** line is the definition of done).
2. At PR merge, delete its row *here* and move it to `docs/THINKTANK-BIN.md §1 Execution log`.
3. When Phase N's gate is green end-to-end, tag `sota-phaseN` and open the next phase's tracking issue.
4. Any new `(line NN)`-style comment or duplicate type must be added here within the same PR — roadmap comments may not live only in source.

---

## 5. Relation to existing docs

* `docs/THINKTANK-BIN.md` — raw backlog + designs; §9 was the draft that became this file.
* `docs/UNWIRED.md` — honest wired/unwired table; treat its "Wired & ..." rows as *done* evidence, not promises. Reconcile with this file after each phase.
* `docs/SPECIFICATIONS.md` / `docs/WHITEPAPER.md` / `docs/ONION_ARCHITECTURE.md` — normative protocol. Update `SPECIFICATIONS.md` wire format on any GTF/nonce/jitter change.
* `roadmap/index.html` — marketing-facing timeline (12 items). Keep it stable; link to this file for the engineering order.
* `roadmap/INVENTION.md` — 20 systems-level inventions beyond SOTA (shardsec, mimic, honey-shards, ZK transit, shatter routing…). Spikes graduate here → SOTA Phase N+1.

---

*Last updated: v0.4.1 SOTA cut. Next edit: after P0 lands, delete P0 section and shift Phase tags.*
