# Roadmap to 95% — Vantablack

> Items are sorted within each area by **impact / effort ratio** (highest first).  
> Current weighted estimate: ~**79%**. Target: **95%**.  
> Each area lists what it needs specifically, grounded in the actual codebase.

---

## 🔴 Critical (blocks reaching 90%)

These are the gaps that a third party would immediately flag. Fix these first.

---

### 1. Wintun / Real TUN Device — End-to-end VPN test
**Area:** VPN | **Impact:** +8–10 pts on VPN, +3 pts security assurance

The fake-TUN path (`GHOST_VPN_FAKE_TUN=1`) is exercised by every VPN integration test. The real Wintun path in [`tun.rs`](file:///c:/Users/lukas/Downloads/SYSTEMS%20&%20CREATIONS/Vantablack/src/ghost/net/tun.rs) (lines 79–175) has **never been run in CI** and has no documented manual test result.

**What to do:**
- [ ] Add a CI job (`windows-vpn`) that downloads `wintun.dll`, runs the daemon in real VPN mode with admin rights, and verifies a packet round-trip through the OS interface (ping/curl to a second process)
- [ ] Document a manual "real-device checklist" (wintun.dll installed → VPN connects → `ipconfig` shows adapter → ping succeeds → adapter tears down cleanly)
- [ ] Add `is_wintun_installed()` assertion to an integration test that gates on the presence of wintun.dll (skip if absent, pass if present)
- [ ] Verify the `--features vpn` build path is tested separately from the default build

---

### 2. DPI / Traffic-Analysis Measurement
**Area:** Security assurance | **Impact:** +10–12 pts on security

This is the single biggest credibility gap. Cover traffic, dummy frames, and timing-jitter are **architecturally present** (8+ matches in `main.rs`) but there is zero recorded evidence of what a DPI box actually sees.

**What to do:**
- [ ] Run a live session (two nodes, real traffic) and capture with `tshark`/Wireshark. Record the packet-size distribution and inter-arrival time histogram
- [ ] Write a `tests/dpi_fingerprint.rs` that spawns two in-process nodes, sends known traffic, captures the resulting frames, and asserts: no plaintext HTTP patterns, size variance > threshold, timing jitter > threshold
- [ ] Document the result (even one screenshot in docs/) — "Mitigated by design" is honest, but "measured on date X: packet distribution shows Y" is credible
- [ ] Add this measurement to CI (can run without real network using the existing `SimNet`)

---

### 3. Real-World NAT Matrix Test
**Area:** NAT traversal | **Impact:** +8–10 pts on NAT traversal

[`tests/p1_nat.rs`](file:///c:/Users/lukas/Downloads/SYSTEMS%20&%20CREATIONS/Vantablack/tests/p1_nat.rs) uses a simulated RFC 4787 NAT (`common::nat::SimNet`). This is good and honest, but it doesn't prove the ICE agent works against a real router.

**What to do:**
- [ ] Add a CI job using two Docker containers behind `iptables`-emulated NAT (Linux; `MASQUERADE` + connection tracking) — this proves the real socket-level ICE exchange, not the simulated one
- [ ] Specifically test: Full-cone, restricted-cone, port-restricted, and symmetric NAT (all four RFC 4787 behaviours) — you have the sim model for this, replicate it with real `iptables`
- [ ] Add a `p1_nat_symmetric` test that forces TURN relay fallback and verifies it succeeds within a time bound
- [ ] Document the NAT type matrix (which topologies are tested, which require TURN) in `docs/`

---

### 4. Refactor `main.rs` — Break the 8,841-line monolith
**Area:** Maintainability / all areas | **Impact:** Not a % score directly, but blocks everything else

[`src/main.rs`](file:///c:/Users/lukas/Downloads/SYSTEMS%20&%20CREATIONS/Vantablack/src/main.rs) is 8,841 lines. The rest of the codebase is well-modularized (`ghost/net/`, `ghost/session/`, etc.). This file is the one piece that makes future changes risky.

**What to do:**
- [ ] Extract the SOCKS5 proxy logic (~lines 1240–1294, 3481–4107) into `src/ghost/net/socks.rs`
- [ ] Extract the CLI argument handling (`handle_cli_args`, line 4310) into `src/cli.rs`
- [ ] Extract the HTTP control-center route handlers (all `GET`/`POST /api/` patterns) into `src/ghost/control.rs`
- [ ] Extract the VPN daemon startup (lines 4584–4641) into a function in `src/ghost/net/vpn/daemon.rs`
- [ ] Each extraction should leave the existing tests green — no logic changes, just moves

> [!WARNING]
> Do this in small, test-verified commits. Each move should keep `cargo test` green.

---

## 🟡 High Priority (to reach 93–95%)

---

### 5. Fuzz CI Integration
**Area:** Security assurance | **Impact:** +4–5 pts

7 fuzz targets exist in [`fuzz/fuzz_targets/`](file:///c:/Users/lukas/Downloads/SYSTEMS%20&%20CREATIONS/Vantablack/fuzz/fuzz_targets/) but are **not run in CI**. They're valid targets — `fuzz_handle_pkt.rs`, `fuzz_parse_handshake_pdu.rs`, `fuzz_kyber_ciphertext.rs` etc. — but without CI they're untested fuzzers.

**What to do:**
- [ ] Add a `fuzz` CI job (Ubuntu) that runs each target for a short corpus seed (`cargo fuzz run <target> -- -max_total_time=30`) — 30 seconds each is enough to gate on crash-free baseline
- [ ] Commit a seed corpus for each fuzz target (a handful of valid inputs from the test suite)
- [ ] Run a longer local fuzz campaign (hours) on `fuzz_handle_pkt` and `fuzz_parse_handshake_pdu` specifically — these are the highest-value attack surfaces
- [ ] Add `fuzz/corpus/` to the repo with any interesting seeds found

---

### 6. Product Surface — Automated UI/API flow tests
**Area:** Product surface | **Impact:** +6–8 pts

The control-center HTTP API has no integration test. It starts and answers (`/api/status`) in the installer CI, but no test exercises connect/disconnect/peer-list/split-tunnel flows.

**What to do:**
- [ ] Write `tests/control_center_api.rs` that starts a node in `GHOST_NO_GUI=1` mode and exercises the REST API: `GET /api/status`, `POST /api/connect`, `GET /api/peers`, `POST /api/split_tunnel`
- [ ] Test the SOCKS5 proxy end-to-end in CI: start node with `GHOST_SOCKS5=1`, open a TCP connection through it, verify bytes flow
- [ ] Add a split-tunnel config write/read/apply cycle test (the config file lives in the user data dir — mock the path in tests)
- [ ] Verify the installer CI job (already in `ci.yml`) also tests the API beyond just `/api/status` — extend it to hit 3–4 endpoints

---

### 7. `stego_physics.rs` — Clarify or remove
**Area:** Credibility / security assurance | **Impact:** +2–3 pts

[`stego_physics.rs`](file:///c:/Users/lukas/Downloads/SYSTEMS%20&%20CREATIONS/Vantablack/src/ghost/net/stego_physics.rs) describes routing shards over acoustic/thermal/optical side-channels. It has 112 lines and one in-memory encode/decode test. It is **not wired to any real hardware driver** and is never called from the daemon.

**What to do (pick one):**
- [ ] **Option A — Label it research:** Move to `research/` or `examples/`, add a `// RESEARCH PROTOTYPE — not wired to production daemon` header, and update docs to remove any implication it's a shipped feature
- [ ] **Option B — Wire it or gate it:** If this is real, it needs: a real audio/thermal/LED driver abstraction, a CI test that at minimum exercises the encode/decode through a mock hardware interface, and a feature flag (`--features stego-physics`) so it's opt-in

Option A is the honest move unless you have hardware to test against.

---

### 8. Cover Traffic — Measurement and test
**Area:** Transport & routing / security assurance | **Impact:** +4 pts

Cover-traffic rate (`COVER_TRAFFIC_RATE_HZ`) and dummy frame injection are implemented (8+ references in `main.rs`, [`diffusion.rs`](file:///c:/Users/lukas/Downloads/SYSTEMS%20&%20CREATIONS/Vantablack/src/ghost/net/diffusion.rs)) but never tested for their actual traffic-shaping effect.

**What to do:**
- [ ] Write a test that sends 100 real packets through a simulated mesh and verifies: (a) dummy frames were injected, (b) the ratio of real-to-dummy frames is within the configured bounds, (c) timing jitter is non-zero
- [ ] Add a metric/log line that reports actual cover traffic rate per session — so the claim is observable, not just architectural
- [ ] Verify that dummy frames are statistically indistinguishable from real frames in size (not just content) — check the AEAD-output sizes match

---

### 9. ProVerif Model — Scope extension
**Area:** Crypto / protocol core | **Impact:** +2–3 pts

The ProVerif models in [`formal/`](file:///c:/Users/lukas/Downloads/SYSTEMS%20&%20CREATIONS/Vantablack/formal/) are honest (they explicitly disclaim what they don't cover). Extending them slightly would be meaningful.

**What to do:**
- [ ] Extend `ghost_session.pv` to model replay guard (the model currently abstracts this away)
- [ ] Add a model for the ShardSec secret-splitting property: adversary with 1 of 3 shards cannot reconstruct the key
- [ ] Run ProVerif in CI on Windows too (currently Ubuntu-only per `formal/README.md`) — or at least document the Windows result separately

---

### 10. Android — Close the JNI integration gap
**Area:** Product surface | **Impact:** +3–4 pts on product surface

[`src/ghost/net/vpn/android_jni.rs`](file:///c:/Users/lukas/Downloads/SYSTEMS%20&%20CREATIONS/Vantablack/src/ghost/net/vpn/android_jni.rs) is 822 lines. The `android-apk.yml` CI builds the APK but **never runs it**. No JNI test exists.

**What to do:**
- [ ] Add an Android emulator CI step (GitHub Actions has `reactivecircus/android-emulator-runner`) that installs the APK, starts the VPN service, and verifies it connects
- [ ] Write at least one JNI unit test (runnable on host via `cargo test --target-dir` with a mock JVM) that exercises the connect/disconnect/status JNI surface
- [ ] Alternatively: document clearly that Android is an early port (alpha) and not included in the main completion score — honest scoping beats untested claims

---

## 🟢 Polish (final 1–2 points)

---

### 11. Docker WAN sim — Re-demonstrate chaos scenarios
**Area:** Transport & routing | **Impact:** +2 pts

The `docker-compose.wan.yml` / `Dockerfile.wan` setup exists and CI runs it. But the byzantine/chaos/failover scenarios in [`tests/simulation.rs`](file:///c:/Users/lukas/Downloads/SYSTEMS%20&%20CREATIONS/Vantablack/tests/simulation.rs) are in-process only, not re-demonstrated via the Docker WAN containers.

**What to do:**
- [ ] Add a Docker WAN CI step that deliberately kills one carrier container mid-session and verifies RS(2,1) recovery still delivers the payload (currently the CI only checks happy-path reconstruction)
- [ ] Add a test that introduces packet loss (Linux `tc netem`) at 30% and verifies the mesh still delivers within a latency bound

---

### 12. External audit / peer review path
**Area:** Security assurance | **Impact:** +3 pts (but takes time/money)

No third-party has reviewed the protocol or implementation.

**What to do:**
- [ ] Publish the ProVerif models and the protocol spec publicly and ask for review (even informal — post to a cryptography forum or tag a known researcher)
- [ ] Write a 2–3 page protocol description document (separate from the README) that a cryptographer can review without reading Rust — describe the handshake, ratchet, and ShardSec scheme formally
- [ ] Budget for a lightweight security review when you're ready — this alone moves Security Assurance from ~62% to ~80%+

---

## Summary Scorecard (projected)

| Area | Now | After roadmap |
|---|---|---|
| Crypto / Protocol core | 93% | **96%** |
| Transport & routing | 83% | **92%** |
| Product surface | 77% | **91%** |
| NAT traversal + QUIC | 75% | **90%** |
| VPN (LAN-over-WAN) | 67% | **88%** |
| Security assurance | 62% | **82%** |
| CI / packaging / docs | 88% | **95%** |
| **Weighted overall** | **~79%** | **~91–93%** |

> [!IMPORTANT]
> Security assurance is the hardest area to push past 90% without external review. With items 2 + 5 + 8 done you get to ~82%. The last 10+ points in that area require a third party.  
> Everything else on this list is in your hands and achievable without external dependencies.

> [!TIP]
> **Fastest path to 90%:** Items 1, 2, 3, and 6 in order. Wintun test + DPI measurement + NAT real-network test + API flow tests. These four items close the biggest deltas and are all self-contained engineering work.
