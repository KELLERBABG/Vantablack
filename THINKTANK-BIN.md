# THINKTANK-BIN

Scratchpad for additions, defects and designs discovered **while executing the
[`PROTOTYPE.md`](PROTOTYPE.md) bucketlist**. Everything here is additive: the
bucketlist itself stays the plan of record. Items are grouped by kind, and each
carries enough detail to be picked up cold.

---

## 1. Execution log — bucketlist items completed this pass

| PROTOTYPE.md item | Change | Where |
| :-- | :-- | :-- |
| **Flaw #6** `identity.key` is CWD-relative | Added `GHOST_IDENTITY_FILE` override (`IDENTITY_FILE_ENV` + `identity_file_path()`); `GhostNode::new` now resolves through it | `layers/l0_identity.rs`, `ghost/mod.rs` |
| **Flaw #2** UDP reply truncation at 2048 B | Flow-reader buffer 2048 → **4096** (EDNS0 ceiling), with a comment explaining that `recv` truncates silently | `net/vpn/hub.rs` (`spawn_flow_reader`) |
| **Flaw #1** counter exhaustion is silent | `send_tunnel_frame` no longer drops silently: it counts the drop in `stats.drops`, logs `warn!` at the wall, and logs a second `warn!` at a 1M-packet pre-wrap margin. Hub `seal_for_client` gained the same proximity warning. | `main.rs`, `net/vpn/hub.rs` |
| **§2.4 zero-elevation self-test** *(was a design sketch, now implemented)* | `PlatformTun` is now an enum (`Real`/`Fake`) implementing `TunDevice` by delegation; `open_fake_tun()` returns the device plus a shared `FakeTun` handle (the queues are `Arc`-shared, so a clone can inject and observe); `GHOST_VPN_FAKE_TUN=1` selects it and spawns a driver that pushes an ICMP echo toward the hub overlay and reports what the tunnel writes back. Harness promoted to `scripts/vpn_loopback_test.sh`. | `net/vpn/tun/mod.rs`, `main.rs`, `scripts/vpn_loopback_test.sh` |

**Ledger lines in PROTOTYPE.md that can now be struck** (§"Open flaws, ranked by
user impact"): #2 is fully fixed; #6 is fixed; #1 is *mitigated, not closed* —
see §2.1 below, the actual re-key trigger is still missing.

**"The big one" is no longer unproven off-hardware.** Two real processes over
real UDP sockets, the real hybrid handshake, the real tunnel seal/open path —
the client on the in-memory TUN, so **no wintun.dll, no Administrator, no OS
interface, no traffic leaving the machine**. `scripts/vpn_loopback_test.sh`
observes ICMP echo replies returning through the mesh (8 in the recorded run,
`replies_total=8`). The wintun / real-LAN / Wi-Fi→LTE-handover layer still needs
hardware, but "no two physical nodes have ever talked" is no longer the state of
the *protocol* path.

**New finding from that run — beacon port collision.** Both nodes bind
`0.0.0.0:2270` for the beacon listener, so on one host one of them loses the
bind and logs `ERROR Beacon listener: … (os error 10048)`. Harmless for this test
(no beacons are used), but two co-located nodes therefore cannot both receive
beacons, and the failure is logged at ERROR. Consider `SO_REUSEADDR`/`SO_REUSEPORT`
on the beacon socket, or a `GHOST_BEACON_PORT` override.

**Verification for this pass:** `cargo check --features vpn` clean;
`cargo test --locked` green (66 lib + integration); `cargo test --lib --features vpn`
green (93 lib); `bash scripts/vpn_loopback_test.sh` PASS. No behaviour change on
the control channel.

---

## 2. Designs ready to implement (ranked)

### 2.1 Flaw #1, for real: a pre-wrap re-key trigger

The counters now warn, but nothing acts. The missing piece is a *trigger*, not
arithmetic:

- Hub: in the 1 Hz housekeeping loop (the one that already calls `sweep()`),
  compare every lease's `tx_counters[fp]` against `CTR_REKEY_AT`. On breach,
  mark the lease `rekey_required = true` and skip `seal_for_client` for it
  (drop, counted) until a fresh handshake rotates the epoch.
- Client: the resilience loop (`client::resilience::TunnelWatchdog`) already
  re-handshakes when the tunnel is dead. Extend `poll()` to also return
  `Action::Rehandshake` when `tx_counter() >= CTR_REKEY_AT`, i.e. treat
  "counter exhausted" as a second liveness trigger. This is the cheapest
  correct fix because the re-handshake path (epoch rotation → `V_MAX = 0` →
  counter reset) already exists and is already gated.
- Test: seed the counter just under the margin, drive one frame, assert a
  re-handshake is requested and that the post-rotation counter restarts at 1
  under a **new epoch**.

### 2.2 Flaw #4: seal at drain, not at produce

Today `enqueue_to_client` seals *before* the 4096-slot egress queue, so a client
re-anchor mid-queue leaves sealed datagrams stamped with a stale epoch + spent
counter — they die. Design:

- The egress channel carries a typed payload (`IpPacket`, i.e. `Vec<u8>` plus
  destination fingerprint) instead of `(fp, sealed_wire)`.
- `poll_egress()` seals at the moment it hands the unit to the mesh, reading the
  *current* epoch + counter then.
- This makes "unsealed relay" and "stale epoch in queue" unrepresentable rather
  than merely unlikely — the bug class the gates already caught once.

### 2.3 Flaw #5: allowlist mesh handshakes on a hub

Right now any PQ-authenticated peer can open a *mesh session* with a hub; only
*VPN tunnels* consult `GHOST_VPN_CLIENTS`. Design:

- In the handshake path (`main.rs` `handle_pkt`, counter == 0), when
  `vpn_mode == Hub`, require the peer fingerprint to be in
  `cfg.allowed_fingerprints` **before** creating the session.
- Keep it VPN-scoped: a hub with the VPN feature off behaves as today, so the
  v0.4.0 surface is untouched.
- Reject with a counted drop + `warn!`, and record it in the reputation matrix
  (already wired for handshake failures).

### 2.4 Zero-elevation self-test: `GHOST_VPN_FAKE_TUN=1`

PROTOTYPE.md calls "nothing is wire-proven" the big one, and this is the cheapest
way to shrink it without wintun.dll or Administrator.

- `tun/mod.rs` already has `FakeTun` implementing `TunDevice`; it is simply not
  reachable. `PlatformTun` is currently a bare type alias
  (`= WintunTun` / `= UnixTun`), so the smallest change is to make it an enum
  `PlatformTun { Real(platform::Tun), Fake(FakeTun) }` implementing `TunDevice`
  by delegation, plus `open_fake_tun()`.
- `main.rs` client construction picks the fake backend when
  `GHOST_VPN_FAKE_TUN` is set, and logs loudly that it is a test mode.
- Then a **two-process loopback smoke test** needs no hardware: process A
  (`GHOST_VPN=hub`) + process B (`GHOST_VPN=client GHOST_VPN_FAKE_TUN=1`), both
  with distinct `GHOST_IDENTITY_FILE` (now possible — see §1), driving a
  `10.66.0.x → 192.168.x.x` ping/HTTP through the real crypto and framing path.
- This is the single highest-value remaining item, and it is now unblocked by
  the identity fix.

---

## 3. Observability (PROTOTYPE.md "Missing surfaces")

### 3.1 `vpn_*` metrics

The hub already exposes `stats() -> (in, out, dropped, leases, tcp_flows)` and
`leases.snapshot()`; `/metrics` ignores all of it. Add to the Prometheus body:

```
ghost_vpn_active_leases            gauge
ghost_vpn_tunnel_frames_in_total   counter
ghost_vpn_tunnel_frames_out_total  counter
ghost_vpn_frames_dropped_total     counter
ghost_vpn_udp_flows                gauge
ghost_vpn_tcp_flows                gauge
ghost_vpn_counter_headroom_min     gauge   # min over leases of (u32::MAX - tx_ctr)
ghost_vpn_watchdog_dead_clients    gauge   # client role only
```

`ghost_vpn_counter_headroom_min` is the metric that makes flaw #1 visible
*before* it bites — it is the counter the doc asks for. Also add
`"vpn": "disabled" | "hub" | "client"` to the `/healthz` JSON.

### 3.2 `VPN STATUS` console view

`LEASES` prints the raw table and `VPNSTATS` prints five numbers; neither shows
epoch, last-seen age, or per-lease flow counts, which is what you actually want
mid-incident. Add a `VPN STATUS` variant rendering one line per lease:

```
fp=ab12…  ip=10.66.0.10  endpoint=203.0.113.9:51000  epoch=7  last_seen=2s  flows=3  headroom=99.98%
```

---

## 4. Defects found while reading (not in the bucketlist)

| # | Defect | Evidence | Fix sketch |
| :-- | :-- | :-- | :-- |
| D1 | `tests/simulation.rs` still races on one `identity.key` (deletes the file before every node) | `tests/simulation.rs:37-51,124,453-456` | Now trivially fixed by §1: give each `SimNode` its own `GHOST_IDENTITY_FILE` instead of deleting the shared file. |
| D2 | `tests/virtual_net.rs` encodes a **stale** frame layout — payload at offset **9**/max 487, vs production offset **10**/486 | `tests/virtual_net.rs:166-167` vs `net/mod.rs` | Align to `OFFSET_PAYLOAD_START`, or `#[path]`-redirect this duplicate to `tests/common/virtual_net.rs`. |
| D3 | `docs/SPECIFICATIONS.md` says the GTF counter is `u32` **(LE)**; the code writes `.to_be_bytes()` (BE) | `docs/SPECIFICATIONS.md:33` vs `net/mod.rs` `build_privacy_frame` | Change the doc to BE. |
| D4 | `index.html` still ships the phantom `./target/release/ggn-daemon --listen 0.0.0.0:2270 --socks 127.0.0.1:1080` copy-paste block, and its frame inspector draws a layout (`MAGIC[4] NONCE[8] POLY1305[16] …`) that matches neither the code nor SPECIFICATIONS | `index.html:876`, `:698-702` | Replace with `vantablack` + env vars; redraw the inspector from `net/mod.rs`. |
| D5 | `README.md` still claims exit nodes "Rotate egress IPs" and NAT traversal is "Bypassed" via STUN hole-punching — neither is implemented | `README.md:57`, `README.md:115` | Delete the two claims; VPN now supersedes the NAT story anyway. |
| D6 | `scripts/mesh_smoke_test.sh` and `scripts/pentest_ggn.sh` probe `C:/Users/Public/ggn-target/debug`, a path `.cargo/config.toml` documents as removed | `scripts/*.sh:19,23` | Drop the second candidate dir. |
| D7 | `net/security/hsm.rs` gates code on `hardware-tpm` / `pkcs11`, but neither feature is declared in `Cargo.toml` → that code can never compile, and `--features hardware-tpm` is an "unknown feature" error | `Cargo.toml` features list vs `hsm.rs:142,157,190,240,256,276` | Declare both (as no-op stubs) **or** delete the gated blocks. Either is better than a claim that cannot be built. |
| D8 | `main.rs` hard-codes the version string `"Global Ghost Net v0.4.0 starting"` while the VPN work is well past v0.4.0 | `main.rs` startup log | Read `env!("CARGO_PKG_VERSION")`, and bump the package version. |
| D9 | The whole `vpn` subsystem (~3.8 kLOC) is **never built in CI** | `.github/workflows/release.yml` runs `cargo test --locked` / `cargo build --release --locked` with no `--features vpn` | Add `cargo test --features vpn` and `cargo check --features vpn` to the `test` job. |
| D10 | `UdpFlowTable::flow_for_local_port` is a linear scan over all flows, called per inbound LAN datagram | `net/vpn/mod.rs` | Keep a secondary `HashMap<u16, FlowKey>` keyed by local port. |
| D11 | `UdpFlowTable::get_or_create` re-inserts a *refreshed* `Arc<UdpFlow>` but returns the **old** one, so the caller's `last_seen` is stale | `net/vpn/mod.rs` `get_or_create` | Return the refreshed Arc, or refresh in place. Harmless today; a trap if anything ever reads `last_seen` off the returned handle. |
| D12 | `LeaseTable::endpoint_for_ip` / `fingerprint_for_ip` scan all leases | `net/vpn/mod.rs` | Secondary index by overlay IP (the table is capped at 245 hosts, so this is tidiness, not urgency). |
| D13 | No `git` repository exists, yet PROTOTYPE.md documents `git tag proto-baseline` / `git reset --hard proto-baseline` and cites commits `4bc75b7`, `2df37fd` | `ls -d .git` → absent | `git init`, import the v0.4.0 snapshot, tag it `proto-baseline` as documented — otherwise the documented rollback path does not exist. |
| D14 | `identity.key` is present in the working tree root and is a live private key (`.gitignore` does list it) | `ls -la` | Keep it out of any future commit; note that the file is now relocatable via `GHOST_IDENTITY_FILE`. |

---

## 5. Documentation debt

- **The `(line NN)` roadmap is still missing.** Eleven source comments cite a
  numbered list at lines 16–33 (*Portable Single Executable Packaging*,
  *AES-XTS Memory Encryption*, *Memory Guard & Secure Zeroing*, *Decentralized
  Capability Revocation List*, *Zero-Knowledge Authentication During Discovery*,
  *Fixed-Slot Temporal Isolation*, *Verified IPC Buffers*, *Decentralized
  Two-Line Element Distribution*, *TPM/HSM Key Enclave*, *eBPF/XDP*, *NTS/Atomic
  Clock*). `PROTOTYPE.md` is a different document and does not contain them.
- **`UNWIRED.md` (in this repo) is stale.** It was written against the previous
  tree: it asserts `hardware-tpm`/`pkcs11` were declared (they are not — D7), and
  it predates the whole VPN subsystem. Either regenerate it from the current
  tree or fold its still-valid rows into this file and delete it; two
  overlapping gap-lists will drift.
- **Two document sets now disagree.** `PROTOTYPE.md` + `docs/LAN_OVER_WAN.md` are
  candid and current; `README.md` + `index.html` + `docs/SPECIFICATIONS.md` still
  overclaim (D3–D5). The honest set should win.

---

## 6. Notes too small to be their own item

- `send_tunnel_frame` does `sessions.get()` then `next_tx_counter()` in two
  steps; a re-handshake in between yields a frame sealed for the old epoch.
  Cheap to close by taking one session snapshot.
- The hub answers ICMP echo in userspace, so `ping 10.66.0.1` works but
  `ping <LAN host>` is dropped (counted). That is deliberate (no fake answers),
  and is the documented v2 gap — worth surfacing in `VPN STATUS` so it is not
  mistaken for a fault.
- Search-domain push (`GHOST_VPN_SEARCH`) is documented as v1 but appears only in
  config plumbing — verify it reaches the TUN/DNS layer on each platform.
- `wintun.dll` redistribution: PROTOTYPE.md flags the Tailscale-shipped copy as
  dev-only. Packaging must vendor the official 0.14.x zip or ship no .dll.
- `MAX_IP_PACKET`/`TUNNEL_MAX_PAYLOAD`/`TUN_MTU` are consistent today (1280 TUN
  MTU → 1446 B bulk payload); if TUN_MTU ever rises, `OVERLAY_MSS` and the
  netstack MSS clamp must move together. Worth an assertion.
