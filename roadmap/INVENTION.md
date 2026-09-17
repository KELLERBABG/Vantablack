# Global Ghost Net — Invention Track (Beyond SOTA)

> **Companion to `roadmap/SOTA.md`.** SOTA gets you to `v1.0` — best mesh done right by copying standards correctly (ICE, ML-DSA, BBR, Sphinx). *This* file is how you define the *next* SOTA — 20 systems-level inventions nobody else can ship because nobody else has your stack (any-2-of-3 RS sharding + hybrid PQ + epoch ladder + tit-for-tat + GTF).

**Rule:** Never invent primitives. Invent *compositions*. Use standardized crypto (ChaCha20, ML-KEM, ML-DSA, SHA-2) and bend how they are *wired*.

How to use: Each concept is a **2-week spike** with a kill gate. If it doesn't show measurable advantage over `Tor / Tailscale / Nym / Mullvad` on its stated experiment in 14 days, kill it and try the next. 2–3 spikes in parallel, max. When a spike graduates, it gets a real spec in `docs/` and a line in `SOTA.md Phase N+1`.

## Graduation ledger — 2026-09-17

The current SOTA implementation baseline has graduated the repository-side portions of **§1 ShardSec** and **§13 Zero-RST Mobility**: both are live behind the documented protocol/configuration paths and have code-level regression coverage. Their remaining entries are validation gates, not invitations to claim hardware, network, or device proof from compilation alone. The next invention-track work therefore begins at **§2 Ghost Handshake — Magic-less PQ Deniability**, unless a separate product decision selects another spike.

---

## How these 20 were chosen

Every idea exploits something **already in this repo** that competitors don't have:

* `l4_rs::encode(2,1)` — any 2 of 3 recovers → information-theoretic sharding hook
* `l6_session::SessionGuardU64` + `vpn::LeaseTable` epoch ladder — mobility primitive
* `net::mesh::DisjointRouteConstraint` + `net::orbit::KeplerElements` — cross-plane enforcement
* `net::mesh::TitForTatEnforcer` + `net::relay::BundleBuffer` — trustless relay hook
* `net::security::RevocationList` + `ZkAuthenticator` — voucher/attestation hook
* `layers::l8_memsec::LockedMemory`/`SecureMemGuard` — physical deniability hook

If an idea doesn't need one of those, it probably belongs in another product.

---

## I. Cryptographic Inventions (5) — make harvest-now-decrypt-later useless

### 1. ShardSec — Per-Shard Ephemeral Keys (any-2-of-3 is actually 0-of-1)

**Idea:** Today `enc_split` uses one session key for all 3 shards. Change to 3 *different* ephemeral `ChaCha20-Poly1305` keys, each HKDF-derived from `master || shard_index || epoch`, sent on 3 disjoint planes. One path capture = random bytes. Even if the PQ KEM is broken in 10 years, attacker needed 2 *planes* + 2 *keys* at the same time.

**Why novel:** Tor has 1 circuit key. Nym has 1 Sphinx key. Nobody splits trust across planes *and* keys. Your `disjoint + RS` makes the 1-shard=0-bytes claim information-theoretic, not hand-wavy.

**First experiment (3d):** `net::shardsec::seal_message` now forks the `enc_split` design: RS shards are sealed independently with HKDF-derived per-shard keys and shard-indexed nonces. `open_message` authenticates before reconstruction, reconstructs from any two valid shards, and rejects a single captured/tampered shard. The remaining migration gate is replacing the legacy single-tag `enc_split` wire contract in every daemon egress/ingress path while preserving the 576-byte privacy-frame invariant.

**Kill if:** overhead >8% or single-shard brute force reveals length via `frame_shard` prefix.

### 2. Ghost Handshake — Magic-less PQ Deniability

**Idea:** `GHOST_HANDSHAKE_` / `GHOST_RESPONSE__` magic makes every flow trivially DPI-classifiable. Replace with a uniform-random transcript: both PDUs look like `768B` random (ML-KEM `ct` is already uniform) via Elligator-style X25519 point encoding + padded Ed25519 sig. Passive observer sees UDP noise.

**Why novel:** Noise/WireGuard still have handshake fingerprints. A fully random PQ handshake over UDP is still open research.

**First experiment (4d):** Build `uniform_handshake` behind `GHOST_HANDSHAKE_UNIFORM=1`, run `scripts/pentest_ggn.sh` chi-square — uniform vs current p-value should flip to `>0.1`.

**Kill if:** Kyber `ct` uniformity broken by compression or X25519 Elligator costs >2ms.

### 3. Burnable Ghost IDs — Unlinkable Per-Peer Identities

**Idea:** Don't reuse one `Ed25519` fingerprint everywhere. Derive `HMAC(seed, peer_fp || epoch)` → one-time `SigningKey`. Hub sees a different `fp` per peer, peers can't correlate you across ASNs. Master seed stays in `LockedMemory`. Rotate on `LeaseTable::rotate_epoch`.

**Why novel:** Tor guards are linkable by key. Tailscale is identity-pinned. Per-peer burnables give you *network-level* unlinkability without blockchain.

**First experiment (2d):** Add `derive_burnable(dh_seed, peer)` in `l0_identity.rs`, prove 1000 derives → 1000 distinct `fp`, same `seed` recovers same `fp`.

**Kill if:** `peers.cache` / `RevocationList` semantics break or 500-peer rotation costs >50ms.

### 4. Self-Destructing Epochs — Harvest-Then-Decay

**Idea:** Every `VpnIngress` epoch key self-expires: after `SILENCE_REANCHOR + 60s`, `SecureMemGuard::panic_zero()` wipes it and `LeaseTable::tunnel_v_max` resets to `u32::MAX` (all old counters become replay). A seized disk or HNDL capture from last year is mathematically dead — not policy-dead.

**Why novel:** Most VPNs keep session keys until reboot. You're making forward secrecy *temporal and enforceable in RAM*, not just ratcheted.

**First experiment (2d):** Add `epoch_ttl: Instant` to `Lease`, prove `cargo test vpn` where old wire replay after TTL → `AuthFail` not `Replay`.

**Kill if:** legitimate 2-min silence (phone sleep) causes unnecessary re-handshake storm.

### 5. PQ Double Ratchet over ML-KEM (not just counter warnings)

**Idea:** Replace `MAX_SAFE_COUNTER warn` with real ratchet: every 256 datagrams or 60s, mix new `X25519 + ML-KEM` ECDH into `master` via `HKDF(master || new_ss)`, ratchet `SessionGuard` window atomically. Compromise of epoch `N` doesn't decrypt `N-1` (PFS) or `N+1` (PCS) without new KEM break.

**Why novel:** Signal ratchet is classical-only. PQ ratchet over lattice KEM with UDP loss is unsolved and you have the loss-tolerant RS layer to hide ratchet messages.

**First experiment (5d):** Prototype `Session::ratchet(new_ss)` behind `GHOST_RATCHET=1`, prove `needs_rekey` never hits in 10M-packet `scale_mesh` run.

**Kill if:** ratchet desync under 20% loss requires more than 1 retransmit.

---

## II. Anonymity & Traffic Analysis Inventions (5) — DPI thinks you're Chrome

### 6. GhostMimic — Learned Per-ASN Cover Traffic

**Idea:** Don't do constant-rate cover (itself fingerprintable). Train a tiny per-ASN Markov model of real `GTF` inter-arrival + size from the local net (when `GHOST_MIMIC_LEARN=1` with user consent). Then `L5` pads *inside* the Poly1305 tag + sends dummy `0x04` frames so the wire distribution `D(Ghost)` ≈ `D(Chrome+YouTube)` on that ASN. Censor sees local traffic, not protocol.

**Why novel:** Constant-rate cover is 90s. ASN-mimic is new and your `L5 jitter inside tag` (Phase 3 fix) is the perfect hook.

**First experiment (4d):** Log 10 min of real `GTF` vs Chrome sizes, train 16-state histogram, Jensen-Shannon distance `JS < 0.05` after mimic vs `0.4` before.

**Kill if:** model leaks user browsing via sizes (audit: model never stores host).

### 7. Poisson-Cloaked Beacons

**Idea:** Your `PoissonReputationMatrix` models cosmic errors as `Poisson(λ)`. Invert it: emit beacons as `Poisson(λ_beacon)` with `λ` tuned to mimic background UDP noise on that LAN (mDNS/SSDP). Signed beacons on `239.255.0.1:2270` become statistically invisible.

**Why novel:** Beacons are usually periodic = trivial detector. Poisson + `ZkAuthenticator` makes discovery indistinguishable from LAN chatter.

**First experiment (3d):** Replace `BEACON_INTERVAL_SECS=30` with `Exp(λ=1/30)`, capture Wireshark, prove periodogram shows no 30s peak.

**Kill if:** discovery latency p95 >90s.

### 8. Sphinx-Shard Onion — 3 Hops, Constant Size, Shard-Aware

**Idea:** Extend `RLY!` to Sphinx-like `576B` fixed-size onion where *each* shard carries its own 3-layer header (guard→middle→exit). Exit does combinatorial `Poly1305` check *before* `RS reconstruct`. Middle nodes can't tell which shard they carry or who the exit is.

**Why novel:** Tor onion is 1 path. Nym Sphinx is 1 packet. Yours is 3 *shard-tagged* onions that only combine at the exit — adversary needs 2 middles on 2 planes.

**First experiment (5d):** Implement `build_sphinx_shard` fixed 576B, prove `cargo test` where 1 middle drops → still reconstructs from other 2.

**Kill if:** header >80B or 3× Sphinx adds >15ms.

### 9. Innocent Camouflage — Steg GTF inside QUIC/DNS/HTTPS

**Idea:** Pluggable transports: wrap `GTF` as seemingly innocent `QUIC` `STREAM` frame, `DNS-over-HTTPS` query, or `HTTPS` `fetch` chunk when `GHOST_CAMO=quic|doh`. Your `bulk 1472B` already MTU-fits. Censor that blocks `0.0.0.0:2270/UDP` still sees `443/TCP`.

**Why novel:** obfs4/utls are TCP-only and not PQ. QUIC-camouflaged PQ-RS over UDP is new.

**First experiment (4d):** `QUIC` camo: GTF → `quinn` `UnreliableDatagram` inside TLS 1.3, DPI says `h3`.

**Kill if:** QUIC handshake adds >100ms or GFW active probe kills it.

### 10. Header-Chaff GTF — Encrypted Length Prefix

**Idea:** Today `frame_shard = [len:2][shard]` is unauthenticated length in clear inside ciphertext but outside tag scope for bulk. Move length *into* `ChaCha20` AAD and chaff the `GTF` header `[session_hash|ctr|shard|flags]` with format-preserving encryption so every `576B` datagram is uniform random.

**Why novel:** Makes GTF itself a *uniform random string* — the hardest object for a classifier to fingerprint, and length is now authenticated.

**First experiment (2d):** Change `build_gtf_frame` to `encrypt(header||len||shard, AAD=epoch)` and prove `unframe` tamper → `auth_fail`.

**Kill if:** breaks `LocklessDispatcher` `parse_session_hash` fast path (needs header in clear for routing — solve via `XDP` keyed hash).

---

## III. Mesh Physics & Resilience Inventions (5) — the WAN fights back

### 11. Shatter Routing — One Message, Three Physics

**Idea:** Enforce `DisjointRouteConstraint` across *media*, not just peers: shard 0 → `WiFi` (OS `SO_BINDTODEVICE wlan0`), shard 1 → `LTE` (`rmnet0`), shard 2 → `DERP relay` or `eth`. Adversary tapping one ISP / one radio sees 1 shard.

**Why novel:** Multipath is usually 3 TCP subflows on same NIC. Cross-PHY shattering across heterogeneous radios is military-grade and nobody does it for consumers.

**First experiment (3d):** Bind per-shard `UdpSocket::bind_device` on Linux, `iperf` loss on WiFi kills only shard 0, still recovers.

**Kill if:** Android `VpnService` can't expose 2 `UdpSocket` with different marks (needs `protect()` dance).

### 12. Predictive Pre-Warming — Keys Before Line-of-Sight

**Idea:** Use `KeplerElements::position_eci` + `GroundPosition::distance_to` *predictively* on the phone: when `can_see(hub)` will be true in `+30s`, pre-do `Kyber encapsulate` + `X25519 ECDH` now so handshake is 1-RTT when link appears. Same math works for terrestrial mobility: predict WiFi AP handover from `BSSID` history.

**Why novel:** Turns your "satellite scaffolding" into a real mobile predictor, not a stub.

**First experiment (3d):** Log `BSSID` RSSI over walk, predict next AP with 80% accuracy, pre-warm reduces handshake p95 from 120ms→40ms.

**Kill if:** Kepler propagation drifts >5km without TLE update (needs `TleDistributor::store_tle` gossip).

### 13. Zero-RST Mobility — TUN Migration Without TCP Death

**Idea:** Keep `TUN_MTU=1280` TCP flows alive across `WiFi→LTE` by *not* killing the TUN. On `ConnectivityManager` callback, `LeaseTable::observe_tunnel_packet` `WindowAdvance` re-anchors `endpoint` and `VpnIngress` epoch stays, `netstack` keeps `MSS` clamped via `OVERLAY_MSS`, and `AckEngine` deliberately *doesn't* retransmit (inner TCP does). Phone changes IP, TUN `10.66.0.10` stays.

**Why novel:** Tailscale/Mullvad kill and re-establish. You're migrating the *overlay* while the *underlay* changes — your epoch ladder already almost does this.

**First experiment (5d):** `tests/vpn_resilience.rs` add `roaming_migration` with 2 endpoints, `netstack` TCP `SYN→SYN-ACK` survives endpoint swap.

**Kill if:** Linux `conntrack` or carrier NAT drops return path for >5s.

### 14. Self-Tuning Concatenated Code (RS + LDPC that learns)

**Idea:** Don't use `RS(2,1)` *or* `LDPC(512,1024)` statically. Concatenate: `LDPC` inner corrects bit flips, `RS` outer recovers erasures. Feedback loop: `PoissonReputationMatrix::observed_error_rate` → tune `LDPC` iterations + decide `RS` vs `bulk` vs `shatter`. Bad link auto-adds parity at cost of throughput.

**Why novel:** Concatenated codes are textbook but *adaptive* concatenation driven by live Poisson error estimate is new for a consumer VPN.

**First experiment (4d):** Simulate 8% BER → LDPC 10 iterations + RS reconstruct beats RS-only by >2×, 0.1% BER auto-disables LDPC (saves 50% overhead).

**Kill if:** `LDPC` 10-iter decode adds >8ms at `128B` block.

### 15. Honey-Shards — Adversarial Tamper Traps

**Idea:** On 1% of flights, inject a *honey shard* that is valid `GTF` but whose `Poly1305` tag is deliberately bound to a trap key. Byzantine relay that tampers will produce a predictable `auth_fail` pattern (`pair (0,2)` fails only when honey on 1) → instant `is_byzantine` flag with proof.

**Why novel:** Turns your combinatorial `Poly1305` check from passive detection into *active* adversary deanonymization.

**First experiment (2d):** Add `is_honey: bool` to `ShardRoute`, prove tampered honey → `PoissonReputationMatrix` `is_byzantine` true with p-value `<1e-9` in 10 flights.

**Kill if:** honey overhead >2% or honest loss triggers false positive >1e-6.

---

## IV. Trust, Incentives & Hardware Inventions (5) — make the mesh want to help

### 16. ZK Proof-of-Transit — Relay Proves Without Seeing

**Idea:** Relay that forwards sealed `GTF` produces `ZK proof = Ed25519(sign(H(payload) || next_hop))` without decrypting payload. Client later verifies proof chain `client→relay→exit` matches `BundleProtocolHeader` hop list. Relay earns `TitForTat` credit, can't claim free credit, learns nothing.

**Why novel:** Today's DERP trusts the relay. You're making relays *accountable* yet *blind*.

**First experiment (3d):** Relay signs `blake3(shard)` + `next_fp`, client verifies chain, tampered proof → `RevocationList` entry.

**Kill if:** proof adds >64B per hop or `ZkAuthenticator` mock must become real Bulletproofs.

### 17. Trustless Relay Marketplace — Pay-to-Forward with Vouchers

**Idea:** Combine 16 + `TitForTatEnforcer`: client mints `cap_voucher.rs`-style capability vouchers (`Ed25519` signed `allow forward N bytes until T`) that are *redeemable* for priority. Relays prioritize voucher traffic, vouchers are double-spend checked via `RevocationList::prune_expired`. No blockchain, just `DashMap` + signatures.

**Why novel:** Nym needs token. Tor is altruistic. You're doing *capability-based* QoS where forwarding history *is* currency, and `Poisson` isolation is the slashing.

**First experiment (4d):** Voucher `mint → forward → verify → tit_for_tat.credit`, double-spend → drop, bench 10k voucher verifies/s.

**Kill if:** voucher verification adds >0.5ms per packet.

### 18. Attested Exit Diversity — ZK Proof of ASN

**Idea:** Exit proves it lives in a different ASN/country than guard without revealing its IP: `ZK proof = "IP ∈ ASN X"` via Merkle proof over `RIR` delegation file + `Ed25519` attestation. Client enforces *multi-ASN* shatter: 3 shards never share ASN.

**Why novel:** Tor's diversity is advisory. You're making ASN-disjointness *cryptographically enforced* per flight.

**First experiment (5d):** Build `RIR` Merkle tree (e.g. `delegated-apnic-latest`), prove `203.0.113.1 ∈ APNIC` in <1ms, verify without IP.

**Kill if:** RIR file >1MB or proof >2KB.

### 19. Hardware-Bound Ghost — TPM Quote + SecureMemGuard

**Idea:** Bind `GhostIdentity` seed to `TPM2` `PCR` quote + `LockedMemory` `VirtualLock`. Node proves "I am the same physical device that minted `fp`" via `TPM2_Quote` over `fp || epoch`. Seized disk without TPM = no identity, cold-boot without `VirtualLock` key = zeros.

**Why novel:** Tailscale node keys are files. You're making identity *physically* bound and remotely attestable with `SecureTimeKeeper` anti-replay.

**First experiment (4d):** `SoftwareTpm` → `TssTpm` behind `hardware-tpm` feature, `TPM2_CreatePrimary + Quote`, verify on hub.

**Kill if:** `tss-esapi` adds >5MB or needs kernel driver absent on consumer laptops.

### 20. Ephemeral Amnesia Mode — Plausible Deniability

**Idea:** `GHOST_AMNESIA=1` keeps *zero* persistent state: `identity.key` in `SecureMemGuard` only (never `fs::write`), `peers.cache` in RAM, `ghost-consumer.json` `mlock`ed. On `SIGTERM` or `panic`, `Drop` zeroizes and node forgets it ever existed. Pairing via QR only, no disk artifact.

**Why novel:** Even Mullvad writes WireGuard keys to disk. You're offering *single-session* deniability for journalists, with `wintun.dll` still working because TUN is ephemeral.

**First experiment (2d):** Run with `GHOST_AMNESIA=1`, `kill -9`, prove `ls -la $GHOST_DATA_DIR` shows no `identity.key` and `strings` on RAM dump after `mlock` shows no seed.

**Kill if:** Windows `VirtualLock` working set limit fails or users lose identity on crash and complain.

---

## How to pick your first 3 spikes

| If you want… | Start with | Why |
|---|---|---|
| **Press + audit buzz** | 1 + 6 + 10 | All demo-able in Wireshark, all use your unique RS+disjoint hook |
| **Investor demo (phone)** | 11 + 13 + 7 | Shatter + zero-RST + Poisson beacons = "watch this SSH survive airplane mode toggle" |
| **Research paper** | 5 + 8 + 16 | PQ ratchet + Sphinx-shard + ZK transit = 3 publishable contributions |

**Next step after this file:** Pick 3, open `roadmap/SOTA.md Phase N+1` tracking issues, and reserve 2 weeks. Everything else stays in this file until a spike graduates.

---
---

# Part II — Radical Spikes (post-20)

> **Why a second part?** §I–§IV (the 20) all obey one rule: *exploit a hook that already exists in this repo.* That keeps them shippable, but it also caps ambition — every one of them is a better version of something Tor/Tailscale/Nym already attempts. **Part II breaks that rule deliberately.** These ideas are allowed to invent *new subsystems*, as long as they keep the same thesis: **compose, don't invent primitives** (ChaCha20, ML-KEM, ML-DSA, SHA-2 stay standard), and stay **provable by a 2-week spike with a kill gate**.
>
> **The through-line.** All of Part II composes one of four new *ways of wiring* (never new cryptography):
> 1. **Split the object** — the same any-2-of-3 shard/erasure logic applied to things that are *not packets*: models, files, computation, identity, time, physical channels, groups.
> 2. **Adversarial-but-honest** — split *trust* and *verification* across mutually-distrusting planes so correctness is a property of the wiring, not of anyone's good behavior.
> 3. **Discontinuity as a first-class assumption** — the network has gaps in *time*, not just space; design for absence, not just loss.
> 4. **Reality check beat** — every Part II spike ends with a lab attack simulator, not a happy-path benchmark.

Same format as above: **Idea · Why novel · First experiment · Kill if**. Same kill discipline: 14 days or it dies.

> **Honesty pass (added after a prior-art review).** These are **not** new primitives, and most are **not** unseen mechanisms — that follows from this file's own law, *compose, don't invent primitives*. A prior-art scan of all 34 (named per item, below) lands here:
>
> | Tier | Meaning | Items |
> |---|---|---|
> | **A** | No direct prior art found; the novelty is the *framing* (still composed from known primitives) | 27, 30 |
> | **B** | Components exist in research; this exact composition for a PQ mesh VPN is unpublished | 28, 31, 33, 35, 38, 39, 40, 41, 45 |
> | **C** | Established elsewhere (named per item); the only genuinely new element is the mesh-VPN deployment/wiring | the other 22 |
> | **D** | Self-contradictory or likely impossible; kept only to define a boundary | 54 |
>
> Read **C** items as *engineering bets* (ship and measure); only **A/B** items are *research* bets. Five claims were corrected in this pass — **§24, §30, §36, §42, §54** — read those corrections before citing anything.

---

## V. Data-Plane Inversions (5) — the data *is* the network

### 21. Sharded Compute — no peer ever holds the whole model

**Idea:** Invert the shard logic: stop sharding only *data* and start sharding *computation*. Split a small model into 3 weight-sets (any 2 of 3 sufficient, RS-coded for straggler tolerance) and run partial forward passes on 3 disjoint peers, combining outputs client-side. No single peer ever sees the whole model *or* the whole input, yet the client gets one answer.

**Why novel:** Every "decentralized inference" today either replicates the model everywhere or trusts one worker. Sharding compute under the *same* erasure discipline used for packets — on unreliable links — is unshipped and matches the mesh's existing failure model exactly.

**First experiment (5d):** Split a small model's MLP blocks across 3 loopback workers, prove `any 2 of 3` output matches a local reference within tolerance and that killing 1 worker still returns a correct answer.

**Kill if:** per-token latency >6× local or weights must be re-broadcast more than once per 1k tokens.

**Prior art / novelty tier:** **C** — [Petals](https://github.com/bigscience-workshop/petals) (BigScience, 2023) already shards a transformer across untrusted internet peers with fault-tolerant partial restarts, and redundancy-for-correctness is BOINC's replication. New here is only the per-shard-key + disjoint-plane wiring.

### 22. Fleet Vault — a file that *is* the mesh

**Idea:** A file you `put` isn't stored on a peer; it's erasure-coded per-shard, keyed per-shard (see §1 ShardSec), and hosted by whatever peers are up. Retrieval walks the mesh until `any k of n` shards come back. Add host-attestation so a shard can't be silently dropped (§19 TPM quote + §15 honey-shard). The file self-heals as peers churn; you never run a server, the file *is* the network's current membership.

**Why novel:** IPFS/BitTorrent separate "storage" from "routing." Here an object's availability is a direct function of mesh topology, with dishonest-drop detection built in — three properties (anonymous, self-healing, tamper-evident) in one composition.

**First experiment (4d):** `put` a 1 MB file, churn 40% of peers, prove retrieval within <5s and that a peer returning a corrupted shard is flagged and excluded.

**Kill if:** retrieval p95 exceeds 3× the object's byte-size / measured link throughput (i.e. churn overhead dominates).

**Prior art / novelty tier:** **C** — [Tahoe-LAFS](https://tahoe-lafs.com/trac/tahoe-lafs/wiki/FAQ?version=58) (2008) *is* this: client-side-encrypted, erasure-coded (3-of-10 default), provider-independent ("servers can neither read nor modify"), self-healing storage with no central storage server. The honest new element is only mesh-routing + honey-shard dishonest-drop detection.

### 23. Ciphertext-Only Storage — the host learns nothing, forever

**Idea:** Hosts store *only* ciphertext they can never decrypt: per-shard keys never leave the owner, hosts hold opaque `576B` GTF blobs, and integrity is checked via a commitment they can verify without the key. Even a host that later gets compromised, or coerced, or seized holds random bytes. Combine with §20 Amnesia so hosts have no *record* that they are hosts.

**Why novel:** Encrypted cloud storage still lets the provider correlate access patterns. Deniable, pattern-free, key-less hosting where the host cannot even tell *which* object it holds is a different class of claim.

**First experiment (3d):** Store 100 blobs, prove host-side `strings` yields no key, no plaintext hash, and no object-identity correlation across two blobs of the same file.

**Kill if:** owner cannot detect a host that returns garbage on *every* fetch (needs a cheap challenge-response that isn't itself a distinguisher).

**Prior art / novelty tier:** **C** — this is Tahoe-LAFS's "provider-independent security" + verifycaps again; **overlaps §22** ("who hosts" vs "what a host sees" are the same Tahoe-class idea). A spike should **merge §22/§23** rather than run both.

### 24. Sharded Inference Privacy — the split is a *transport* claim, not a privacy proof

**Idea:** Formalize §21 into a *narrow* property: at every peer, the shard it holds is information-theoretically useless on its own — the same `l4_rs` any-2-of-3 guarantee the transport uses — and expose it as a routing **policy**: "never let two shards of one request reach the same peer or the same ASN."

**Why novel (revised):** The contribution is *unifying a transport guarantee with a routing policy* — one primitive, two trust domains — not proving that inference is private. That is a much smaller, defensible claim.

**First experiment (4d):** For a 3-peer pipeline, run the pairwise mutual-information test from `attack_harness` on the *shards in transit* and show no peer's view of the bytes leaks more than the shard's own entropy.

**Kill if:** enforcing the policy costs >2× routing overhead, or a colluding pair of peers recovers a shard pair without a third.

**Prior art / novelty tier.** **B** (framing), with a **correction**: do **not** claim the split makes inference private. Split inference / split learning is documented to *leak* — a semi-honest worker reconstructs inputs from intermediate activations (*Unleashing the Tiger*, CCS 2021; *UnSplit*, WPES 2022; the [split-learning attack/defense SoK](https://dl.acm.org/doi/abs/10.1007/978-3-032-32578-5_1)). An information-theoretic per-peer guarantee for *computation* requires secret-sharing/MPC (CrypTFlow2, [BumbleBee](https://www.ndss-symposium.org/ndss-paper/bumblebee-secure-two-party-inference-framework-for-large-transformers/), [PIGEON](https://crysp.petsymposium.org/popets/2025/popets-2025-0090.php)) — which pays exactly the cost this idea was invented to avoid. Keep the claim to the bytes.

### 25. Verifiable Compute via Retransmission

**Idea:** Re-run the same Part-II shard job at a second, independent peer and compare *only a hash commitment* (not the work). A mismatch flags the pair via the existing combinatorial `Poly1305`-style check; a retry to a third peer resolves it. Correctness comes from redundancy, exactly like packet shards — no ZK circuit.

**Why novel:** The industry's instinct is zkML/ZK circuits (expensive). The mesh already lives in a redundant-erasure paradigm; extending "verify by retry" from bytes to computation is cheaper and matches the failure budget it already runs.

**First experiment (3d):** Inject a lying worker, prove the commitment mismatch localizes to it in <3 retries with no false positives across 1k honest jobs.

**Kill if:** redundant computation pushes useful throughput below the mesh's own packet-level goodput.

**Prior art / novelty tier:** **C** — BOINC used redundant replication with cheat detection for exactly this; Petals already proposes "send tensors through multiple disjoint routes and compare." The mesh just reuses its own erasure budget as the verifier.

---

## VI. Time & Discontinuity (5) — bits that survive being *absent*

### 26. Dead-Drop Addressing — rendezvous without a server

**Idea:** An address isn't a host; it's a `SHA2` commitment. Anyone can *deposit* a shard at the address; only the key-holder *withdraws*. Deposits are indistinguishable from any other shard on the wire, and the recipient's periodic sweep is just more mesh traffic. Builds on §3 (burnable IDs) + §22 (erasure hosting) to make a mailbox that exists without a server and without linkability.

**Why novel:** Tor hidden services still need a rendezvous *point*; this is a rendezvous *commitment* with no point — coupled to the same erasure + unlinkable-identity machinery, it becomes a delay-tolerant anonymous drop with no infrastructure.

**First experiment (4d):** Deposit 8 shards across the mesh; a key-holder sweeps and reconstructs after a 3-day simulated outage with no peer having a persistent index of the address.

**Kill if:** sweep latency requires more than one O(mesh-size) pass or deposits become linkable by size/timing.

**Prior art / novelty tier:** **C** — this is a crowded, well-studied design: [Vuvuzela](http://os.inf.tu-dresden.de/Studium/ReadingGroupArchive/slides/2015/20151008-bierbaum-vuvuzela.pdf) (SOSP 2015, mailbox = `H(pk) mod m`), Blockchain Commons' Hubert (DHT/IPFS dead-drops with HKDF-derived ARIDs), DatashareNetwork (hash-rendezvous mailbox), Zax, and patent US10334037B2. The mesh's only new element is reusing §22 hosting + §3 burnables.

### 27. Spatio-Temporal Erosion Codes — data that literally fades

**Idea:** Encode so that information is recoverable only if gathered across *both* space and time — shards spread across peers **and** across epochs, with old shards *deliberately* eroding (rotating keys, §4). A limited adversary who can raid one location at one moment gets nothing; a harvester who captures the wire forever still needs `k of n` *epoch-reconstructed* pieces. Fade is a feature, not a bug.

**Why novel:** Every system minimizes time-to-reconstruct. None *enforces* that reconstruction needs a time axis. Harvest-now-decrypt-later's whole premise is "capture at one time"; making the plaintext require legitimate temporal presence kills the premise at the coding layer.

**First experiment (4d):** Encode a secret across 3 peers × 3 epochs, prove reconstruction needs ≥2 epochs of honest keys and that a single-epoch capture opens zero.

**Kill if:** legitimate re-fetch requires the user to be online in ≥2 separate windows (breaks async usability) with no way to add a live "entropy oracle."

**Prior art / novelty tier:** **A** — the pieces are known (regenerating codes, Dimakis et al. 2007; forward-secure storage), but "reconstruction *requires* a time axis as a deliberate feature" is the one Part-II idea I could not match to direct prior art. This is the strongest *research* bet in Part II; treat the "kill if" as the real experiment.

### 28. Present-Tense Mesh — presence is a cryptographic claim

**Idea:** Discovery stops meaning "here is a durable address." A peer proves it is *physically around right now* by combining recent local-entropy beacons (§7 Poisson + §9 timing) with a monotonic claim, so a faraway collaborator can't replay and a future collaborator can't pre-claim. The mesh routes to the *present*, which is exactly what mobile/handover needs (§13).

**Why novel:** Presence today = a valid key, i.e. a durable claim. Turning it into an *ephemeral, verifiable* one gives a physical-layer Sybil cost and makes the same design cover handover + dead-drops + anti-replay.

**First experiment (3d):** A replay attempt from a second host must be rejected because its entropy beacon set doesn't match the live epoch; honest presence must validate on reconnect in <1s.

**Kill if:** presence proof needs tight clock sync (which the mesh deliberately doesn't anchor) or fails across NAT.

**Prior art / novelty tier:** **B** — proof-of-location and distance-bounding are mature (Brands & Chaum 1993; [composable anonymous PoL, IEEE Access 2023](https://ieeexplore.ieee.org/document/10132439); [decentralized PoL, Nature Sci. Rep. 2025](https://www.nature.com/articles/s41598-025-04566-4.pdf)). New here is only folding presence into *discovery beacons already present* for a mesh, rather than a dedicated infrastructure.

### 29. Windowing the Blackout — retroactive reconciliation

**Idea:** When a link returns, two peers exchange *how their local worlds differed* during the gap and splice them — like erasure-repair but for a time window. Combine §26 dead-drops (what was dropped) with the `BundleBuffer` semantics already in `relay.rs` (what changed). Reconnection becomes reconciliation, not re-handshake.

**Why novel:** DTN and mesh healing are usually separate layers. Fusing them means a blackout is a *first-class event the protocol repairs*, giving a single mechanism for airplane-mode, censorship windows, and satellite gaps.

**First experiment (3d):** Simulate a 6h DTN partition with interleaved writes; prove both sides converge to identical state in one exchange after reconnect with no data loss.

**Kill if:** window state (what to remember) grows unbounded and can't be bounded by a fixed ring.

**Prior art / novelty tier:** **C** — this is DTN Bundle Protocol + anti-entropy/CRDT reconciliation (Merkle-tree sync, Cassandra-style repair). Fusing it with shard-repair is a *packaging* choice, not a new mechanism.

### 30. Time-as-the-4th-Shard

**Idea:** Treat *time itself* as a shard dimension. A message's 3 shards travel not only across 3 paths but **scheduled across 3 moments** (e.g. now / +200ms / next-beacon). An adversary present for only *part* of the schedule sees fewer than 2 shards.

**Why novel (revised):** The genuinely new content is narrow: making *latency scheduling a first-class privacy parameter* of the erasure code. That is a framing contribution, not a new primitive.

**First experiment (5d):** In `scale_mesh`, show a partial-window capture opens zero while end-to-end delivery stays within a configured T, and that T is enforceable per-flow.

**Kill if:** tolerable T forces real-time apps to fail (needs a per-flow opt-in and a hard correctness bound on scheduling).

**Prior art / novelty tier.** **A** (framing), with a **correction**: the original headline "a single-instant capture opens zero" is **trivially true of any 2-of-3 erasure code** — fewer than 2 shards never reveal anything — so it is *not* a new property. The claim must be restated as "temporal spread as a tunable anonymity dimension" and measured *against a partial-window adversary*, not against the generic erasure guarantee.

---

## VII. Ecology, Energy & Physics (5) — the mesh feeds itself

### 31. Energy-Voucher Currency — proof-of-useful-work, not proof-of-burn

**Idea:** Replace relay altruism with a voucher whose *backing* is proof-of-forwarded-work: a peer earns credit only by demonstrating it moved or repaired real shards (§16 ZK transit + §17 marketplace), and the proof is verifiable but reveals no payload. Duplicate-forward is rejected by the existing combinatorial check; double-credit by `RevocationList` pruning.

**Why novel:** Bitcoin burns energy for security; Filecoin proves storage; **nobody mints a currency whose denominator is "correct erasure repair I did for a stranger."** The mesh is the ledger and the work *is* useful.

**First experiment (4d):** Instrument an N-node run; prove credit correlates 1:1 with verified repairs, that a duplicate-forwarder earns nothing, and that verified-repair/sec stays flat as N grows.

**Kill if:** the voucher verification path costs more bandwidth than the throughput it prices, or admits a Sybil farm.

**Prior art / novelty tier:** **B** — proof-of-useful-work is an active field (Ofelimos, CRYPTO 2022 and its [local-search follow-up](https://eprint.iacr.org/2025/2091); [PoUFW](https://www.computer.org/csdl/journal/tq/2026/05/11578242/2hBThPPAFAQ)). Heed the 2025 [SoK "Is Proof-of-Useful-Work Really Useful?"](https://orbilu.uni.lu/handle/10993/67110): external utility rarely strengthens the security budget. New here is only that the "work" is *erasure repair*.

### 32. Diffusion Routing — no server ever sees the whole

**Idea:** Instead of a path from A to B, inject *bounded copies* that diffuse like heat, each copy erasure-coded so no one copy is intelligible, destined via §26 dead-drop semantics rather than an address. The "route" is an emergent property of the mesh's local trust, not a table — a mixnet without mix batches, a flood without a flood's cost.

**Why novel:** Tor needs a directory; Sphinx needs a path; flooding needs infinite fan-out. Bounded-fan erasure diffusion makes routing a *statistical* property and removes the global view an adversary usually needs.

**First experiment (4d):** Simulate 100 nodes; prove p95 delivery <T with fan-out bounded, and that no single node ever holds a full path table that reveals source and destination together.

**Kill if:** fan-out that meets T exceeds the mesh's fair-share bandwidth or delivery degrades unpredictably under 20% churn.

**Prior art / novelty tier:** **C** — epidemic/gossip routing and bounded flooding are classic DTN literature; "bounded fan-out + erasure-coded copies" is a repackaging of them.

### 33. Self-Eating Storage — a mesh that forgets on purpose

**Idea:** Storage is reclaimed by *demand* — pairs of peers periodically prove a stored shard is still wanted (a retrievability challenge); unrequested shards decay and are garbage-collected, with the `PoissonReputationMatrix`'s *observed error rate* driving decay rate. The mesh literally loses what no one uses, using error statistics as forgetting.

**Why novel:** Distributed storage systems are retention-maximizers. Using *observed network error* as the forgetting signal, so a healthy network forgets cheaply and a broken network holds on, is a genuinely new control loop — and it's a legal feature (data minimization by default).

**First experiment (3d):** Run a mock workload; prove ≥60% of cold shards are reclaimed while 0 hot shards are lost, driven purely by the repair-error signal.

**Kill if:** decay causes a hot-but-quiet object to vanish (needs a cheap "keep" proof users actually send).

**Prior art / novelty tier:** **B** — TTL caches, GC, retrievability proofs (Filecoin), and erasable storage are all old; the one mild, new element is driving *decay rate* from the live Poisson error estimate.

### 34. Beacon Grid — the infrastructure *is* the network

**Idea:** Turn §7's beacons into a physical reference grid: mesh beacons double as a crude distributed clock/location reference (region entropy, not GPS), and any node can later ask "where/when was I when beacon set `E` was live?" The network's own heartbeat becomes the thing you navigate by, in a world where GPS is jammed.

**Why novel:** Every "decentralized time" scheme (Roughtime, NTS) is *somebody's* server. If beacons already have to exist for discovery, making them a mesh-native spatial/temporal reference is a near-zero-marginal-cost capability nobody ships.

**First experiment (3d):** Prove two nodes separated by a partition agree on a coarse "epoch grid" within tolerance on reconnect, using only beacon exchanges.

**Kill if:** drift exceeds the tolerance an application can tolerate without an external anchor (e.g. TLS validity windows).

**Prior art / novelty tier:** **C** — NTP/Roughtime cover time; the [NIST Randomness Beacon](https://csrc.nist.gov/pubs/ir/8213/ipd) (2013/2018) and [drand](https://docs.drand.love/about/) (League of Entropy, 2019) cover distributed beacons. The only new bit is *piggybacking* on beacons that exist for discovery.

### 35. Thermal-Mesh — trust the thermally-different

**Idea:** Route shards by *physical energy class*, not just topology (§11 shatter): a battery-phone, a plugged desktop, and a solar relay have different "sustained-truth" profiles. Prefer splitting across heterogeneous energy budgets so no single adversary can afford to run all three classes. The heterogeneity *is* the security.

**Why novel:** The same mobility rationale as §11, extended to a resource the adversary can't cheaply fake: a Sybil farm has uniform, cheap energy. Forcing routes across genuinely distinct power/environment classes prices out the attacker.

**First experiment (3d):** Instrument 3 device classes; prove the router *prefers* a mixed-energy triple and that a uniform-energy cluster is measurably deprioritized.

**Kill if:** class can't be attested cheaply (needs a hardware hint) or honest mixed routes are unreliable under 20% churn.

**Prior art / novelty tier:** **B** — energy-aware routing is decades old (wireless-sensor-network literature); the newer contribution is the *security* framing: resource/energy heterogeneity as a Sybil cost.

---

## VIII. Interop & Legacy Subversion (5) — make the old world the new underlay

### 36. Shards over Tor — the dark forest becomes a road

**Idea:** Let each shard travel over an independent Tor circuit, a BitTorrent-swarmed object, or an IPFS DHT fetch — *reuse* the legacy anonymity transport as the underlay instead of racing it. The mesh contributes the erasure + disjunction; Tor contributes the hop coverage. Two anonymity layers, each cheap, composed.

**Why novel (revised):** Composing overlays multiplicatively is a plausible *resilience/coverage* win and is immediately deployable (Tor is everywhere) — sell it that way, not as an anonymity win.

**First experiment (3d):** Send a sharded message across 3 Tor circuits; prove a single-circuit observer sees 1 shard and that no *consistent* trio reassembly is possible from one guard's view.

**Kill if:** Tor latency makes TLC infeasible for interactive use (OK if it only graduates as a "high-latency but sovereign" tier).

**Prior art / novelty tier.** **C** — this is [Conflux](https://gk.pages.torproject.net/torspec/proposals/329-traffic-splitting.html) (Tor Proposal 329, multipath over independent circuits; original paper 2012, shipped Tor 0.4.8.4) plus the common "Tor as a transport" pattern. **Correction:** the anonymity benefit is *contested* — Conflux's authors report a slight anonymity *decrease*, and 2026 measurement work shows a latency-advantaged guard still fingerprints effectively. Claim resilience + cross-plane disjunction, not a correlation advantage over Tor.

### 37. Universal Shard-Tunnel — carry *any* protocol blind

**Idea:** Make the mesh a *generic* post-quantum shard transport: wrap arbitrary legacy protocols (RDP, RTSP, gRPC, SMTP, IPFS) as opaque payload and route their shards under the full anonymity stack. Apps don't get rewritten; they inherit the mesh's properties by being tunneled. No application adaptation required.

**Why novel:** Most privacy transports need app support. Bootstrapping "any TCP/UDP app gets PQ-sharded, unlinkable carriage" with no app changes is what makes the mesh a *platform* rather than a product.

**First experiment (4d):** Tunnel three semantically different unmodified apps over the same shard fabric and prove each one's bytes never appear in a single-peer view.

**Kill if:** wrapping adds per-flow state that can't survive churn, or head-of-line blocking from reordering breaks interactive apps.

**Prior art / novelty tier:** **C** — "run arbitrary protocols over an anonymity network" is the standard VPN-over-Tor / onion-transport pattern; the new element is PQ-sharding the wrapped flow, which is a deployment choice.

### 38. Shape-Shifting Wire — the protocol dialect is negotiated, not fixed

**Idea:** Replace §9's *static* choice (quic|doh) with a *negotiated* outer dialect: a handshake picks the outer appearance from a live-probed menu (what does the local network *already* look like?), and the dialect rotates over time so no single outer signature persists. The mesh morphs to the census it did not build.

**Why novel:** Pluggable transports are configured and frozen (obfs4 is always obfs4). Negotiating + rotating the dialect per link, based on probed local ground truth, defeats "block any single signature" for good.

**First experiment (4d):** Run with two different background environments; prove the chosen dialect tracks the environment and that a signature-matcher trained on environment A gets ≈chance on B.

**Kill if:** rotation causes observably-synchronized switches on both ends (a metadata leak) or breaks a middlebox's baseline.

**Prior art / novelty tier:** **B** — pluggable transports (obfs4) and traffic-morphing/parroting work (Tamaraw, Marionette, TrafficSliver) exist; the twist here is making the dialect *negotiated and ground-truth-driven* rather than configured.

### 39. Replay-Resistant Chronology — causality without a server

**Idea:** Replace any single time authority with a mesh-native *causal* order: each node keeps a monotone causal counter advanced by observing others; ordering is by the causal DAG, not wall clock. §4's self-destructing epochs then expire against *causal* time, not local time, so a replay that arrives "late" in real time but early in causal time still gets rejected.

**Why novel:** Vector clocks exist, but nobody couples them to *key expiry* in a sharded network. Making an epoch die on causal supersession — not a timer — is unfalsifiable by clock manipulation, the mesh's own hostile environment.

**First experiment (3d):** Cross-partition replays must be rejected on causal grounds even when local clocks are skewed arbitrarily in the attacker's favor.

**Kill if:** causal metadata grows unbounded across a long-running mesh (needs aggressive pruning that preserves the guarantee).

**Prior art / novelty tier:** **B** — vector clocks / Lamport timestamps (1978) are ancient; the new element is coupling causal order to *key-epoch expiry* in a sharded setting.

### 40. Identity-Agnostic Channels — the route has no *who*

**Idea:** Separate *who you are* from *where a flow lives* completely: a flow is identified by a content/capability token (§17 voucher) and the mesh never needs an identity binding to forward it. §3 burnables become optional, not required. The result is a data plane with no identity surface for an adversary to compromise, seize, or subpoena.

**Why novel:** Every VPN is identity-anchored by design. A mesh where a route carries *no identity* at all inverts the trust model — the thing you'd seize simply doesn't exist on the wire.

**First experiment (4d):** Run a full session with identity material absent from every relay's view; prove forwarding still works and the session drops with no identity leak if a relay is seized.

**Kill if:** abuse/resource accounting becomes impossible without per-flow identity (needs a privacy-preserving reputation that survives the loss).

**Prior art / novelty tier:** **B** — onion routing is already largely identity-free on the wire, and capability-based flows are known; the twist is making identity *optional* (§3 burnables not required) end-to-end.

---

## IX. Groups, Identity & Social (5) — networks of *people*, not nodes

### 41. Group-as-Shards — a secret only a group can reconstruct

**Idea:** Model a group as an erasure-coded identity: any `k of n` members can act as the group, and no single member (or seized device) alone can. Group key derivation, group messaging, and group authorization all reuse the *same* any-2-of-3 construction the transport already trusts — one primitive, whole social layer.

**Why novel:** Multisig/group crypto today is a bolted-on app feature (FROST, MLS). Making "the group" literally *the same* Reed-Solomon object as a packet shard is a conceptual collapse nobody ships, and it gives threshold group secrecy for free under the mesh's existing assumptions.

**First experiment (4d):** A 5-member group where any 3 reconstruct the group capability and any 2 cannot, sharing all code with `l4_rs` and `l3_shamir`.

**Kill if:** membership churn forces a full re-issue that costs more than one link-time round-trip.

**Prior art / novelty tier:** **B** — threshold group crypto is standard (FROST / [RFC 9591](https://datatracker.ietf.org/doc/html/rfc9591), Shamir + Feldman + Pedersen DKG). The twist is only *reusing the packet's own RS object* as the group primitive; the security is the same as existing threshold schemes.

### 42. Collective Defense from Aggregate Observables

**Idea:** Each node publishes a *privacy-preserving aggregate* of what it's seeing (peers dropping, times of loss, error rates) — not content, not topology — and the mesh learns *which regions/time windows are under active attack*, rerouting proactively before any single node fails. Built on the `PoissonReputationMatrix` idea extended across the network as a gossip aggregate.

**Why novel (revised):** The differentiator is *architectural*, not cryptographic: no collector. Peers each contribute a no-payload observable and the aggregate is the defense, so there is no honeypot/telescreen to seize.

**First experiment (3d):** Simulate a targeted drop region; prove the mesh reroutes within T before any individual link notices, and that the aggregate leaks no *payload* and no *identifying* report (per-node reports must be threshold-bucketed).

**Kill if:** the aggregate is itself a fingerprint (a node can be identified by its report) or the false-positive rate raises reroute cost >2×.

**Prior art / novelty tier.** **C** — collaborative/federated intrusion detection is a huge field (FL + DP + HE + SMPC; e.g. [privacy-preserving CTI with FL+DP+HE](https://ieeexplore.ieee.org/abstract/document/10968450), PIR-based threat-intel querying). **Correction:** "contains no metadata" is **too strong** — a per-node report is itself a fingerprint unless it is **k-anonymized / differentially-private bucketed**. Claim "no payload, identifying detail suppressed below a threshold," not "no metadata."

### 43. Sharded Model Gossip — your network, locally intelligent

**Idea:** Distribute a small learned model across the mesh as shards (read §21 as weights, §3 as identity). The mesh *learns* local behavior — jitter distributions, timing — from aggregate metadata, and improves its *own* cover (§6) and routing without any central trainer. Behavioral adaptation, decentralized.

**Why novel:** Federated learning still assumes a coordinator and labeled data. Sharding the *model* itself across peers, and letting the mesh improve only on *metadata it already sees*, is a federated system with neither.

**First experiment (4d):** Prove a sharded model converges on a synthetic metadata task with 3 disjoint holders and that no holder can reconstruct the full model from its shard.

**Kill if:** the model's improvement is indistinguishable from noise at realistic mesh sizes, or it leaks peer identity.

**Prior art / novelty tier:** **C** — gossip learning and decentralized federated learning already remove the coordinator; sharding the model weights is the mesh's re-use of §21.

### 44. Sovereign Cloud — your personal devices *are* the mesh

**Idea:** Define a mesh-native "cloud" as a set of devices you already own; the mesh is the fabric, and *there is no provider*. Sync, file, compute, and inference all live across your own endpoints, sharded and *jurisdiction-tagged* so data can be constrained to, say, EU endpoints. No terms of service, no vendor, no account.

**Why novel:** "Personal cloud" products are still a service someone operates. A protocol where the cloud *is* the mesh holding your own shards, with compliance expressed as topology constraints, is a category no incumbent can enter without becoming a protocol.

**First experiment (4d):** Run 4 owned endpoints with a jurisdiction constraint and prove an object tagged `EU` never resolves to a non-EU holder under simulated churn.

**Kill if:** the invariant can't be enforced without a trusted directory or leaks the tag to non-EU holders.

**Prior art / novelty tier:** **C** — Syncthing, Tailscale, and Nebula already mesh your own devices with no provider. The only new element is expressing compliance as *topology* (jurisdiction tags).

### 45. Anonymous Capability Economy — identity-free privileges

**Idea:** Convert §17 vouchers + §41 groups into an *anonymous* capability layer: prove you may do X without revealing who you are, using the group-shard construction as the authorization root and the same unforgeability the mesh trusts. The economy has *rights*, not accounts.

**Why novel:** Capability systems (macaroons) bind to identity or keys. A capability whose root is a threshold group and whose use is identity-free gives you a privileges economy that survives device seizure — again, because the thing to seize isn't on any one device.

**First experiment (4d):** Mint a capability from a 3-of-5 group, exercise it from an identity-less flow, and prove revocation works via `RevocationList` without ever linking uses to a user.

**Kill if:** revocation can't be made both anonymous and non-replayable, or the verifying cost per use is >0.5ms.

**Prior art / novelty tier:** **B** — anonymous credentials (Chaum, 1985) and macaroons do identity-free authorization; the twist is rooting the capability in a *threshold group* so no single device holds it.

---

## X. Reality Checks & Adversarial Falsification (5) — break it in a lab, not on Tor

### 46. Mesh Red-Team Harness — 100 nodes, 1 machine

**Idea:** A deterministic, in-process adversary that spins up ~100 virtual nodes, injects a chosen mix of packet-loss, reordering, collusion, capture, and CGNAT, and *always* runs before a Part-II spike graduates. It's the gate, not an afterthought: no graduation without a red-team run in the harness.

**Why novel:** Most open-source crypto ships because it *passes* a happy-path test. Making the *adversary run* the definition of done — default-on, deterministic, reproducible — would be a genuine research-infrastructure advantage over every competitor's CI.

**First experiment (4d):** Reproduce a known §1–§20 kill *as a test* and show it fails a bad implementation and passes a good one, in <60s wall.

**Kill if:** the harness needs real network hardware to be meaningful (i.e. it can't be deterministic in-process).

**Prior art / novelty tier:** **C** — deterministic network simulators with adversary models already exist (ns-3, Mininet, Shadow). The novelty is the *CI policy* ("the adversary run is the definition of done"), not the tool.

### 47. Formal Core Model — machine-checked invariants

**Idea:** Extract only the *compositional core* — the shard/key epoch ladder, the disjoint route constraint, the group/threshold object — into a machine-checkable model checked on every PR. Not the whole system; the *wiring the whole security story rests on*.

**Why novel:** SOTA.md's P2 gate floats a Tamarin/ProVerif check *once*. Making the compositional invariants (not just the crypto primitives) a permanent CI gate is rare, and it *proves* the "composition, not primitives" thesis rather than asserting it.

**First experiment (5d):** Model the 3-shard × 3-epoch requirement and prove (or refute) "single-epoch capture opens zero" mechanically.

**Kill if:** the core can't be extracted cleanly and the proof degrades into re-testing the crypto library (which we already trust).

**Prior art / novelty tier:** **C** — Tamarin, ProVerif, CryptoVerif, F*, and EasyCrypt all do machine-checked protocol proofs, and SOTA.md's P2 gate already names Tamarin/ProVerif. New: making the *compositional* invariants (not just primitives) a standing CI gate.

### 48. Deploy-Not-Design — reproducible reference network

**Idea:** A one-command, containerized reference mesh (3–10 nodes) that a stranger can stand up from a bare checkout, with the red-team harness (§46) and the formal core (§47) wired in. A reviewer's *first 10 minutes* shows the mesh working and under attack, not a design doc.

**Why novel:** Most privacy networks are un-runnable without infrastructure. Making the *reference deployment itself* a reproducible artifact — same inputs in, same behavior out — is both a research and an adoption unlock.

**First experiment (4d):** `docker compose up` → a green smoke test + a failing red-team scenario, in <5 min, on a fresh checkout.

**Kill if:** the reference network needs privileged host networking that breaks on laptops, or nondeterminism makes reproduction fail.

**Prior art / novelty tier:** **C** — a `docker compose` demo is standard practice, not an invention. Keep it in the plan as *engineering hygiene*; do not cite it as novelty.

### 49. Protocol Fuzzing for *new* semantics

**Idea:** Extend `fuzz/` from byte-crash-finding to *semantic* fuzzing of the new Part-II surfaces: dead-drop addressing (§26), causal chronology (§39), group reconstruction (§41). A property-based fuzzer that asserts invariants (no loss, no linkability, no false revocation) under random *sequence* attacks, not random bytes.

**Why novel:** Semantic sequences are where new protocols actually break — and almost nobody fuzzes *permission* and *ordering* properties. For a system whose entire pitch is compositional invariants, this is the missing verification leg.

**First experiment (3d):** Fuzz §26 with replayed/duplicated/delayed deposits and prove no invariant violation in 10^6 sequences.

**Kill if:** the space is so large the fuzzer can't find meaningful cases in CI time (then narrow to one surface).

**Prior art / novelty tier:** **C** — property-based/stateful fuzzing (QuickCheck, TLS fuzzing, AFL) is mature; the twist is targeting *permission and ordering* invariants rather than byte crashes.

### 50. Anti-Fragile Tarpit — an attack that makes the attacker pay

**Idea:** Turn every attack into a cost for the attacker: failed/corrupted handshakes consume attacker *compute-and-time* bounded by a proof-of-work the *honest* side also requires (so it's free to honest peers), and §15 honey-shards make the attacker's `Poly1305` work reveal its own pairwise signatures. The mesh gets *stronger* by being attacked — each failed probe becomes a signed, sharded signal to §42's aggregate.

**Why novel:** This is the mesh-native inverse of "attacker uses holes in this network": here being probed *hardens* the network and *identifies* the prober, with the cost asymmetry proven in a lab. It's the flagship demo for §46–§49 — a network that defeats you by letting you in.

**First experiment (5d):** In the red-team harness, run a replay+Sybil+reorder mix: prove honest throughput is unchanged, the attacker's cost grows super-linearly with attempts, and the attacker is localized without false positives.

**Kill if:** the honest path pays the tarpit cost (a DoS-on-yourself), or attack localizations can be spoofed by a third party against an innocent peer.

**Prior art / novelty tier:** **C** — tarpits, honeypots, and PoW anti-DoS are classic (and "antifragility" is Taleb's). The new element is the *direction*: reusing §15 honey-shards so being probed *identifies and prices* the prober.

---

## XI. Bonus Shelf — raw, unproven, maybe genius, maybe delusion

> Kept only because someone will want the receipts. Even rougher than Part II proper; these may need >2 weeks or may be provably impossible (which is itself the finding).

### 51. Stego-in-Physics — carry a shard in heat, sound, or light

Route one shard over a covert *physical* channel (fan-noise, audio, IR), the other two over the network. Needs a receiver physically present. Possibly insane; possibly the most censorship-proof channel in existence.

**Prior art / novelty tier:** **C** — covert/subliminal channels date to Lampson (1973); wrapping one *shard* in one is the mesh reuse.

### 52. Mesh-as-Archive — the network remembers public standards

Mirror an open standard/canon as sharded, unlinkable public infrastructure that a jurisdiction cannot delete. Ties to §22 + §26; legal and political reality, not technical, may kill it.

**Prior art / novelty tier:** **C** — Freenet, IPFS, and ZeroNet already do censorship-resistant publishing; the mesh adds erasure + unlinkability.

### 53. Entropy-Beacon Commons — a public randomness the adversary can't steer

Cooperate to emit shard-verified public randomness (a decentralized beacon), useful for the mesh's own security *and* as a diffuse, censorship-resistant public good.

**Prior art / novelty tier:** **C** — the [NIST Randomness Beacon](https://csrc.nist.gov/pubs/ir/8213/ipd) and [drand](https://docs.drand.love/about/) already provide verifiable distributed public randomness.

### 54. Causal Capsule — bits that outlive the mesh that made them

Data encoded so it stays readable even if *every current node and key-derivation service* is gone — the packet carries its own minimal decoder. The theory is likely impossible for real plaintext; the experiment would define the exact boundaries.

**Prior art / novelty tier:** **D** — as stated this is likely **impossible**: confidentiality and "readable without any key-derivation service" are mutually exclusive for real plaintext. Keep it only as a boundary-defining experiment (e.g. *public* data with a self-contained decoder); do not build on it.

---

*Last updated: v0.4.1 + SOTA cut. Part I: 20 inventions, each maps to code you already have — nothing needs a new primitive, only wiring. Part II (§V–§XI): 34 radical spikes — new subsystems, same "compose, don't invent primitives" law, same 14-day kill gate. Honesty pass applied: every Part-II item now carries a prior-art / novelty tier (A/B/C/D), and §24, §30, §36, §42, §54 carry corrections. Pick 3 from either part; the graduation path is the same (`docs/` spec → `SOTA.md Phase N+1`).*
