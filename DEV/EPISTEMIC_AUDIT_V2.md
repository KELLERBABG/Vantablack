# Epistemic Audit (`v2.1.8`) — What's Not

> Socratic cross-examination (*elenchus*) of Vantablack `v2.1.8`. Every finding below is verified directly against the current source tree, ProVerif models, and physical/information-theoretic bounds.

---

## 1. The Truth Ledger Audits *Policy*, Not *Reality*

**Files:** `src/ghost/v2/xray.rs:1-16`, `src/ghost/v2/api.rs:45-62`

`xray.rs` states: *"anything the node cannot measure is `Unknown`, never `Verified`."*
However, `api.rs::ledger_input` populates `LedgerInput` by echoing configuration rather than measuring live wire state:
- `circuit_hops: connected.then(|| state.regime.hops().hops())` — whenever `peers >= 1`, `api.rs` reports the **configured regime requirement** as the observed hop count. With 1 peer in `vantablack` mode (where a 3-hop circuit cannot exist), `circuit_length` reports `Verified: "3 hops, 3 required by vantablack"`.
- `cover_traffic: state.regime.cover_traffic() && connected` — echoes the policy boolean rather than actual measured cover-frame transmissions.
- `public_relays: Some(state.peers)` — counts every connected peer (including a private LAN device or non-relaying client) as a public relay.
- `pq_hybrid: connected.then_some(true)` — ignores that legacy v1/ML-KEM-512 frames remain accepted on receive (`docs/SPECIFICATIONS.md:73`).

**Result:** The Truth Ledger currently mirrors configuration back in the typography of measurement rather than acting as a live epistemic oracle.

---

## 2. The HPEB Two-Path Pigeonhole Collapse

**Files:** `src/ghost/v2/hpeb.rs:8-12, 144-155`, `src/ghost/layers/l4_rs.rs:120-140`

`hpeb.rs` promises two properties for AONT + RS(2,1) across `live.len() >= 2` interfaces:
1. One interface vanishing costs nothing (availability).
2. No single carrier holds a whole message (carrier secrecy).

In `HpebScheduler::bond`, shards `0, 1, 2` are assigned round-robin via `live[i % live.len()]`. On $m = 2$ paths (e.g., Wi-Fi + 5G):
- **Path 0** receives Shard 0 **and** Shard 2 (2 of 3 shards).
- **Path 1** receives Shard 1 (1 of 3 shards).

Because `l4_rs::aont_inverse` is keyless ($K_e = \text{tail} \oplus \text{SHA256}(C)$), **both promises collapse simultaneously**:
- Path 0 holds 2 of 3 shards $\implies$ reconstructs the AONT block $\implies$ decrypts 100% of the payload with zero keys.
- If Path 0 drops, Path 1 holds only 1 shard $\implies$ total loss.

### Theorem 1 (Multipath Secrecy–Availability Bound)
*No threshold coding scheme (linear, Reed-Solomon, Shamir, or AONT) over $m$ physical paths can simultaneously tolerate $c$ colluding wiretapping carriers (zero information leaked) and $f$ failed paths (full reconstruction) unless:*
$$m \ge c + f + 1.$$

*Proof.* Suppose $m \le c + f$. Partition the $m$ paths into a failed set $F$ of size $f$ and a surviving set $S$ of size $m - f \le c$. By $f$-outage availability, the shards on $S$ must uniquely determine any message $M \in \mathcal{M}$ ($|\mathcal{M}| \ge 2$). By $c$-carrier secrecy, because $|S| \le c$, the shards on $S$ must leak zero information about $M$. The same random variable $Y_S$ cannot satisfy both $H(M \mid Y_S) = 0$ and $H(M \mid Y_S) = H(M) > 0$. Contradiction. $\blacksquare$

For $c = 1, f = 1$, $m \ge \mathbf{3}$ disjoint physical paths is an information-theoretic law, not a bug in round-robin indexing. Over 2 radios, a node must explicitly choose between availability and carrier secrecy.

---

## 3. Vacuous ProVerif Proofs

**Files:** `formal/ghost_session.pv`, `formal/ghost_circuit_unlinkability.pv`, `formal/session_ratchet.pv`, `formal/README.md:44-51`

1. **`formal/ghost_session.pv:41-46, 102, 129`:**
   - `dh` has no Diffie–Hellman commutativity equation (`dh(x, dh(y, g)) = dh(y, dh(x, g))`).
   - Line 102 has the initiator run `decaps_pq(skPQa, encaps_pq(pq_pub_b, pq_eph_a))` (decapsulating with `skPQa` a ciphertext encapsulated to `pq_pub_b`), while line 129 has the responder run `decaps_pq(skPQb, encaps_pq(pq_pub_a, pq_eph_b))` with an unrelated private `pq_eph_b`.
   - Thus `k_a` can never equal `k_b`, `sdec(msg_a, k_b)` on line 132 always fails, and `event recv_counter` / `event agreement` are **100% unreachable**. In logic, $\text{false} \implies P$ is unconditionally true — explaining why mutating or deleting the transcript check still proved `true`. (`session_key` on line 60 is also unused.)
2. **`formal/ghost_circuit_unlinkability.pv:42, 50, 58`:**
   - `free origin_id: bitstring [private]` is queried with `query attacker(origin_id)`, and `origin_id` never appears anywhere in `process`.
   - Line 11 states the attacker holds `k_r2`, but line 58 only leaks `k_r1`.
   - True unlinkability in ProVerif requires observational equivalence (`diff[...]`), not a secrecy query on an unused name.
3. **`formal/session_ratchet.pv:58-96`:**
   - A single process generates both `ra2` and `rb2`, never puts `encaps_pq(...)` on channel `c`, lacks DH commutativity, and verifies its own signature against local variables — unable to test an active MITM during break-in recovery.

---

## 4. Three Live Cryptographic Breaks in `BTCr`

**Files:** `src/ghost/v2/btcr.rs:175-187, 218-223, 306-312, 417-436`, `src/ghost/v2/api.rs:189-244`

1. **Public "secret" key (`btcr.rs:175-187`, `api.rs:219, 243`):** `Issuer::for_node(fingerprint)` derives the VOPRF secret scalar $k = \text{SHA512}(\text{"VB-BTCR-ISSUER-V1"} \| \text{fingerprint}) \bmod \ell$. Because `fingerprint` is public, anyone can compute $k$ offline and forge infinite valid bearer tickets $(M, k \cdot M)$.
2. **Unauthenticated value & expiry (`btcr.rs:218-223, 306-312`):** `verify_ticket` checks only $k \cdot M \stackrel{?}{=} N$. Neither `expires_at` nor `work_bytes` is cryptographically bound into $k$, $M$, or $N$. Editing the last 16 bytes of a 1-byte ticket to `expires_at = u64::MAX`, `work_bytes = u64::MAX` passes verification.
3. **Unbounded receipt replay (`api.rs:189-234`, `btcr.rs:417-436`):** Redeemed `Receipt`s are never recorded as spent, so one beneficiary-signed receipt can be replayed with fresh blinded points $B_1, B_2, \dots$ to mint unlimited distinct nullifiers.

---

## 5. Timing & Cover Paradoxes (`ChronosSplice` & `RACS`)

- **`ChronosSplice` (`src/ghost/v2/chronos.rs:99-118`):**
  1. *Factor-of-2 error:* Line 105 computes `delay = (inner_rtt - outer_rtt) / 2`, while line 109 computes `paced = outer_rtt + delay * 2`. Delaying the Guard's ACK on a client-to-guard flight traverses the Guard's ACK buffer **once**, so real $\text{TRTT}_{\text{paced}} = \text{TRTT} + \text{delay}$, leaving 50% of the `ARTT - TRTT` gap unclosed while reporting `residual == 0`.
  2. *Multiplexing instability:* Tracking per-destination inner RTTs causes a single Guard IP's outer RTT to swing across destinations (e.g., 15 ms vs. 240 ms), creating a relay fingerprint of its own.
- **`RACS` (`src/ghost/v2/racs.rs:17-20, 32, 137-142`):**
  `note_real_traffic()` suppresses cover for `YIELD_WINDOW_MS = 25 ms` while real traffic transmits immediately. Immediately after the final packet of any real burst at $t_0$, the wire hazard drops identically to **zero** on $(t_0, t_0 + 25\text{ ms})$ and jumps discontinuously back to $\lambda_C > 0$ at $t_0 + 25\text{ ms}$ — turning yielding cover into a deterministic burst-endpoint detector.

---

## 6. The Physical Wall (NVIS Bandwidth & Dormant Modules)

**Files:** `abos/WHITEPAPER.md:62-64`, `abos/abos-hal/src/sdr.rs:57, 112`, `src/ghost/layers/l10_qel.rs:80`, `src/ghost/net/shardsec.rs:316`, `src/ghost/layers/l3_shamir.rs:58`

- `abos` SDR drivers are zero-fill stubs and `SimulatedQel` uses constant seed `0x51EE` (contributing epoch agreement, not secrecy — already documented honestly in `DEV/ANCHORS_CODEBASE_INTEGRATION.md`).
- **Physics contradiction in `abos/WHITEPAPER.md:62-64`:** The spec claims **1 Mcps DSSS** (30 dB processing gain) and **$< 1\text{ ms}$ randomized bursts** on **2–10 MHz NVIS** skywave.
  - The F2 ionospheric layer has multipath delay spread $\tau_{\text{rms}} \approx 0.5\text{–}3\text{ ms}$ (coherence bandwidth $B_c \approx 70\text{–}400\text{ Hz}$), and a practical HF channel is $3\text{–}24\text{ kHz}$ wide — not $1\text{–}2\text{ MHz}$.
  - Achieving $G_p = 30\text{ dB} = 1000\times$ below-noise-floor processing gain inside $B = 24\text{ kHz}$ bounds the symbol rate to $R_s = B / G_p = 24\text{ symbols/s} \approx 48\text{ bps}$ (QPSK).
  - Sending one 180-byte `GhostCell-Nano` with rate-1/2 LDPC ($2880$ coded bits) stealthily below the noise floor takes **$\ge 60\text{ seconds}$**, never $< 1\text{ ms}$.
- Meanwhile, `SpatioTemporalErosionCodec`, `ThresholdGroupKey`, and the `research`-gated modules remain isolated in unit tests rather than coupled into the live daemon.
