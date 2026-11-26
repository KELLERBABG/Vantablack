# Epistemic Hardening Plan (`v2.1.8+`)

Actionable engineering instructions to close the remaining epistemic, cryptographic, formal-verification, and physical-realism gaps in Vantablack.

---

## 1. `BTCr v2` — Private Root Key, Quantized Bucket Keys & Receipt Nullifiers

**Targets:** `src/ghost/v2/btcr.rs`, `src/ghost/v2/api.rs`

1. **Remove public-fingerprint key derivation (`src/ghost/v2/btcr.rs:175-187`):**
   - `Issuer::for_node(fingerprint)` currently hashes `ISSUER_DOMAIN || fingerprint` to derive the VOPRF secret scalar `secret`. Because `fingerprint` is public, anyone can forge tickets offline.
   - Replace with `Issuer::from_seed` derived from the node's **private** `identity.key` secret (via domain-separated HKDF `"VB-BTCR-V2"`), and update `src/ghost/v2/api.rs` callers (`api.rs:219`, `api.rs:243`) so only the local node can mint/sign.
2. **Bind quantized `(day, tier)` metadata into bucket keys:**
   - Quantize `expires_at` to UTC day buckets (`day = unix_secs / 86400 + 1`) and `work_bytes` to fixed tiers (`1 MiB`, `16 MiB`, `256 MiB`) so anonymity sets share identical metadata.
   - Derive per-bucket scalar `k_{day,tier} = H_scalar(k_root || day || tier)` and publish `K_{day,tier} = k_{day,tier} * G`.
   - Evaluate `E = k_{day,tier} * B` with Chaum-Pedersen DLEQ against `K_{day,tier}`, and verify `N == k_{day,tier} * M` using the bucket key for the ticket's claimed `(day, tier)`.
3. **Prevent receipt replay:**
   - Compute a deterministic receipt nullifier `SHA256("VB-BTCR-RCPT" || worker || epoch || beneficiary)` on redemption, store it in a spent-receipt set, and reject duplicates.

**Verify:** `cargo test --lib btcr` and `cargo clippy --all-targets -- -D warnings`

---

## 2. Non-Vacuous ProVerif Models

**Targets:** `formal/ghost_session.pv`, `formal/session_ratchet.pv`, `formal/ghost_circuit_unlinkability.pv`, `formal/README.md`, `.github/workflows/ci.yml`

1. **Fix `formal/ghost_session.pv`:**
   - Add the Diffie-Hellman commutativity equation (`equation forall x: bitstring, y: bitstring; dh(x, dh(y, g)) = dh(y, dh(x, g)).`) so initiator and responder derive the same shared key.
   - Fix the PQ encapsulation/decapsulation mismatch so the initiator's ciphertext encapsulated to `pq_pub_b` is actually sent on channel `c` and decapsulated by the responder with `skPQb`.
   - Add a positive reachability witness (`query event(agreement(...))` returning `false`) to prove the protocol actually executes to completion rather than passing vacuously.
2. **Fix `formal/session_ratchet.pv`:**
   - Split initiator and responder into separate communicating processes over channel `c`, transmit `encaps_pq(...)` over `c`, add DH commutativity, and include reachability witnesses for epoch-2 completion.
3. **Upgrade `formal/ghost_circuit_unlinkability.pv`:**
   - Use `origin_id` inside the actual process rather than leaving it unused, leak `k_r2` only in an explicit middle-relay compromise scenario (separate from entry-relay `dest_exit` secrecy), and add observational equivalence (`diff[...]`) or reachability checks.

**Verify:** `proverif formal/ghost_session.pv && proverif formal/session_ratchet.pv && proverif formal/ghost_circuit_unlinkability.pv`

---

## 3. Honest `HPEB` & $(c, r, f)$ Vandermonde Ramp Bonding

**Targets:** `src/ghost/v2/hpeb.rs`, `src/ghost/layers/l4_rs.rs`, `src/ghost/layers/l3_shamir.rs`

1. **Enforce the Multipath Secrecy-Availability Bound ($m \ge c + f + 1$):**
   - On $m = 2$ paths (e.g., Wi-Fi + 5G), round-robin 3-shard RS(2,1) + keyless AONT places 2 shards on Path 0, breaking both 1-carrier secrecy and Path-0 outage recovery.
   - Require an explicit 2-path regime choice:
     - **Confidentiality mode ($c=1, r=1, f=0$):** 2-of-2 XOR split across the 2 paths (zero single-carrier leakage, 0% overhead).
     - **Availability mode ($c=0, r=1, f=1$):** 1-of-2 duplication (survives either path dropping; secrecy relies on L2 AEAD).
2. **Implement $(c, r, f)$ Vandermonde Ramp Bonding over $\mathbb{F}_{2^8}$ for $m \ge 3$:**
   - Sample $c$ random mask symbols $(u_0, \dots, u_{c-1}) \in \mathbb{F}_{2^8}^c$, form degree-$(c+r-1)$ polynomial $P(x) = \sum_{j=0}^{r-1} m_j x^j + \sum_{j=0}^{c-1} u_j x^{r+j}$, and evaluate at $m$ distinct nonzero points $\alpha_1, \dots, \alpha_m \in \mathbb{F}_{2^8}^*$.
   - Guarantees unconditional $c$-carrier secrecy, $f$-outage recovery, and optimal rate $R = 1 - (c+f)/m$.

**Verify:** `cargo test --lib hpeb` and `cargo test --lib l4_rs`

---

## 4. Live `X-Ray` Witnesses, `Horizon-Chronos`, `Shaped-RACS` & Honest NVIS

**Targets:** `src/ghost/v2/api.rs`, `src/ghost/v2/xray.rs`, `src/ghost/v2/regime.rs`, `src/ghost/v2/chronos.rs`, `src/ghost/v2/racs.rs`, `abos/WHITEPAPER.md`

1. **Live Wire-Witnesses & $N_{\text{eff}}$ (`api.rs`, `xray.rs`, `regime.rs`):**
   - Stop populating `LedgerInput` from configured regime booleans in `api.rs`. Feed real measured cover-TX counters, verified `CAP_RELAY` counts, and live 3-hop signed nonce echo witnesses; drop unmeasured invariants to `Unknown`.
   - Replace raw `relays >= 200` with Rényi-2 collision-entropy effective population $N_{\text{eff}} = \left(\sum_i w_i^2\right)^{-1}$ grouped by administrative/routing domain (ASN/subnet cluster) to defeat single-VPS Sybil inflation.
2. **Fix `ChronosSplice` & Add Stationary Horizon Pacing (`chronos.rs:99-118`):**
   - Fix the factor-of-2 error (`delay = inner_rtt.saturating_sub(outer_rtt)`, `paced = outer_rtt + delay`).
   - Lock Guard outer transport pacing to a stationary latency horizon $H \in \{80\text{ ms}, 160\text{ ms}, 280\text{ ms}\}$ per session and mark `clock_consistent` failed if an inner flow exceeds $H$.
3. **Replace Yielding Cover with Input-Independent Slot Shaping (`racs.rs`):**
   - Remove the `25 ms` `note_real_traffic()` cover suppression window (which creates a deterministic burst-end edge).
   - Emit 576 B frames only on an input-independent ON/OFF renewal slot schedule (real queued frame if present, otherwise dummy frame).
4. **Honest Narrowband NVIS Physical Profile (`abos/WHITEPAPER.md`):**
   - Replace the physically impossible `1 Mcps` / `< 1 ms` 2–10 MHz NVIS burst spec with a realistic $3\text{–}24\text{ kHz}$ narrowband slow-symbol `GhostCell-Nano` profile ($\approx 30\text{–}60\text{ s}$ per covert 180-byte cell at $30\text{ dB}$ processing gain).
