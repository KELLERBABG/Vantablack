# Anchors integration — L10 QEL, ETSI 014, and the ABOS skybridge

**Where this fits:** the two "anchor" layers at the bottom of the 10-layer onion —
L10 (`src/ghost/layers/l10_qel.rs`, quantum entropy) and the ABOS skywave bridge
(`src/ghost/net/sdr_bridge.rs`, physical ionospheric fallback). Both are *additive*:
when they are missing or degraded the daemon keeps working; when they are present they
add a property the rest of the stack does not by itself provide.

This file is the honest description of what the two anchors actually are in v0.8.11,
where the vendored third-party code comes from, and what that means for an operator or
a reviewer. It exists so the prose in `src/ghost/layers/l10_qel.rs`, `docs/SPECIFICATIONS.md`
and `docs/DORMANT_MODULES.md` can point here rather than duplicate the same caveats.

---

## 1. L10 — the quantum entropy anchor

**File:** `src/ghost/layers/l10_qel.rs`.
**What it does:** each session epoch can be mixed with 32 bytes of key material that did
not come from the classical handshake, plus a label that names that material. The starter
obtains the key and sends the *label* (never the key) in the signed session-mix PDU; the
answerer derives the same key from the label.

**Two backends, selected at runtime by `GHOST_QEL_BACKEND`:**

| Backend | Env value | Source of the key |
|---|---|---|
| `SimulatedQel` | `sim` (default) | the vendored Python `Quantum Entanglement Link/` stack, driven as a subprocess: `python -m quantumnet ghost-net ...` to route, `python -m quantumnet qkd-derive ...` to derive |
| `Etsi014Client` | `etsi014` | a **real QKD appliance** over the ETSI GS QKD 014 REST key-delivery API (`enc_keys` / `dec_keys` by key ID) |

**The honest property of the simulated backend.** The simulated engine derives the key from
`(fidelity, seed)`, and `QEL_KDF_SEED` is a constant. With this engine, every fidelity above
the BB84 cutoff maps to the *same* 32 bytes for a given seed. The `a_route_key_and_the_key_
redeemed_from_its_label_are_identical` test pins that property, and the prose in `l10_qel.rs`
states it: in a `sim` build the mix contributes **epoch agreement**, not secrecy. Both peers
agree on the key because they agree on the label, not because the channel gave them something
neither chose. A real ETSI 014 appliance has no such degeneracy: there the label is a `key_ID`,
and each ID names one key.

**Why this matters for a claim.** If someone says "sessions are quantum-anchored", the honest
reading is: *when the ETSI backend is present and healthy, the session mixes in material from a
quantum channel; when only the simulated backend is present, the session mixes in structurally
deterministic material that still forces epoch agreement but does not add secrecy*. The anchor
is additive and degrades gracefully; it never silently promotes the simulator to the appliance's
security claim. `l10_qel.rs` is written so that a misconfigured `etsi014` becomes
`"misconfigured"`, not `"sim"` — falling back would change what the mixed entropy actually is
without telling the operator.

---

## 2. The vendored QEL tree is a snapshot, not upstream

**Where it lives:** `Quantum Entanglement Link/` (next to the Vantablack checkout root).
**Where it came from:** a snapshot of `https://github.com/KELLERBABG/QEL`.

**What v0.8.11 actually uses from it:** the two commands above, the `quantumnet` package
entrypoint the probe imports, and `pyproject.toml`/`poetry.lock`. That is the entire interface
the daemon depends on.

**What the vendored tree is not:** it is *not* a current tip of the upstream repo. Measured
against a current upstream checkout, the upstream tree is larger (more protocol/encoding modules,
more of `src/quantumnet/`, a larger tests tree, documentation files). The vendored snapshot keeps
the pieces the daemon routes through and omits the rest. This is intentional — the vendored tree
is a slice, not a mirror.

**How the vendored package is loaded:** `Quantum Entanglement Link/` uses a PEP 517 `src/` layout
(`Quantum Entanglement Link/src/quantumnet`). `SimulatedQel` automatically prepends
`Quantum Entanglement Link/src` to `PYTHONPATH` when spawning Python for `run_probe` and
`run_json`, so `import quantumnet` and `python -m quantumnet` succeed out-of-the-box as long as a
Python interpreter with `numpy` is installed (without requiring a manual `pip install -e "Quantum
Entanglement Link"`). If Python or `numpy` is absent, the probe cleanly reports `Unavailable` or
`Degraded` and sessions continue without quantum entropy.

**What "upgrade the vendored QEL" would mean:** it is updating vendored third-party code, against
a *current* upstream checkout, not re-diffing the old snapshot. The parts to validate are narrow:
does `import quantumnet` succeed from the vendored tree; do the two `--json-output` commands still
emit the `QuantumRouteResult` contract `l10_qel.rs` parses; does the `qkd-sim/1/...` label
contract still round-trip the way `parse_label` and the round-trip test expect; and did upstream
change the simulated engine's `(fidelity, seed)` → key mapping (if so, the deterministic-key
statement in `l10_qel.rs` and §1 above needs rewriting, and the round-trip test may need a new
assertion).

---

## 3. The ETSI 014 appliance backend

**File:** `src/ghost/layers/l10_qel_etsi.rs`.
**What it does:** talks to a real QKD key-management entity over the ETSI GS QKD 014 V1.1.1
REST key-delivery API — `GET …/enc_keys` to obtain a key for a peer, `POST …/dec_keys` to redeem
one that arrived as a label. The delivered material is HKDF'd to the 32 bytes a session epoch needs.

**Configuration:** `GHOST_QKD_KME_URL`, `GHOST_QKD_SAE_ID`, `GHOST_QKD_PEER_SAE_ID` (or the
per-peer SAE map), `GHOST_QKD_KEY_BITS`, `GHOST_QKD_TIMEOUT_MS`, `GHOST_QKD_INSECURE`,
`GHOST_QKD_CA_PEM`, and the client-identity certificate paths. The ETSI backend is the only path
that makes the "quantum-anchored" claim in §1 about *secrecy* rather than epoch agreement.

**Honest posture:** a reachable appliance that cannot serve the requested key size is reported as
**degraded** (operator action: set `GHOST_QKD_KEY_BITS` to a size it accepts) rather than silenced.
A transport failure (appliance down, TLS unusable) is **unavailable** (nothing the session can do).
A refusal (wrong SAE, missing client cert, empty pool) is **degraded** with the refusal reason. The
certificate-verification mode is surfaced in the control-plane `backend_report()` rather than merely
logged, because an operator should be able to see from the control plane that this node is not
verifying the appliance's certificate.

---

## 4. ABOS — the skywave / ionospheric fallback layer

**File:** `src/ghost/net/sdr_bridge.rs` (and the `abos/` workspace).
**What it does:** when compiled with `--features sdr`, the bridge orchestrates the ABOS signal-
processing pipeline (NVIS 2–10 MHz skywave, meteor scatter, DSSS stealth) as an autonomous
out-of-band physical fallback carrier when terrestrial WAN links fail. Without the feature — or
without attached SDR hardware — the bridge runs in *synthetic mode*: the same decision logic,
telemetry and ingress plumbing, minus the physical DSP stages. The bridge is `Send + Sync` and can
be installed process-wide; `ABOSSystem` itself is kept off it because it holds non-`Send` state.

**Vendored origin:** the `abos/` workspace is a copy of `https://github.com/KELLERBABG/ABOS`.

**Measured state of the vendored tree vs upstream:** the vendored workspace has the 13 crates the
Vantablack build depends on, but is missing some root-level files the upstream repo carries (e.g. a
`LICENSE` file, `rust-toolchain.toml`, and the HTML index/docs the upstream repo surfaces). The
Vantablack dependency is on the workspace crates, not on the missing root files, so the missing root
files do not by themselves break a Vantablack `sdr` build.

**What the bridge does not claim:** it does not claim over-the-air verification. The ABOS README
states this honestly: the SDR hardware drivers are simulation stubs (zero-fill reads), and live
radio behaviour was not verified because no radio hardware was available. The virtual carrier is a
loopback UDP socket by default (`127.0.0.1:0` unless `GHOST_SKYWAVE_UDP` overrides it), and frames
received over it are not trusted — they enter the same authenticated receive path as any other
datagram, and the AEAD rejects anything not sealed to us.

---

## 5. How to read the caveats together

- **L10 with `sim` only:** the session mixes in deterministic material; the anchor gives epoch
  agreement, not secrecy. This is stated in `l10_qel.rs` and here; it is not a bug to fix, it is a
  property to know.
- **L10 with `etsi014` only:** the session mixes in appliance-delivered material; the anchor can
  then reasonably be described as contributing entropy from a quantum channel, *if* the appliance is
  real, reachable, and correctly configured. The control plane exposes whether certificate verification
  is on.
- **L10 with nothing importable:** degraded, not fatal. The daemon continues without quantum entropy.
- **ABOS without `--features sdr`:** the skywave path is absent; the daemon continues on terrestrial
  links.
- **ABOS with `--features sdr` but no hardware:** synthetic mode; the bridge logic and ingress are
  exercised, the physical DSP is not. No over-the-air claim is made.

---

## 6. Where to look next

- For the QEL JSON contract and label format, read `src/ghost/layers/l10_qel.rs` and its tests.
- For the ETSI backend and its environment variables, read `src/ghost/layers/l10_qel_etsi.rs`.
- For the skybridge's threading model, virtual carrier, and telemetry, read `src/ghost/net/sdr_bridge.rs`.
- For the honest state of the two ProVerif models (which do *not* cover either anchor), read `formal/README.md`.
- For the planned upgrades that touch these anchors, read `docs/future_upgrades.md`.
- For the descriptive docs that should stay descriptive of what *is*, read `README.md`, `docs/SPECIFICATIONS.md`, `docs/OPERATOR_GUIDE.md` and `formal/README.md`. When one of the "not landed" items in `docs/future_upgrades.md` §1 becomes real, move its facts out of `future_upgrades.md` and into the descriptive doc that owns that subject, and leave a one-line note behind.
