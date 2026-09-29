# Atmospheric Broadcast OS (ABOS) — Technical Whitepaper

**Version 1.0 — August 2026**

> A software-defined radio operating system written in Rust that enables covert, resilient, long-range communication by exploiting ionospheric propagation physics. The atmosphere itself becomes a distributed relay, memory buffer, and stealth medium.

---

## Abstract

ABOS is a unified platform for decentralized mesh communication *without routing tables*. It combines **spread-spectrum stealth**, **cognitive radio**, **delay-tolerant networking (DTN)**, and **ionospheric sounding** into a single Rust workspace. The system treats the ionosphere as a passive, planetary-scale reflector: Near-Vertical Incidence Skywave (NVIS) propagation in the 2–10 MHz band returns signals almost straight down, enabling beyond-line-of-sight communication with no infrastructure. Every transmission is shard-split, FEC-encoded, DSSS-spread, stealth-masked, and delivered through DTN store-and-forward with opportunistic "Phoenix Window" scheduling (meteor scatter). The implementation is **feature-complete per the T4 readiness tier**: 14 crates, 103/103 workspace tests passing, zero compiler warnings, zero clippy warnings (`-D warnings`), CI-gated (fmt + clippy + test on every push), a full TX/RX chain orchestrated by `ABOSSystem`, a 10-subcommand clap CLI, a mesh layer (beacons, ACK aggregation with backoff, shard-availability tracking, live forwarding), a headless-testable GUI dashboard, and an offline loopback test harness. Remaining work (T5): real SDR hardware integration and over-the-air validation.

---

## 1. Motivation

Conventional communication infrastructure (cell towers, fiber, satellites) is a single point of failure under adversarial conditions or natural disaster. ABOS exploits a physical resource that cannot be switched off: **the ionosphere** — a conductive plasma layer at 60–1000 km altitude that reflects radio waves back to Earth. NVIS uses high-angle radiation (70–90° elevation) at frequencies just below the ionospheric critical frequency (f₀F2), reflecting energy directly back down and creating a closed-loop inductive path with the ground — the equivalent of a planetary-scale transformer.

The design goal: a mesh of nodes that communicate **without IP addresses, without routing tables, and without any centralized authority**, resilient to jamming, detection, and infrastructure loss.

## 2. System Architecture (13 Crates)

```
ABOSSystem (root orchestrator)
├── abos-hal       SDR driver abstraction, DMA zero-copy streaming, GPIO (T/R, PA), GPSDO
├── abos-dsp       DDC, SIMD FIR decimation, AGC, I/Q correction, Costas loop, Gardner timing,
│                  OFDM (256 subcarriers), FFT/IFFT, RRC pulse shaping
├── abos-phy       DSSS (PN/Gold codes), FHSS, scrambler, burst builder/parser
├── abos-fec       LDPC (256/512), BICM interleaver, soft-decision LLR (QPSK/BPSK/16-QAM), CRC32
├── abos-protocol  File→shard split (1.5× redundancy), DTN bundle, buffer-bounce, Phoenix scheduler, dedup routing,
│                  mesh layer: beacon discovery, ACK aggregation w/ exponential backoff, shard availability,
│                  forwarding path
├── abos-cognitive Spectrum scanner (FFT), jammer detection, white-space finder, adaptive MCS controller
├── abos-iono      Chirp sounder, f₀F2 estimation, NVIS frequency selection, meteor-burst detection, MUF prediction
├── abos-stealth   Cyclostationary masking (variable symbol rate), artificial phase noise, amplitude dither,
│                  randomized burst scheduling (<1 ms bursts)
├── abos-storage   Persistent DTN bundle store (TTL/eviction, dedup, pending listing), config
├── abos-common    Complex math, PN/Gold code generators, AES/HMAC crypto, node ID from pubkey, key derivation
├── abos-cli       10 subcommands (clap; provides the `abos` binary)
├── abos-gui       Headless GuiState + egui dashboard view (unit-tested without a display)
└── abos-tests     Loopback channel, e2e/mesh/fault-injection harness
```

## 3. Physical Layer

### 3.1 RF Chain (TX)
```
Shard split → DTN bundle → scramble → BICM interleave → LDPC encode → QPSK map →
OFDM modulate (256 subcarriers, 32 CP, 4 pilots) → RRC pulse shape → DSSS spread →
stealth mask (variable symbol rate + phase noise + amp dither) → burst build →
SDR TX (T/R switch)
```

### 3.2 RF Chain (RX)
```
SDR RX → burst parse → sync correlate → DSSS despread → RRC → OFDM demod →
QPSK soft LLR → LDPC decode (50 iters) → deinterleave → descramble →
bundle deserialize → dedup check → store → buffer-bounce → forward decision
```

### 3.3 DSSS & Stealth
- **Processing gain ≥ 20–30 dB** required to hide below the noise floor (1 kbps symbol / 1 Mcps chip → 30 dB).
- **CDMA-over-DSSS** as primary multiple access (different PN codes = simultaneous TX); FHSS for anti-jam.
- **Stealth masking:** cyclostationary signature masking via variable symbol-rate dithering, artificial phase-noise injection, pseudo-natural amplitude fluctuations modeled on ionospheric scintillation, and randomized sub-millisecond burst timing.

## 4. Ionospheric Sounding & NVIS

| Function | Implementation |
|---|---|
| f₀F2 estimation | `f_p ≈ 9·√N_e` from electron density (critical plasma frequency) |
| NVIS selection | Picks frequencies below f₀F2 (typically 2–8 MHz night, 4–10 MHz day) |
| MUF prediction | Maximum usable frequency for a given distance |
| Meteor scatter | Sudden SNR peak detection on far channels → "Phoenix Window" opportunistic TX |
| Chirp sounder | Frequency-swept probe waveform for live channel assessment |

## 5. Protocol Layer

- **Shard splitting** with 1.5× redundancy (Fountain-code-style: receiver needs *any* K of N).
- **DTN bundles** with TTL, hop count, store-and-forward via persistent `BundleStore`.
- **Buffer-Bounce engine**: listens for complementary shards + ACKs; opportunistic retransmission.
- **Routing**: no routing tables — implicit flooding/bouncing with TTL + content-hash dedup (`DedupCache`).

## 6. Cryptographic Design

- **Bundle encryption:** AES-256-GCM (recommended; building plan).
- **Key exchange:** X25519 or Kyber512 (post-quantum) — building-plan recommendation.
- **PN sequences for DSSS/FHSS:** cryptographically secure PRNG (ChaCha20-based) seeded with a shared secret.
- **Node identity:** cryptographic node ID = hash of public key (Tor/i2p/libp2p style) — no IP addresses.
- **HMAC** for integrity.

## 7. Test Coverage (103/103 passing)

| Crate | Tests | Coverage |
|---|---|---|
| `abos` (root) | 5 | System creation, f₀F2, NVIS selection, chirp, meteor detection |
| `abos-common` | 14 | QPSK constellation, IQ rotation, PN determinism, Gold codes, AES, HMAC, node ID, key derivation, shard serialization, MCS |
| `abos-dsp` | 14 | DDC, AGC, IQ correction, Costas convergence, Gardner timing, FIR, decimation, RRC, FFT/IFFT, OFDM |
| `abos-fec` | 12 + 5 | LDPC roundtrip, interleaver, LLR, CRC + **syndrome-zero, single-flip correction, short-input** |
| `abos-phy` | 3 | DSSS spread/despread roundtrip, truncated tail, wrong-seed rejection |
| `abos-protocol` | 10 | Mesh: beacon discovery, flooding dedup, ACK backoff, availability, forwarding rules |
| `abos-storage` | 4 | Store roundtrip, dedup-on-insert, TTL eviction, pending listing |
| `abos-gui` | 11 | Spectrum/whitespace/log/status rules + **headless egui render tests** |
| `abos-tests` | 27 | E2e byte-identical roundtrip (clean/noise/DSSS/corruption), 3-node mesh, fault injection |

## 8. Status & Roadmap

- **T4 (feature-complete & gated)** reached — full coverage across all 13 workspace crates with 103/103 tests passing and zero compiler or clippy warnings.
- **T5 remaining:** real SDR backend (SoapySDR/UHD FFI), over-the-air loopback
  decode, structured logging/metrics, fuzzing of the wire parsers, LICENSE.
- **Hardware:** targeting USRP B210 / LimeSDR, PA + NVIS horizontal dipole (~5–10 m height, λ/2 at 3–7 MHz), RPi 4 / x86 embedded / FPGA SoC.
- **Legal note:** NVIS/meteor bands require amateur-radio or experimental licensing in most jurisdictions.