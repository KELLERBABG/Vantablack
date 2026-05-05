# 🖤 VANTABLACK — Post-Quantum, Cryptographically Layered P2P Chat

> **Blind Routing Protocol (BRP) · Black Hole Storage (BHS)**  
> A cryptographically layered, post-quantum peer-to-peer chat system designed for adversarial networks.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/built%20with-Rust-orange.svg)](https://www.rust-lang.org/)
[![Tokio](https://img.shields.io/badge/async-Tokio-blue.svg)](https://tokio.rs/)
[![Post-Quantum](https://img.shields.io/badge/crypto-post--quantum-brightgreen.svg)]()

---

## Table of Contents

- [Why VANTABLACK](#why-vantablack)
- [Overview](#overview)
- [Module Structure](#module-structure)
- [Core Architecture](#core-architecture)
- [GHOST Protocol Stack](#ghost-protocol-stack)
- [Ghost Transport Frame (GTF)](#ghost-transport-frame-gtf)
- [PQ-Exchange PDU](#pq-exchange-pdu)
- [Blind Routing Protocol (BRP)](#blind-routing-protocol-brp)
- [Black Hole Storage (BHS)](#black-hole-storage-bhs)
- [Cryptographic Stack](#cryptographic-stack)
- [Handshake & Key Exchange](#handshake--key-exchange)
- [Data Transfer Security](#data-transfer-security)
- [Session & Replay Protection](#session--replay-protection)
- [Why Interception Is Practically Infeasible](#why-interception-is-practically-infeasible)
- [Getting Started](#getting-started)
- [Dependencies](#dependencies)
- [Security Considerations](#security-considerations)
- [License](#license)

---

## Why VANTABLACK?

Most people who want private messaging reach for Signal, WhatsApp, or Telegram. These are good products. But they all share a structural problem: **they are centralized, server-dependent, and not designed to survive a determined, resourced adversary or a post-quantum threat.** VANTABLACK was built for the cases they cannot cover.

### The Problem With Popular Messengers

| Property | Signal | WhatsApp | Telegram | Wire | VANTABLACK |
|---|---|---|---|---|---|
| End-to-end encrypted | ✅ | ✅ | ✅ (opt-in) | ✅ | ✅ |
| Centralized server required | ✅ | ✅ | ✅ | ✅ | ❌ |
| Phone number / account required | ✅ | ✅ | ✅ | ✅ | ❌ |
| Metadata visible to server | ✅ | ✅ | ✅ | ✅ | ❌ |
| Post-quantum key exchange | ❌ | ❌ | ❌ | ❌ | ✅ |
| Key material split across packets | ❌ | ❌ | ❌ | ❌ | ✅ |
| Ciphertext split across packets | ❌ | ❌ | ❌ | ❌ | ✅ |
| Traffic-analysis resistant padding | ❌ | ❌ | ❌ | ❌ | ✅ |
| Dynamic ephemeral port | ❌ | ❌ | ❌ | ❌ | ✅ |
| Open, auditable, dependency-minimal | ✅ | ❌ | ❌ | partial | ✅ |

### Signal Is Good — But It Has a Server

Signal is widely considered the gold standard for consumer messaging security. Its Double Ratchet protocol provides forward secrecy and break-in recovery that VANTABLACK does not currently implement. For most threat models, Signal is excellent.

However, Signal requires connecting to Signal's infrastructure. That means:

- **Signal knows who you talk to and when** — message metadata (sender, recipient, timestamp, frequency) is handled by their servers, even if the content is encrypted.
- **Signal can be compelled or blocked** — a government can demand metadata under legal process, or simply block Signal's servers at the network level. Both have happened.
- **Signal requires a phone number** — your identity is tied to a real-world identifier from the moment you register.

VANTABLACK operates entirely peer-to-peer over raw UDP. There is no server. No account. No phone number. No metadata leaves your machine except the packets themselves — and those packets are designed to reveal as little as possible even to a passive observer on the wire.

### Telegram Is Not What People Think

Telegram's default chats are **not end-to-end encrypted**. Messages are stored in plaintext on Telegram's servers and encrypted only in transit (TLS). "Secret Chats" do offer E2E encryption, but this is opt-in, unavailable for group chats, and based on MTProto — a home-designed protocol that has faced sustained academic criticism. Telegram has handed over user data to authorities and has had its protocol vulnerabilities documented publicly.

### WhatsApp Uses Signal's Protocol — But Meta Sees Everything Around It

WhatsApp's content encryption is solid (it uses the Signal Protocol under the hood). The problem is the envelope: Meta collects your contact graph, usage patterns, device identifiers, and behavioral metadata at scale. The message content may be private; the fact that you messaged someone at 2 AM, how often, and from which device is not.

### Wire and Similar "Business-Secure" Tools

Wire and similar enterprise-grade secure messengers improve on consumer apps in some respects — Wire does not require a phone number, for example — but they are still server-reliant, still centralized, and none implement post-quantum key exchange or the shard-based packet-level obfuscation that VANTABLACK provides.

### Where VANTABLACK Fits

VANTABLACK is **not a Signal replacement for everyday use.** It does not have persistent message history, group chats, or a polished mobile app. What it does have is a specific set of properties that no centralized messenger can offer:

**1. No infrastructure dependency.** Two machines, a network path between them, and nothing else. No DNS, no CDN, no servers to seize or block.

**2. Post-quantum security today.** The hybrid X25519 + Kyber512 key exchange means the session key is secure against both classical and quantum adversaries. A recording adversary who captures today's traffic and waits for a cryptographically-relevant quantum computer will find the Kyber512 component still holds.

**3. Sub-packet-level obfuscation.** No other production messaging system splits the key *and* the ciphertext across independently transmitted packets. A passive observer capturing a single packet captures neither a complete key share (which would still be useless alone) nor a complete ciphertext — they have a fragment of an already-encrypted blob, with no key material to pair it against.

**4. Zero identity linkage.** Identity keys are generated fresh at startup and never persisted. There is no account, no registration, no phone number, and no server log to subpoena.

If your threat model includes state-level passive interception, traffic analysis, server compromise, quantum-capable adversaries, or the need to communicate without revealing that you are communicating at all — VANTABLACK was built for exactly that.

---

## Overview

VANTABLACK is a peer-to-peer encrypted messaging system built in Rust that operates over raw UDP. It is designed around two foundational principles that, when combined, make passive interception and active tampering extremely difficult even for well-resourced adversaries:

**Blind Routing Protocol (BRP)** — a layered approach to key derivation, transmission splitting, and counter-based replay prevention that ensures no single captured packet can yield plaintext or key material. BRP governs *how* data travels: splitting keys, sequencing packets, and obfuscating traffic patterns.

**Black Hole Storage (BHS)** — a multi-shard transmission scheme using Shamir's Secret Sharing combined with Reed-Solomon erasure coding, ensuring that even if packets are dropped, duplicated, or tampered with mid-transit, the session remains intact and tamper-evident. BHS governs *what* travels: the shard-level construction of each payload so that any individual packet is cryptographically incomplete on its own.

Together, these form a system where both passive eavesdroppers and active man-in-the-middle attackers face layered, compounding barriers at every stage of a communication session.

---

## Module Structure

The codebase is split into four files, each with a single clear responsibility:

| File | Responsibility |
|---|---|
| `src/main.rs` | Entry point, CLI setup, async task orchestration, Tokio runtime |
| `src/session.rs` | `SessionGuard` — sliding-window anti-replay, hard/idle timeout logic |
| `src/crypto.rs` | All cryptographic operations: AEAD, Shamir SSS, Reed-Solomon, identity key management |
| `src/network.rs` | Packet layout constants, `send_handshake_packets`, `send_data_packets`, header parsing helpers |

### Dependency graph

```
main.rs
 ├── session.rs   (SessionGuard, timeout constants)
 ├── crypto.rs    (encrypt_message, decrypt_message, rs_encode, rs_reconstruct,
 │                 shamir_split, shamir_join, random_key, PeerIdentity)
 └── network.rs   (HANDSHAKE_ID, BASE_SIZE, JITTER_MAX, offset constants,
                   send_handshake_packets, send_data_packets,
                   parse_counter, shard_len_for)
```

`session.rs`, `crypto.rs`, and `network.rs` have no dependencies on each other, keeping each module independently testable.

---

## Core Architecture

```
┌─────────────────────────────────────────────────────────┐
│                     VANTABLACK V2.0                     │
├──────────────┬──────────────────────┬───────────────────┤
│  HANDSHAKE   │    DATA CHANNEL      │   SESSION GUARD   │
│  (BRP/BHS)   │     (BRP/BHS)        │  (Replay Window)  │
│ network.rs   │  network.rs          │  session.rs       │
├──────────────┴──────────────────────┴───────────────────┤
│          CRYPTOGRAPHIC LAYER  (crypto.rs)               │
│  X25519 ECDH + Kyber512 KEM + Ed25519 Signing           │
│  ChaCha20-Poly1305 AEAD · Shamir SSS · Reed-Solomon     │
├─────────────────────────────────────────────────────────┤
│          ORCHESTRATION  (main.rs)                       │
│             TRANSPORT: RAW UDP (DYNAMIC PORT)           │
└─────────────────────────────────────────────────────────┘
```

The system spawns three concurrent async tasks:

1. **Receiver loop** — reconstructs shards, verifies counters, decrypts messages
2. **Handshake loop** — continuously retransmits handshake shards until the master key is established
3. **Chat loop** — encrypts, shards, and transmits user messages

All tasks share state through `Arc<RwLock<_>>` primitives, making the system thread-safe across the async Tokio runtime.

---

## GHOST Protocol Stack

Every transmission in VANTABLACK passes through seven ordered protocol layers. Each layer adds an independent security property; an adversary must defeat all of them simultaneously to compromise a session.

```
┌─────────────────────────────────────────────────────────────┐
│                    GHOST STACK                              │
├──────┬──────────────────────────────────────────────────────┤
│ L0   │ Ed25519 Signature                                    │
│      │ Authenticates the origin of the handshake key        │
│      │ material. Prevents key substitution attacks.         │
├──────┼──────────────────────────────────────────────────────┤
│ L1   │ X25519 (ECC) + Kyber-512                            │
│      │ Hybrid KEM: classical + post-quantum key exchange.   │
│      │ Secure if either primitive remains unbroken.         │
├──────┼──────────────────────────────────────────────────────┤
│ L2   │ ChaCha20-Poly1305 Auth-Tag (MAC)                     │
│      │ AEAD encryption + authentication of all content.     │
│      │ Any byte modification causes silent discard.         │
├──────┼──────────────────────────────────────────────────────┤
│ L3   │ Shamir (GF256)                                       │
│      │ Master key split into 3 shares, any 2 reconstruct.   │
│      │ A single share is cryptographically zero-knowledge.  │
├──────┼──────────────────────────────────────────────────────┤
│ L4   │ Reed-Solomon (Erasure Coding)                        │
│      │ Ciphertext split into 2 data + 1 parity shard.       │
│      │ Any 2 of 3 shards reconstruct the full ciphertext.   │
├──────┼──────────────────────────────────────────────────────┤
│ L5   │ Noise-Injection / Constant Flow                      │
│      │ Random jitter padding (0–64 B) per packet.           │
│      │ Obscures payload size; frustrates traffic analysis.  │
├──────┼──────────────────────────────────────────────────────┤
│ L6   │ Variable Payload Size · State & Replay Guard         │
│      │ Dynamic ephemeral port binding. 128-counter sliding  │
│      │ window bitmask rejects replayed or stale packets.    │
└──────┴──────────────────────────────────────────────────────┘
```

The layers are ordered so that lower layers (L0–L1) protect identity and key material, middle layers (L2–L4) protect content integrity and enable loss recovery, and upper layers (L5–L6) protect the communication pattern itself from traffic analysis and replay.

---

## Ghost Transport Frame (GTF)

Every UDP packet — whether handshake or data — uses the Ghost Transport Frame layout. The fields are fixed-position so the receiver can parse the header before any decryption or shard reconstruction occurs.

```
┌──────────────┬───────────────┬──────────┬─────────────────────────────────┬──────────────┐
│ Offset       │ Field         │ Size     │ Purpose                         │ Notes        │
├──────────────┼───────────────┼──────────┼─────────────────────────────────┼──────────────┤
│ 0 – 3        │ Session Hash  │ 4 B      │ Short ID linking this shard to  │ Truncated    │
│              │               │          │ its handshake session.           │ hash         │
├──────────────┼───────────────┼──────────┼─────────────────────────────────┼──────────────┤
│ 4 – 7        │ Packet        │ 4 B      │ Monotonic counter for anti-     │ Big-endian   │
│              │ Counter       │          │ replay. Every packet requires   │ u32/u64      │
│              │               │          │ a new value.                    │              │
├──────────────┼───────────────┼──────────┼─────────────────────────────────┼──────────────┤
│ 8            │ Shard Index   │ 1 B      │ Tells the receiver which of the │ 0, 1, or 2   │
│              │               │          │ three shards this packet        │ (parity)     │
│              │               │          │ carries, for re-assembly.       │              │
├──────────────┼───────────────┼──────────┼─────────────────────────────────┼──────────────┤
│ 9 – 495      │ Shard Payload │ 487 B    │ The actual BHS/BRP payload:     │ GF(256)      │
│              │               │          │ Galois-field encoded ciphertext │ coordinates  │
│              │               │          │ or handshake data.              │              │
├──────────────┼───────────────┼──────────┼─────────────────────────────────┼──────────────┤
│ 496 – 511    │ Auth Tag      │ 16 B     │ Poly1305 MAC. Authenticates the │ Covers full  │
│              │               │          │ entire packet against tampering.│ frame        │
└──────────────┴───────────────┴──────────┴─────────────────────────────────┴──────────────┘
```

**Total frame size: 512 bytes** (base). Data packets append 0–64 bytes of random jitter padding beyond this base.

The Auth Tag at the tail means any in-transit modification — to any field including the counter or shard index — causes authentication to fail. The packet is silently dropped, never processed.

---

## PQ-Exchange PDU

The handshake is transmitted as a single 960-byte Protocol Data Unit, split across three GTF packets by BHS. The PDU layout carries all material needed for the hybrid post-quantum key exchange and identity verification:

```
┌─────────────────┬──────────┬────────────────────────────────────────────────┬────────┐
│ Field           │ Size     │ Content / Purpose                              │ Layer  │
├─────────────────┼──────────┼────────────────────────────────────────────────┼────────┤
│ Header (Intern) │ 16 B     │ Magic bytes ("GHOST_HANDSHAKE_"). Visible only │   —    │
│                 │          │ after full shard reconstruction; not exposed   │        │
│                 │          │ in any individual packet.                       │        │
├─────────────────┼──────────┼────────────────────────────────────────────────┼────────┤
│ X25519-Part     │ 32 B     │ Sender's X25519 (ECC) public key.              │  L1    │
│                 │          │ Classical elliptic-curve component of the       │        │
│                 │          │ hybrid KEM.                                     │        │
├─────────────────┼──────────┼────────────────────────────────────────────────┼────────┤
│ Kyber-Part      │ 800 B    │ Sender's Kyber-512 public key.                 │  L1    │
│                 │          │ Post-quantum lattice-based KEM component.       │        │
│                 │          │ Resistant to Shor's algorithm.                  │        │
├─────────────────┼──────────┼────────────────────────────────────────────────┼────────┤
│ Identity-Key    │ 32 B     │ Sender's Ed25519 verifying key (public).        │  L0    │
│                 │          │ The persistent cryptographic identity of this   │        │
│                 │          │ device for this session.                        │        │
├─────────────────┼──────────┼────────────────────────────────────────────────┼────────┤
│ Identity-Proof  │ 64 B     │ Ed25519 signature over the Kyber-Part.         │  L0    │
│                 │          │ Cryptographically proves the sender controls    │        │
│                 │          │ the identity key and authored the KEM key.      │        │
├─────────────────┼──────────┼────────────────────────────────────────────────┼────────┤
│ Padding /       │ 16 B     │ Padding to reach the clean 960-byte total.     │   —    │
│ Checksum        │          │ Used for integrity checking and alignment.      │        │
└─────────────────┴──────────┴────────────────────────────────────────────────┴────────┘
```

**Total PDU size: 960 bytes** → split into two 480-byte data shards + one 480-byte Reed-Solomon parity shard, each carried in its own GTF packet.

The receiver verifies the `Identity-Proof` signature before accepting any key material. A man-in-the-middle cannot substitute the `Kyber-Part` without also producing a valid Ed25519 signature over the replacement key, which requires possession of the sender's private identity key.

---

## Blind Routing Protocol (BRP)

BRP — **Blind Routing Protocol** — is the overarching transmission protocol that governs how data moves between peers. Its primary goal is to ensure that no single intercepted packet — or even the full set of intercepted packets — gives an adversary a trivial path to plaintext.

### Key Principles of BRP

**1. Key Material Never Travels Whole**

The master encryption key is never sent across the wire in its entirety. Instead, it is split using Shamir's Secret Sharing (a threshold secret sharing scheme) into three shares, any two of which are required for reconstruction. These shares are distributed across three independently transmitted UDP packets. An adversary intercepting only one packet captures a share that is, by itself, cryptographically useless — it reveals nothing about the key.

**2. Ciphertext Never Travels Whole**

The encrypted payload is split at the midpoint into two shards, with a third Reed-Solomon parity shard computed over them. The receiver reconstructs the full ciphertext only after collecting at least two shards. An adversary who captures a single shard holds roughly half of an already-encrypted blob — decryption requires key material that is itself split across separate packets.

**3. Jitter Padding Frustrates Traffic Analysis**

Each packet is padded with a random number of bytes (0–64) beyond the base size. This prevents traffic analysis attacks that rely on correlating packet sizes to message lengths or protocol phases.

**4. Dynamic Addressing**

The system binds to `0.0.0.0:0`, receiving a dynamically assigned ephemeral port. The peer's address is updated on first contact, preventing static port-based filtering and making passive traffic correlation harder.

**5. Monotonic Counter Sequencing**

Every message carries a globally monotonic 64-bit counter, embedded in each of its three shards. The session guard validates these counters against a sliding window bitmask, rejecting any out-of-window or already-seen sequence numbers.

---

## Black Hole Storage (BHS)

BHS — **Black Hole Storage** — describes the shard-level construction of each transmission: the combination of secret sharing and erasure coding that makes individual packets non-reconstructible by a passive observer and resilient to packet loss.

### How Sharding Works

For a message of length `N` bytes:

```
Original plaintext
        │
        ▼
┌─────────────────────┐
│  ChaCha20-Poly1305  │  ← encrypted with master key + 16-byte auth tag
│   (N + 16 bytes)    │
└─────────────────────┘
          │
     split in half
          │
     ┌────┴────┐
     ▼         ▼
  Shard[0]  Shard[1]    ← two data shards
               │
               ▼
           Shard[2]    ← Reed-Solomon parity shard (computed from 0+1)
```

Each shard is paired with a corresponding Shamir share of the master key and wrapped in a Ghost Transport Frame (GTF):

```
GTF Packet i = [ session_hash (4B) | packet_counter (4B) | shard_index (1B) |
                 shard_payload (487B) | auth_tag (16B) | jitter_padding (0–64B) ]
```

The Shamir share of the master key travels inside the `shard_payload` field alongside the ciphertext shard, so no single packet exposes either the key or the ciphertext in usable form.

The receiver buffers shards per `msg_id` and attempts reconstruction only when ≥ 2 shards arrive. Reed-Solomon allows the third shard to substitute for either missing data shard, providing one-packet-loss resilience.

### Why This Is "Byzantine Hardened"

In Byzantine fault-tolerant systems, the concern is not just packet loss but active adversarial interference — packet injection, modification, or replay. BHS addresses each threat:

| Threat | Mitigation | Protocol Layer |
|---|---|---|
| Packet interception | Single shard = ½ ciphertext, useless without key share | BHS (L4) |
| Key reconstruction | Requires 2 of 3 Shamir shares from separate packets | BHS (L3) |
| Packet tampering | Poly1305 Auth Tag in GTF covers the full frame | GTF / L2 |
| Packet replay | 128-counter sliding window bitmask rejects duplicates | BRP (L6) |
| Packet injection | Ed25519 identity proof in PQ-Exchange PDU | BRP (L0) |
| Traffic analysis | Jitter padding (L5) + variable payload + ephemeral port | BRP (L5/L6) |
| Packet loss | RS parity shard reconstructs from any 2 of 3 | BHS (L4) |
| Quantum adversary | Kyber-512 KEM unbroken by Shor's algorithm | BRP (L1) |

---

## Cryptographic Stack

VANTABLACK uses a hybrid classical + post-quantum cryptographic stack:

### Key Exchange: X25519 + Kyber512 (Hybrid KEM)

The handshake combines two key encapsulation mechanisms:

- **X25519 (ECDH)** — classical elliptic-curve Diffie-Hellman over Curve25519. Provides ~128-bit classical security and is resistant to all known classical attacks.
- **Kyber512 (ML-KEM)** — a NIST-standardized post-quantum key encapsulation mechanism based on the hardness of Module Learning With Errors (MLWE). Resistant to attacks by Shor's algorithm on a cryptographically-relevant quantum computer.

By combining both, the session key derivation is secure as long as *either* scheme remains unbroken — a classical adversary cannot break Kyber512, and a quantum adversary cannot break the combined binding without solving both simultaneously.

### Identity Authentication: Ed25519

Each peer generates a fresh ephemeral `SigningKey` (Ed25519) at startup. During the handshake, the sender signs their Kyber512 public key with this identity key. The receiver verifies the signature before accepting the handshake. This prevents key substitution attacks and authenticates the origin of the key material.

The identity fingerprint (first 8 bytes of the verifying key) is displayed to the user for out-of-band verification.

### Symmetric Encryption: ChaCha20-Poly1305

All chat messages are encrypted with ChaCha20-Poly1305 AEAD, using the reconstructed master key:

- **ChaCha20** provides 256-bit stream cipher security
- **Poly1305** provides 128-bit authentication tag integrity
- Any single-bit modification to ciphertext causes authentication failure — tampering is detectable

### Secret Sharing: Shamir's Secret Sharing (GF(256))

Key material is split using Shamir's Secret Sharing over GF(256). A (2,3) threshold scheme is used: 3 shares are generated, any 2 are sufficient to reconstruct the secret. One share alone reveals zero information about the secret due to the information-theoretic security of the scheme.

### Erasure Coding: Reed-Solomon (2,1)

A (2,1) Reed-Solomon code is applied to the ciphertext shards. This means 2 data shards plus 1 parity shard. Any 2 of the 3 shards are sufficient to reconstruct the full ciphertext, providing resilience against single-packet loss on unreliable networks without retransmission overhead.

---

## Handshake & Key Exchange

The handshake is designed to bootstrap a shared master key between two peers with no prior shared state. It is continuously retransmitted until acknowledged.

### Handshake Blob Structure (960 bytes)

```
Bytes [0..16]    → Magic header "GHOST_HANDSHAKE_"
Bytes [16..48]   → X25519 ephemeral public key (32 bytes)
Bytes [48..848]  → Kyber512 public key (800 bytes)
Bytes [848..880] → Ed25519 verifying key (32 bytes)
Bytes [880..944] → Ed25519 signature over Kyber512 public key (64 bytes)
```

This blob is split into two 480-byte shards with a Reed-Solomon parity shard, and a temporary ephemeral key is Shamir-split across the three packets.

### Handshake Flow

```
Alice                                          Bob
  │                                              │
  │──── Shard[0]: Kyber PK + Sig + X25519 ─────▶│
  │──── Shard[1]: (continued) ──────────────────▶│
  │──── Shard[2]: RS parity ────────────────────▶│
  │                                              │
  │                   [Bob reconstructs blob, verifies Ed25519 sig]
  │                   [Bob derives master key, marks session open]
  │                                              │
  │◀─── Shard[0]: Kyber PK + Sig + X25519 ──────│
  │◀─── Shard[1]: (continued) ──────────────────│
  │◀─── Shard[2]: RS parity ────────────────────│
  │                                              │
[Alice reconstructs blob, verifies Ed25519 sig]  │
[Alice derives master key, marks session open]    │
  │                                              │
  ╔══════════════════════════════════════════╗   │
  ║         ENCRYPTED CHAT SESSION           ║   │
  ╚══════════════════════════════════════════╝   │
```

Master key derivation uses the Shamir-reconstructed ephemeral key from the handshake shards. After one successful handshake, subsequent handshake packets are silently dropped.

---

## Data Transfer Security

Once the session is established, each message undergoes the following pipeline before transmission:

```
User input string
        │
   format with nickname
        │
        ▼
ChaCha20-Poly1305 encrypt (master key)
        │   + 16-byte Poly1305 tag appended
        │
   pad to even length
        │
        ▼
  Split at midpoint → Shard[0], Shard[1]
        │
  Reed-Solomon encode → Shard[2] (parity)
        │
  Shamir-split master key → Share[0], Share[1], Share[2]
        │
        ▼
  Assign random msg_id (1–253), increment global counter
        │
        ▼
  Transmit 3 packets, each with random jitter padding
```

On the receiver side:

```
Buffer incoming shards by msg_id
        │
  Await ≥ 2 shards
        │
  Validate counter against SessionGuard window
        │
  Reed-Solomon reconstruct full ciphertext
        │
  Shamir reconstruct master key from 2 shares
        │
  ChaCha20-Poly1305 decrypt + verify tag
        │
  Display plaintext to user
```

---

## Session & Replay Protection

The `SessionGuard` struct maintains a sliding-window anti-replay mechanism:

```rust
struct SessionGuard {
    start_time: Instant,      // session start (hard timeout reference)
    last_activity: Instant,   // last valid packet (idle timeout reference)
    v_max: u64,               // highest counter seen
    bitmask: u128,            // tracks received counters in [v_max-127, v_max]
}
```

### Window Mechanics

- The window covers the 128 most recent counter values (`WINDOW_SIZE = 128`)
- Any counter ≤ `v_max - 128` is unconditionally rejected (too old)
- Any counter already set in the bitmask is rejected (already received — replay)
- A new highest counter shifts the bitmask and sets the leading bit

### Timeout Policy

| Timeout | Duration | Description |
|---|---|---|
| Hard session timeout | 24 hours | Absolute session lifetime |
| Idle timeout | 30 minutes | Max silence before session expires |

After expiry, `check_and_update` returns `false` for all packets, effectively closing the session until a new handshake is completed.

---

## Why Interception Is Practically Infeasible

The following summarizes the compounding barriers an adversary faces when attempting to compromise a VANTABLACK session.

### Against Passive Eavesdropping (LAN/WAN sniffing)

An attacker capturing all packets on the wire faces:

1. **No plaintext** — all data is ChaCha20-Poly1305 encrypted before transmission
2. **No complete ciphertext in any single packet** — ciphertext is split across two data packets; one packet holds ~½ of an already-encrypted blob
3. **No key in any single packet** — the master key is Shamir-split; one share leaks zero information about the key
4. **No key in two packets** — the Shamir reconstruction requires a correct pairing of shares; an adversary holding shard[0] and shard[2] (wrong pairing) reconstructs garbage
5. **No static address or port** — dynamic ephemeral ports prevent trivial passive correlation
6. **Obfuscated lengths** — jitter padding breaks packet-size-based traffic fingerprinting

Even a passive adversary capturing the complete three-packet burst for a message must break ChaCha20-Poly1305 with a 256-bit key to reach plaintext — computationally infeasible with current and near-future classical hardware.

### Against Active Man-in-the-Middle

An active attacker attempting to inject or substitute packets faces:

1. **Ed25519 handshake authentication** — the Kyber512 public key is signed by the sender's ephemeral identity key; a MITM cannot substitute a different key without producing a valid signature, which requires possession of the private identity key
2. **Poly1305 authentication tag** — any modification to any ciphertext byte causes decryption to fail (`open_in_place` returns `Err`); tampered packets are silently discarded
3. **Counter window** — replayed original packets are rejected by the bitmask; an attacker cannot reuse captured packets to trigger re-processing of old messages

### Against Quantum Adversaries

A quantum computer running Shor's algorithm breaks X25519 (ECDH) but **not** Kyber512. Because both are used in the hybrid KEM:

- Breaking X25519 alone does not yield the session key
- Breaking Kyber512 requires solving MLWE, for which no quantum polynomial-time algorithm is currently known
- The combined scheme is secure as long as either primitive remains unbroken

---

## Getting Started

### Prerequisites

- Rust (stable, 1.75+)
- Cargo

### Project Layout

```
vantablack/
├── Cargo.toml
└── src/
    ├── main.rs       ← entry point & async orchestration
    ├── session.rs    ← anti-replay SessionGuard
    ├── crypto.rs     ← AEAD, Shamir, Reed-Solomon, identity
    └── network.rs    ← packet format & send helpers
```

### Build

```bash
git clone https://github.com/KELLERBABG/vantablack.git
cd vantablack
cargo build --release
```

### Run

```bash
# On machine A
./target/release/vantablack
# > Nickname: Alice
# > Ziel-IP: 192.168.1.42

# On machine B
./target/release/vantablack
# > Nickname: Bob
# > Ziel-IP: 192.168.1.10
```
Or easier, download the EXE file and you can directly chat with someone in your LAN or WAN, depending on your usecase.

The application will display each peer's identity fingerprint. Verify these out-of-band (e.g., via phone or a pre-established secure channel) to confirm you are speaking with the intended party.

---

## Dependencies

| Crate | Purpose |
|---|---|
| `tokio` | Async runtime, timers |
| `reed-solomon-erasure` | (2,1) RS erasure coding over GF(2^8) |
| `ring` | ChaCha20-Poly1305 AEAD, secure random |
| `gf256` | Shamir's Secret Sharing over GF(256) |
| `x25519-dalek` | X25519 elliptic-curve Diffie-Hellman |
| `pqcrypto-kyber` | Kyber512 post-quantum KEM |
| `ed25519-dalek` | Ed25519 identity signing and verification |
| `rand` | Thread-local RNG for jitter and IDs |
| `hex` | Identity fingerprint display |

---

## Security Considerations

- **Nonce derivation**: Each message is encrypted with a nonce derived from the monotonic session counter (`counter (8 B) || 0x00 0x00 0x00 0x00`). Because the counter is strictly increasing and unique per session, the nonce is unique per (key, message) pair, satisfying ChaCha20-Poly1305's uniqueness requirement. The counter is already embedded in every GTF packet and validated by the replay guard, so the receiver always has the correct nonce available for decryption without additional transmission overhead.
- **Key confirmation**: The handshake establishes key material but does not include an explicit key confirmation step. An active MITM who intercepts all three handshake shards could potentially delay or suppress delivery.
- **Ephemeral identities**: Identity keys are generated fresh at startup and are not persisted. There is no persistent identity or public key infrastructure. Out-of-band fingerprint verification is recommended for high-assurance use.
- **Counter overflow**: The 64-bit counter will not overflow in practical use, but long-lived sessions should consider key renegotiation after a defined message count.
- **UDP reliability**: This system provides best-effort delivery only. Packet loss beyond the one-shard RS recovery capability will result in dropped messages with no retransmission.

---

## License

This project is licensed under the **MIT License**. See [LICENSE](LICENSE) for full terms.

```
MIT License

Copyright (c) 2026

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```
