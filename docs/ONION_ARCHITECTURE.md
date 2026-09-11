# Deep Dive: Clean-Room Onion Routing Architecture

This document details the multi-hop onion routing mechanism implemented in Global Ghost Net, explaining how it achieves decentralized, anonymous message forwarding without relying on, borrowing from, or reusing any legacy Tor or onion routing codebases.

---

## 1. Clean-Room Implementation Principles

Traditional onion networks (such as Tor) were designed decades ago around TCP circuits, directory authorities, and pre-quantum cryptography (RSA, Curve25519). 

Global Ghost Net implements onion routing **from first principles** in pure Rust:
1. **Zero Legacy Dependencies:** No C/C++ libraries, no OpenSSL, no legacy circuit protocols.
2. **Datagram-Native (UDP):** Operates on fixed 512-byte Ghost Transport Frames (GTF) over UDP, eliminating TCP circuit stalls, head-of-line blocking, and TCP fingerprinting.
3. **Post-Quantum Layering:** Key encapsulation at each layer uses hybrid **ML-KEM-512 (Kyber)** and **X25519**, defending transit payloads against future quantum decryption.
4. **No Central Directory Authorities:** Relays discover each other through decentralized DNS seeds, peer-to-peer exchange, and local signed beacons—completely eliminating trusted directory servers.

---

## 2. Multi-Hop Onion Peeling Mechanics

In Global Ghost Net, onion routing is handled through the clean-room `RLY!` header protocol implemented in `src/ghost/net/relay.rs`.

```
Initiator (A)
   ¦
   ¦ Encrypted with Relay Key (R) & Outer Key (B)
   ?
[Hop 1: Relay Node R] ---- Unwraps outer RLY! layer
   ¦                   ---- Learns only: "Next Hop is Exit Node B"
   ¦                   ---- Does NOT see payload or origin identity
   ?
[Hop 2: Exit Node B]  ---- Unwraps final inner AEAD layer
   ¦                   ---- Delivers payload to destination
   ?
Target Destination / WAN
```

### Frame Encapsulation Lifecycle

When a node sends an onion-routed frame via `SENDRELAY <dest_fp> <relay_fp> <payload>`:

1. **Inner Layer (Destination):**
   The plaintext payload is encrypted using the authenticated symmetric session key shared with the destination (`dest_fp`):
   ```text
   InnerCiphertext = ChaCha20-Poly1305_Encrypt(Key: DestinationKey, Payload)
   ```

2. **Onion Relay Header Construction:**
   An onion forwarding instruction is prepended:
   ```text
   [4 Bytes: Magic "RLY!"] + [32 Bytes: Destination Fingerprint] + [InnerCiphertext]
   ```

3. **Outer Layer (Relay Node):**
   The relay instruction and inner ciphertext are encrypted together using the session key shared with the intermediate relay (`relay_fp`):
   ```text
   OuterCiphertext = ChaCha20-Poly1305_Encrypt(Key: RelayKey, "RLY!" + dest_fp + InnerCiphertext)
   ```

4. **Peeling at the Relay:**
   When the intermediate relay receives the frame, it decrypts its outer layer using its own session key.
   - It verifies the `RLY!` magic prefix.
   - It reads the target `dest_fp`.
   - It **immediately forwards** the remaining inner payload to the destination session.
   - The relay learns *only* who handed it the packet and who to pass it to. It cannot read the payload or know the true original source if chained across multiple hops.

---

## 3. Synergy with Reed-Solomon Sharding

Unlike traditional onion routing where a single full stream travels through a static multi-hop circuit, Global Ghost Net integrates **Reed-Solomon RS(2,1) Erasure Sharding**:

```
                  +--> [Relay 1] --> Shard 0 --+
[Initiator A] ----+--> [Relay 2] --> Shard 1 --+--> [Exit Node] --> WAN
                  +--> [Relay 3] --> Shard 2 --+
                     (Independent Paths)
```

1. Outbound data is fragmented into two data shards and one parity shard.
2. Each shard is wrapped in its own onion-encrypted envelope.
3. The shards travel across **completely independent relay nodes**.
4. Even if an adversary compromises an intermediate relay, they only observe an isolated 486-byte erasure shard. Reconstructing the message requires capturing multiple divergent relay streams simultaneously.

---

## 4. Replay & Timing Attack Mitigations

- **64-Bit Replay Sliding Window (`SessionGuardU64`):** Every hop maintains a lockless sliding window bitmap. Replayed onion packets are discarded before decryption occurs.
- **Fixed-Slot Temporal Isolation:** Decapsulation and crypto verification routines run in constant-time slots with dummy iterations to mitigate side-channel timing analysis.
- **Jitter Padding:** Frames are normalized to 512 bytes with 0–64 bytes of pseudorandom noise, masking packet lengths from passive network observers.
