# Global Ghost Net — Technical Specifications

This document defines the low-level protocols, cryptographic guarantees, and frame formats implemented in Global Ghost Net.

---

## 1. Cryptographic Suite

Global Ghost Net uses a dual classical and post-quantum hybrid cryptographic design:

- **Identity Layer (L0):** Ed25519 permanent signing key pair generated on first run and stored locally (`identity.key`). Used for authenticating identity beacons and capability vouchers.
- **Key Agreement (L1):** Hybrid Ephemeral Key Exchange:
  - Classical: X25519 ECDH.
  - Post-Quantum: ML-KEM-512 (Kyber-512 / FIPS 203) Key Encapsulation Mechanism.
  - Salt & Pre-Shared Key: HKDF-SHA256 mixes both shared secrets with an optional 32-byte pre-shared key (`GHOST_PSK`).
- **Authenticated Encryption (L2):** ChaCha20-Poly1305 (RFC 8439) with a 256-bit symmetric key.
  - Nonce generation incorporates the 4-byte session hash, direction bitmask (initiator vs receiver), and a 64-bit monotonic packet counter to mathematically eliminate nonce collision risks.
- **Erasure Coding (L4):** Reed-Solomon RS(2,1) over Galois Field GF(2^8). Plaintexts are split into two primary data shards and one parity shard. Any 2 shards reconstruct the exact original payload.
- **Memory Hardening (L8):** Ephemeral session keys and decrypted memory buffers are wiped using volatile zeroization on drop and protected with AES-256-XTS memory encryption.

---

## 2. Ghost Transport Frame (GTF) Format

All mesh communication travels encapsulated in uniform UDP datagrams.

### Privacy Mode Frame (512 Bytes)
In privacy mode, all datagrams are fixed to 512 bytes with randomized trailing jitter padding (0 to 64 bytes) to defeat packet-length traffic analysis:

| Byte Range | Field | Type | Description |
|---|---|---|---|
| `00..03` | Session Hash | `[u8; 4]` | Truncated session identifier for fast lookup |
| `04..07` | Packet Counter | `u32` (LE) | Monotonic counter used for replay protection |
| `08` | Shard Index | `u8` | Shard indicator (`0`, `1`, or `2` for RS parity) |
| `09` | Flags | `u8` | Bit flags (`0x00`: privacy, `0x01`: bulk transfer) |
| `10..495` | Encrypted Shard | `[u8; 486]` | ChaCha20-Poly1305 ciphertext payload |
| `496..511`| Auth Tag | `[u8; 16]` | Poly1305 authentication MAC tag |
| `512..576`| Jitter Padding | `[u8; 0..64]` | Variable pseudorandom noise bytes |

### Bulk Mode Frame (1472 Bytes)
For high-bandwidth file transfers across verified links, MTU-aligned 1472-byte frames maximize payload throughput without fragmentation.

---

## 3. Multipath Routing & Asymmetric Sharding

When a client transmits traffic:
1. The stream is chunked into 900-byte segments and passed through Reed-Solomon RS(2,1), producing three 486-byte shards.
2. The router evaluates candidate peer routes based on a Poisson reputation matrix (latency, jitter, drop rate).
3. The three shards are dispatched concurrently over distinct network interfaces or peer paths:
   - **Shard 0:** Dispatched to Peer A (fast link).
   - **Shard 1:** Dispatched to Peer B (medium link).
   - **Shard 2 (Parity):** Dispatched to Peer C (redundant link).
4. The exit node reconstructs the original packet as soon as any two shards arrive.

---

## 4. Replay Protection Window

Replay attacks are mitigated by `SessionGuardU64`, an atomic 64-bit sliding window bitmap:
- Packets with counters greater than the current window head advance the window.
- Packets inside the 64-bit window are checked against the bitmap and dropped if already received.
- Packets trailing behind the window boundary are immediately discarded.

---

## 5. Peer Discovery Protocols

- **Cloudflare DNS Seed Resolution:** The daemon issues standard DNS queries against designated hostnames (`GHOST_DNS_SEED`), extracting all associated `A` and `AAAA` records.
- **Local Cache Persistence:** Upon successful handshake, peer socket addresses are written to `peers.cache`. During cold boots without WAN access, the cache is read first.
- **Local Subnet Multicast:** LAN nodes announce themselves on `239.255.0.1:2270` using Ed25519-signed beacons containing timestamp, port, and public key. Unsigned or expired beacons are silently dropped.
