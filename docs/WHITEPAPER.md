# Vantablack (Vantablack)
## Post-Quantum WAN Mesh Routing Architecture
**Technical Specification — Version 0.4.0**

---

### Abstract

Vantablack is an autonomous, post-quantum WAN mesh routing daemon. Operating entirely peer-to-peer over UDP, nodes establish zero-trust, forward-secret tunnels that protect traffic against both mass surveillance and cryptographically relevant quantum computers. The architecture eliminates centralized coordinators, certificate authorities, and single points of infrastructure failure by combining hybrid post-quantum key exchange (X25519 + ML-KEM-768), Reed-Solomon asymmetric shard routing, anti-traffic-analysis jitter padding, 64-bit sliding window replay protection, and decentralized DNS seed discovery.

---

### 1. Architectural Principles

1. **Serverless Decentralization:** Every node operates simultaneously as a router and a relay. There is no central directory server.
2. **Post-Quantum Defense-in-Depth:** Key agreement combines classical elliptic-curve Diffie-Hellman (X25519) with lattice-based key encapsulation (ML-KEM-768 / FIPS 203) alongside optional pre-shared salt mixing.
3. **Traffic Morphing:** Frames are padded with variable pseudorandom jitter, rendering datagrams indistinguishable from uniform white noise to intermediate deep packet inspection (DPI) systems.
4. **Resilient Erasure Multipath:** Datagrams are sharded via Reed-Solomon RS(2,1) for path diversity and packet-loss resilience (any 2 of 3 shards reconstruct intact payloads). Datagram confidentiality on the wire is enforced by authenticated encryption (L2 AEAD / ShardSec per-shard keys).

---

### 2. GHOST Protocol Stack (L0–L9)

| Layer | Component | Implementation | Function |
|---|---|---|---|
| **L0** | Identity | Ed25519 | Cryptographic node identity and beacon signing |
| **L1** | Key Exchange | X25519 + ML-KEM-768 | Hybrid post-quantum key encapsulation with HKDF-SHA256 |
| **L2** | AEAD Transport | ChaCha20-Poly1305 | 256-bit encryption with directional session-bound nonces |
| **L3** | Secret Sharing | Shamir SSS (GF256) | Threshold key distribution and split recovery (2-of-3 threshold) |
| **L4** | Erasure Coding | Reed-Solomon RS(2,1) | Multi-path fragment dispersal & availability (any 2 of 3 shards reconstruct) |
| **L5** | Traffic Obfuscation | Jitter Padding | Randomized byte injection to eliminate length fingerprinting |
| **L6** | Replay Protection | SessionGuardU64 | 64-bit sliding window packet replay rejection |
| **L7** | Error Correction | LDPC | Forward error correction across high-loss links |
| **L8** | Memory Defense | AES-256-XTS | Cryptographic protection for RAM buffers and zeroing on drop |
| **L9** | Trust Enclave | TPM / HSM Support | Hardware-backed root-of-trust integration and NTS time sync |

---

### 3. Ghost Transport Frame (GTF) Specification

Packets in privacy mode are structured as follows:

```
+---------------+-------------------+---------------+-----------------------+
| Offset (Byte) | Field             | Size          | Description           |
+---------------+-------------------+---------------+-----------------------+
| 0 - 3         | Session Hash      | 4 Bytes       | Truncated session ID  |
| 4 - 7         | Packet Counter    | 4 Bytes       | Monotonic sequence    |
| 8             | Shard Index       | 1 Byte        | Shard position (0..2) |
| 9             | Flags             | 1 Byte        | Stream control flags  |
| 10 - 495      | Payload           | 486 Bytes     | Encrypted ciphertext  |
| 496 - 511     | Authentication Tag| 16 Bytes      | Poly1305 MAC tag      |
| 512+          | Jitter Padding    | 0 - 64 Bytes  | Pseudorandom noise    |
+---------------+-------------------+---------------+-----------------------+
```

---

### 4. Routing & Peer Discovery

1. **Cloudflare DNS Seeds:** Nodes query designated DNS hostnames (`GHOST_DNS_SEED`) resolving multiple `A`/`AAAA` records via standard DNS queries.
2. **Local Peer Cache:** Discovered operational nodes are committed to local disk (`peers.cache`). If bootstrap seeds are unreachable on subsequent boots, nodes resume routing directly from cached endpoints.
3. **Local Multicast Beacons:** On LAN environments, nodes broadcast cryptographically signed identity beacons on `239.255.0.1:2270`.
4. **NAT Traversal:** Simultaneous dual-side UDP hole punching enables direct peer-to-peer connectivity behind standard consumer NAT gateways.
5. **Contact Graph Routing (CGR):** Route selection dynamically scores candidate paths using a Poisson reputation model based on latency, jitter, and link reliability.

---

### 5. Application Proxying & Egress

Nodes feature an internal SOCKS5 proxy engine listening on `127.0.0.1:1080`:
- Outbound TCP connections initiated by client applications are encapsulated into GHOST transport frames.
- Payload streams are sharded across established peer paths to an authenticated Exit Node.
- The Exit Node reassembles the shards, executes the outbound connection to the target WAN destination, and shards the inbound response back across the mesh.

---

### 6. Level 2 Multi-Hop Carrier Mesh & Active Validation Scenarios

The architecture incorporates a 7-node carrier simulation topology (`vantablack-carrier-1..5`, `mesh-client`, `mesh-exit`) modeled under Linux kernel `tc netem` latency, jitter, and packet loss emulation. The deployment validates 4 continuous resilience invariants:

1. **Scenario 1 (Byzantine Tamper Resistance):** Pairwise combinatorial RS(2,1) testing against Poly1305 authentication tags isolates actively corrupted shards from compromised carriers without packet retransmission.
2. **Scenario 2 (Layer 6 Anti-Replay Defense):** The `SessionGuard` 64-bit sliding window bitmask detects and rejects duplicate clone transmissions and injected replay counters.
3. **Scenario 3 (Layer 5 Traffic Shaping & Analysis Resistance):** Canonical 512-byte GTF frames are padded with 16–64 bytes of cryptographically randomized jitter, defeating statistical traffic classification and deep packet inspection (DPI).
4. **Scenario 4 (Real-time Convergence Latency Measurement):** An autonomous Chaos Monkey periodically severs the high-latency satellite carrier (`Carrier 3`), triggering sub-55ms failover to hot-standby `Carrier 5` via the `AdaptiveShardRouter`.

---

### 7. Observability & Telemetry Surface

The protocol core embeds a real-time observability engine:
- **JSON Telemetry API:** Served at `/api/telemetry` detailing flight cycle metrics, carrier latency, Byzantine isolation events, and failover convergence.
- **Reactive Dashboard:** Served on port 8080 (`assets/wan_dashboard.html`), providing dynamic SVG carrier topology visualization, live status indicators, and security alert feeds.
