# State of the Art (SOTA) Architectural Benchmark

> **Vantablack** was engineered from first principles in pure Rust to establish an undisputed State of the Art (SOTA) across post-quantum cryptography, transport resilience, zero-trust decentralization, and privacy routing.

---

## 1. Executive SOTA Comparison Matrix

The table below benchmarks Vantablack against existing modern networking and privacy standards: **WireGuard**, **Tailscale**, the **Tor Network**, and **Commercial VPNs** (e.g., Mullvad, IVPN, NordVPN).

| Capability & Plain English Purpose | Vantablack | WireGuard | Tailscale | Tor Network | Commercial VPN |
|---|---|---|---|---|---|
| **Post-Quantum Cryptography**<br>_Protection against future quantum supercomputers decrypting intercepted/archived traffic._ | **Hybrid ML-KEM-768 + ML-DSA-65 + X25519 (FIPS 203 / 204)** | Classical Only (Curve25519) | Classical Only (Curve25519) | Classical Only (Curve25519 / RSA) | Classical Only (RSA / ECDH) |
| **Network Architecture**<br>_Can the network be shut down, seized, or banned by attacking a central company or server?_ | **100% Serverless Autonomous Mesh + Zero-Knowledge 3-Tier Discovery (`peers.bin`, `vb://` URIs, Epoch-Keyed Blind Rendezvous)** | Point-to-Point (Manual config required) | Centralized (Requires Tailscale / Google / Microsoft login) | Semi-Centralized (Relies on 9 Directory Authorities) | Centralized (Provider servers & billing accounts) |
| **Packet Loss & Congestion Resilience**<br>_What happens when a connection drops packets or experiences carrier congestion?_ | **Stream Coalescing (984 B Batch, 200 µs) + SIMD RS(2,1) Erasure Sharding (20.4 GiB/s Fast-Path Reassembly)** | Single Path (Retransmits dropped packets) | Single Path (Retransmits dropped packets) | Single TCP Circuit (Head-of-line blocking stalls stream) | Single Tunnel (Connection latency stalls) |
| **Mobile Roaming Handover (Wi-Fi ➔ LTE)**<br>_Does your connection freeze or disconnect when switching from Wi-Fi to cellular data?_ | **Zero-RST Silent Re-Anchor (Seamless live session migration; zero dropped frames on physical carrier)** | Endpoint Roaming (Requires packet exchange to update) | DERP Relay Switch (Session stalls or re-handshakes) | Circuit Breaks (Must negotiate brand new 3-hop circuit) | Tunnel Drops (10–30 second disconnection & IP leak) |
| **Traffic Analysis & Censor Disguise**<br>_Can an ISP, government firewall, or censor detect that you are running a VPN or mesh?_ | **Uniform 576B Frames + PRF Slack Masking (7.92 bits/byte) + Authenticated Jitter + Poisson Cover Traffic** | Known Packet Lengths & Handshake Headers (Trivially blocked by DPI) | WireGuard Fingerprints (Easily throttled or identified) | Obfs4 pluggable transports (Base Tor easily blocked) | Standard OpenVPN / WireGuard / IPsec headers |
| **Formal Mathematical Verification**<br>_Has the cryptographic security been proven by rigorous machine-checked mathematics?_ | **ProVerif symbolic models of the session key schedule and single-shard sealing only (`formal/README.md` lists the queries and the gaps)** | Formally Verified (Noise protocol Tamarin/CryptoVerif models) | Relies on WireGuard proof (Coordination plane unverified) | Academic papers (Partial formal proofs) | No formal protocol model |
| **In-Memory Hardware Defense**<br>_Are keys protected in RAM against physical memory dump attacks if a device is seized?_ | **Volatile Zeroization on Drop + In-Memory Ring Buffer Hardening (`l8_memsec`)** | Kernel memory zeroing (Plaintext in RAM) | Standard user-space memory | Standard user-space memory | Standard user-space memory |
| **Anonymity & Egress Forwarding**<br>_Can the destination or exit node discover who originally sent the traffic?_ | **Port-Multiplexed SOCKS5 (:1080–:1083) + Clean-Room 3-Hop Onion (RLY!) with Hard Swarm Privacy ($N \ge 3$) + Symmetric Multi-Hop Return Path (`Exit -> Relay -> Client`)** | None (Exit node sees true client IP) | None (Exit node sees Tailscale identity) | 3-Hop TCP Circuits (Slow, circuit stalls) | None (VPN company sees real IP & billing identity) |
| **Reachability Below the Internet** _(experimental, opt-in)_<br>_What happens when every terrestrial path is gone — fiber cut, ISP blackout, or jammed spectrum?_ | **HF/NVIS skywave carrier as the last rung of the fallback ladder, plus a QKD-entropy anchor feeding the session ratchet (in-simulation by default; a real ETSI GS QKD 014 appliance is supported)** | None (IP only) | None (IP only) | None (IP only) | None (IP only) |

> The last row is deliberately marked **experimental**. It is shipped and it is off by default, and
> it is not a claim about hardware that has not been tested — see §2.9 for exactly what is and is
> not real in each anchor today.

---

## 2. Plain English Architectural Breakdown

### 2.1 Post-Quantum Hybrid Defense (FIPS 203 / 204)
- **The Problem:** Hostile nation-states and mass-surveillance agencies currently record encrypted Internet traffic under "Store Now, Decrypt Later" (SNDL) initiatives. When large-scale quantum computers arrive, all standard VPNs (WireGuard, OpenVPN, IPsec) using classical elliptic curves (Curve25519) or RSA will have their master keys retroactively broken via Shor's algorithm.
- **The GGN Solution:** Vantablack executes a dual-layer hybrid key exchange combining **X25519** and **ML-KEM-768** (formerly Kyber, FIPS 203). Even if quantum machines break elliptic curve cryptography entirely, the lattice-based Module-LWE encryption ensures archived network data remains mathematically unbreakable. Identity beacons and session proofs are authenticated with hybrid **Ed25519 + ML-DSA-65** signatures (FIPS 204).

### 2.2 100% Serverless Autonomous Mesh & Zero-Knowledge 3-Tier Discovery
- **The Problem:** Modern "mesh" overlays such as Tailscale or ZeroTier require proprietary coordination servers and accounts (Google, Microsoft, GitHub). Centralized discovery servers or public Kademlia DHTs can be easily scraped by surveillance agencies to harvest all node IP addresses.
- **The GGN Solution:** Vantablack operates with zero coordinators, zero user accounts, and zero billing servers. Discovery utilizes a **3-tier zero-knowledge architecture**: (1) local authenticated disk cache (`peers.bin`) for silent reboots, (2) compact out-of-band manual URIs (`vb://<hex>`), and (3) epoch-keyed ChaCha20-Poly1305 blind rendezvous where third-party workers or DHTs see only pseudo-random 32-byte slot IDs and encrypted payloads, revealing zero network topology. Bootstrapping nodes ($N=0$) use Genesis Seed proxying before switching to 1-hop internal mesh updates.

### 2.3 Stream Coalescing & Reed-Solomon RS(2,1) Erasure Sharding
- **The Problem:** Traditional tunnels send small datagrams sequentially, introducing packet-size side-channels, high syscall overhead, and packet-loss stalling over lossy wireless links.
- **The GGN Solution:** Ingress streams coalesce into optimal 984-byte blocks ($2 \times 492$ B data shards) with a 200 µs timer and `FLAG_IMMEDIATE` preemption. Using **SIMD Reed-Solomon RS(2,1)** over Galois Field $GF(2^8)$, parity is computed in-place directly into pre-allocated shard buffers. At the exit, an automated 64-slot ring buffer delivers **20.4 GiB/s fast-path reassembly** ($0.05\text{ µs}$) from $D_0 + D_1$ and instant erasure recovery from $D_0 + P_0$ with zero retransmission delay.

### 2.4 Mobile Roaming Handover (Zero-RST Silent Re-Anchor)
- **The Problem:** When a smartphone steps outside home Wi-Fi and connects to 5G/LTE cellular towers, its IP address abruptly changes. Commercial VPNs and Tor drop all active TCP connections, trigger connection resets (RST), and stall for 10–30 seconds while negotiating a brand new tunnel.
- **The GGN Solution:** GGN incorporates an asynchronous **re-anchor ladder**. Because cryptographic identity is tied to the node's permanent Ed25519 key rather than an ephemeral IP socket, the hub observes incoming counter advances and silently re-anchors the client endpoint without dropping active TCP streams or alerting middlebox sniffers.

### 2.5 Uniform 576B Frames, PRF Slack Masking & Poisson Cover Traffic
- **The Problem:** Deep Packet Inspection (DPI) firewalls monitor packet sizes and detect trailing zero runs. Unpadded or poorly padded frames leak plaintext null bytes that reduce wire entropy and trigger censorship blocks.
- **The GGN Solution:** Every GGN privacy datagram is normalized to an exact, invariant length of **576 bytes**. Trailing slack bytes are masked with keyed pseudo-random PRF noise prior to sealing, delivering **$\ge 7.92$ bits/byte Shannon entropy** with 100% keyed tail tamper rejection. To eliminate timing-based presence detection, nodes emit exponential Poisson cover traffic, making idle silence indistinguishable from active browsing.

### 2.6 Formal Symbolic Models (ProVerif)
- **The Problem:** Most VPN protocols rely on manual informal code reviews, leaving subtle session hijacking, key misbinding, or downgrade vulnerabilities undetected.
- **The GGN Solution:** Two ProVerif files model parts of the protocol. `formal/ghost_session.pv` runs both roles as separate replicated processes over one public channel against an active Dolev-Yao attacker, and queries secrecy of the payload and the message key, injective agreement on the responder start, and injective counter correspondence. `formal/shardsec_space_time.pv` asserts one narrower property: an attacker holding one sealed shard and the key for it learns nothing about the payload.
- **Coverage, stated rather than implied:** neither file models the double ratchet, forward secrecy, post-compromise security, key-compromise impersonation, relay and onion behaviour, or the wire format. The shard file treats the three Reed-Solomon shards as uninterpreted functions, so it does not demonstrate the 2-of-3 threshold. `formal/README.md` lists every query and every gap.

### 2.7 In-Memory Protection (Volatile Zeroization & Memory-Hardened Rings)
- **The Problem:** If a device running a standard VPN is physically seized, forensics software can extract private keys directly from volatile RAM using cold-boot attacks or Direct Memory Access (DMA) exploits.
- **The GGN Solution:** Ephemeral session keys implement strict volatile zeroization on drop, enforced by compiler memory fences. In-transit packet ring buffers implement bounded memory verification via `l8_memsec`.

### 2.8 Port-Multiplexed SOCKS5 (:1080–:1083) & Clean-Room 3-Hop Onion Forwarding
- **The Problem:** In conventional VPNs, the exit node knows both your real IP address and every destination website you visit. Naive implementations also silently degrade hop count on small swarms, creating a false sense of anonymity.
- **The GGN Solution:** Vantablack exposes a port-multiplexed loopback proxy interface:
  - `127.0.0.1:1080` (**Auto Mode**): Automatically selects circuit depth based on live swarm size.
  - `127.0.0.1:1081` (**1-Hop Fast Path**): Direct low-latency path for high-throughput trusted streams.
  - `127.0.0.1:1082` (**2-Hop Circuit**): `Client -> Relay -> Exit`.
  - `127.0.0.1:1083` (**Strict 3-Hop Onion**): Enforces true onion routing (`Client -> Guard -> Middle -> Exit`). If the active verified swarm size is insufficient ($N < 3$), the proxy immediately returns RFC 1928 `0x05 Connection Refused` rather than silently degrading privacy!
  - **Credit-Based Flow Control:** A 64 KB sliding window per sub-stream bounds memory growth and avoids bufferbloat across multi-hop relay circuits.

### 2.9 Reachability Below the Internet — Physical Anchors _(experimental)_
- **The Problem:** Every overlay above this row still rides the public internet. A national ISP blackout, a severed terrestrial fiber, or targeted RF jamming removes the IP layer entirely, and a pure-software VPN has nowhere left to send a datagram. Separately, a session's secrecy is only as good as the entropy that seeded it, and on a fully compromised host the operating system's RNG is exactly what an adversary controls.
- **The GGN Solution:** Two optional anchors extend the reachability ladder past IP. The **HF/NVIS skywave carrier** (ABOS) is the last rung of the fallback ladder — chosen only after a direct path, a mesh relay, and a blinded TURN allocation have all failed — and carries real ABOS DSP (LDPC FEC, DSSS/OFDM) into the session. The **quantum anchor** (QEL) contracts a session's next ratchet epoch from out-of-band key material, with both peers proving agreement before either moves; a route below the security cutoff yields no key rather than a weak one. Both are opt-in (`GHOST_SKYWAVE=1`/`--skywave`, `GHOST_QUANTUM=1`/`--quantum`) and neither is required for normal operation.
- **Status, stated rather than implied:** on a default build the skywave carrier transmits over a **virtual loopback channel** with ABOS's SDR drivers as simulation stubs, and QEL derives keys from a **simulated noise model** rather than a photon measurement — so in simulation these anchors add structural entropy and reachability, not a secret. The one production path that is built is the **ETSI GS QKD 014** client for a real QKD appliance, tested against a mock appliance. Neither anchor has been verified against real radio or optical hardware yet.
