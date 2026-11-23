# Experimental Features

Vantablack includes several opt-in experimental mesh capabilities under **Settings -> Experimental**. All six are **off by default** so normal operation keeps minimal battery, CPU, and background-data overhead.

---

## 1. Flood Shield (`exp_pow_shield` / `ghost::net::pow`)
- **What it does:** Protects the node from handshake floods and Sybil connection storms by requiring new unauthenticated peers to solve a short cryptographic client puzzle before a session is allocated.
- **How it works:** Challenges bind `[server_salt (32 B) || peer_id (32 B) || timestamp (8 B) || difficulty (1 B)]` and expire after `DEFAULT_POW_TTL_SECS` (300 s). Verification is $O(1)$ on the receiver; the connecting client searches for a `u64` nonce whose `SHA-256` meets the leading-zero difficulty (`DEFAULT_POW_DIFFICULTY = 12`).
- **Overhead:** Zero on the data path; small CPU cost on the connecting client during initial handshake.

## 2. Offline Sync (`exp_dtn_reconcile` / `ghost::net::dtn_reconcile`)
- **What it does:** Automatically reconciles missed store-and-forward bundles when a peer reconnects after airplane mode, satellite gaps, or network blackouts.
- **How it works:** Peers exchange Merkle-tree root commitments over their buffered bundle histories (`MREC` frames) and isolate differences in $O(\log N)$ branch queries instead of re-sending already-delivered data.
- **Overhead:** Zero while online; logarithmic hash exchange on reconnect.

## 3. App Port Tunnel (`exp_universal_tunnel` / `ghost::net::universal_tunnel`)
- **What it does:** Lets non-SOCKS5 applications (SSH, RDP, SMTP, custom TCP services) tunnel through the mesh using a local TCP port (`127.0.0.1:<port>`).
- **How it works:** Slices arbitrary TCP byte streams into sequenced, bounded chunks (`MAX_TUNNEL_PAYLOAD_CHUNK = 512` B) padded into 576-byte GTF privacy frames and reassembles them at the exit.
- **Overhead:** Zero unless a local port forward is active.

## 4. Shared Threat Signals (`exp_collective_defense` / `ghost::net::collective_defense`)
- **What it does:** Allows peers to share anonymous link-anomaly reports (packet-loss spikes, dropping relays, handshake failure bursts) so the mesh can route around degraded or hostile paths.
- **How it works:** Reports (`CDEF`) are bucketed by coarse region/ASN and 10-minute epoch slots, perturbed with differential-privacy noise, and suppressed below `K_ANONYMITY_THRESHOLD` (3).
- **Overhead:** Negligible CPU/memory and tiny periodic metadata.

## 5. Serverless Discovery (`exp_rendezvous` / `ghost::net::rendezvous`)
- **What it does:** Discovers mesh peers without relying on centralized DNS, hardcoded VPS seeds, or fixed domains.
- **How it works:** Combines a 256-bit XOR Kademlia DHT routing table, deterministic dead-drop rendezvous slots, and decentralized Nostr relay presence beacons.
- **Overhead:** **Higher battery & background traffic** due to periodic DHT bucket refreshes and persistent relay connections. Recommended only when central/seed discovery is unavailable.

## 6. Emergency Broadcast (`exp_diffusion` / `ghost::net::diffusion` / `GHOST_DIFFUSION=1`)
- **What it does:** Keeps critical packets moving during severe network partitions or collapsed routing tables by flooding erasure-coded shards across nearby peers.
- **How it works:** Uses bounded epidemic gossip (`DIFF` frames) capped by `DEFAULT_MAX_DIFFUSION_HOPS` (4), `DEFAULT_DIFFUSION_FANOUT` (3), and duplicate-suppression caches to prevent broadcast storms.
- **Overhead:** **High bandwidth amplification.** Intended strictly as an emergency fallback.
