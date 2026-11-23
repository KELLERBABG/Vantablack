# Experimental Features

Vantablack includes several opt-in experimental mesh capabilities under **Settings -> Experimental**. All six are **off by default** so normal operation keeps minimal battery, CPU, and background-data overhead.

> **Daemon wiring status.** A toggle only means something if the packet path reads it. **All six are wired**: a flipped switch takes effect on the next handshake (1), the next unreachable peer (2), the next local TCP connect (3), the next beacon (4), the next bootstrap (5), and the next frame no route could carry (6). Each section below states the exact hook, the configuration it needs, and what stays inert until that configuration exists — several toggles deliberately do nothing without an operator-supplied list, because the alternative is a node that silently becomes a relay.

---

## 1. Flood Shield (`exp_pow_shield` / `ghost::net::pow`)
- **What it does:** Protects the node from handshake floods and Sybil connection storms by requiring new unauthenticated peers to solve a short cryptographic client puzzle before a session is allocated.
- **How it works:** Challenges bind `[server_salt (32 B) || peer_id (32 B) || timestamp (8 B) || difficulty (1 B)]` and expire after `DEFAULT_POW_TTL_SECS` (300 s). Verification is $O(1)$ on the receiver; the connecting client searches for a `u64` nonce whose `SHA-256` meets the leading-zero difficulty (`DEFAULT_POW_DIFFICULTY = 12`).
- **Wired:** the daemon sends a `POWS` token before a handshake when the toggle is on (`daemon::auth`), and refuses every handshake variant from a source without a redeemed token (`daemon::peer_loop`). The challenge is `SHA-256("GGN_POW_SHIELD_V1" ‖ mesh port ‖ 5-minute epoch)`, so it needs no round trip; `GHOST_POW_DIFFICULTY` (default 12, clamped 8–24) sets the cost. This is a **mesh-wide policy**: a node that requires tokens cannot be reached by a node that does not send them.
- **Overhead:** Zero on the data path; small CPU cost on the connecting client during initial handshake.

## 2. Offline Sync (`exp_dtn_reconcile` / `ghost::net::dtn_reconcile`)
- **What it does:** Automatically reconciles missed store-and-forward bundles when a peer reconnects after airplane mode, satellite gaps, or network blackouts.
- **How it works:** Peers exchange Merkle-tree root commitments over their buffered bundle histories (`MREC` frames) and isolate differences in $O(\log N)$ branch queries instead of re-sending already-delivered data.
- **Wired:** the daemon keeps a real per-peer bundle store (`daemon::dtn`): a `DtnMerkleTree` keyed by `SHA-256(peer ‖ payload)`, a delivered set, and pending work computed as `compute_missing_from(delivered)`. When `send_pex` finds no session it buffers the signed batch instead of dropping it, and a five-second loop (`daemon::dtn::flush_all`) delivers everything pending as soon as the peer has a session again, exactly once. Only self-contained, idempotent payloads are buffered — today the signed PEX v2 descriptor batch; a message with an effect is never replayed. Each peer queue holds at most 64 pending bundles, and the tree is compacted from the pending set once it passes twice that.
- **Overhead:** Zero while online; logarithmic hash exchange on reconnect.

## 3. App Port Tunnel (`exp_universal_tunnel` / `ghost::net::universal_tunnel`)
- **What it does:** Lets non-SOCKS5 applications (SSH, RDP, SMTP, custom TCP services) tunnel through the mesh using a local TCP port (`127.0.0.1:<port>`).
- **How it works:** Slices arbitrary TCP byte streams into sequenced, bounded chunks (`MAX_TUNNEL_PAYLOAD_CHUNK = 512` B) padded into 576-byte GTF privacy frames and reassembles them at the exit.
- **Wired:** with the toggle on, `daemon::tunnel::spawn` binds each `GHOST_TUNNEL_PORTS=local=target` entry (a bare port means `127.0.0.1:<port>`) and splices every accepted connection over the mesh to `GHOST_TUNNEL_EXIT` using `UTUN` envelopes sealed to that peer's session; the exit side reassembles and dials. Every `UTUN` frame names the **sender's role** for the stream (its own forward, or a stream it serves), because both endpoints number streams from their own counter — the role is what keeps one side's stream 7 from being read as the other's. **Both allowlists must be set**: `GHOST_TUNNEL_ALLOW` is the complete list of targets the exit will dial and `GHOST_TUNNEL_PEERS` the complete list of fingerprints allowed to ask. Either one empty leaves the exit role off, and admission is exact-match — no wildcards, no prefixes. Without `GHOST_TUNNEL_EXIT` no local port is published.
- **Overhead:** Zero unless a local port forward is active.

## 4. Shared Threat Signals (`exp_collective_defense` / `ghost::net::collective_defense`)
- **What it does:** Allows peers to share anonymous link-anomaly reports (packet-loss spikes, dropping relays, handshake failure bursts) so the mesh can route around degraded or hostile paths.
- **How it works:** Reports (`CDEF`) are bucketed by coarse region/ASN and 10-minute epoch slots, perturbed with differential-privacy noise, and suppressed below `K_ANONYMITY_THRESHOLD` (3).
- **Wired:** every beacon carries a 15-byte `CDEF` section while the toggle is on — a hashed /24 (or /48), the epoch, the discretized share of known peers this node holds no session with, and that count bucketed to fives. Receivers feed it into the aggregator (`daemon::experimental::note_observable`), which reports a region once the k-anonymity threshold is met. Nothing else about a peer leaves the node.
- **Overhead:** Negligible CPU/memory and tiny periodic metadata.

## 5. Serverless Discovery (`exp_rendezvous` / `ghost::net::rendezvous`)
- **What it does:** Discovers mesh peers without relying on centralized DNS, hardcoded VPS seeds, or fixed domains.
- **How it works:** Combines a 256-bit XOR Kademlia DHT routing table, deterministic dead-drop rendezvous slots, and decentralized Nostr relay presence beacons.
- **Wired:** with the toggle on, `daemon::rendezvous::sync` publishes the signed descriptor to 2 of 3 blind-mailbox slots chosen by rendezvous hashing over the node's fingerprint and queries all three, so any two nodes meet in at least one slot instead of every node sharing slot 0. Every descriptor accepted by the ordinary install path is also recorded in a `DhtRoutingTable` keyed by XOR distance from us, and when the tracker returns nothing `http_bootstrap` falls back to those contacts, closest first. Slot answers only ever contain signed descriptors, which are verified by the normal install path.
- **Overhead:** **Higher battery & background traffic** due to periodic DHT bucket refreshes and persistent relay connections. Recommended only when central/seed discovery is unavailable.

## 6. Emergency Broadcast (`exp_diffusion` / `ghost::net::diffusion` / `GHOST_DIFFUSION=1`)
- **What it does:** Keeps critical packets moving during severe network partitions or collapsed routing tables by flooding erasure-coded shards across nearby peers.
- **How it works:** Uses bounded epidemic gossip (`DIFF` frames) capped by `DEFAULT_MAX_DIFFUSION_HOPS` (4), `DEFAULT_DIFFUSION_FANOUT` (3), and duplicate-suppression caches to prevent broadcast storms.
- **Wired:** when `send3_adaptive` reports `Routed::Unroutable`, `socks` floods each carrier as a `DIFF` envelope sealed per neighbour (`daemon::diffusion::flood`). Receivers handle the envelope inside `RxContext::ingest` **before** any other interpretation: hop count and fanout come from the router, the seen cache suppresses duplicates and is pruned after 5 minutes, and a nested `DIFF` payload is dropped so a peer cannot multiply amplification. The seeder records its own id, so an echo is never forwarded twice. On the receiving end, an enclosed datagram addressed to a session this node holds is fed back into `ingest` from the peer's own address, not the forwarder's.
- **Overhead:** **High bandwidth amplification.** Intended strictly as an emergency fallback.
