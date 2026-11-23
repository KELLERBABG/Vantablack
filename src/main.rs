//! Vantablack Daemon and Desktop Application Entrypoint.
//!
//! Orchestrates the runtime of a Global Ghost Net (GGN) node, bootstrapping
//! cryptographic identities, peer discovery, mesh networking, SOCKS5 proxy,
//! control center REST API, and native desktop UI / system tray integration.

// The desktop build is a GUI application, so on Windows it must not spawn a
// console window next to the app. Diagnostics are not lost: the log writer
// below mirrors every line into ghost.log.
#![cfg_attr(all(windows, feature = "webview"), windows_subsystem = "windows")]

use rand::RngCore;
use std::collections::BTreeMap;
use std::net::SocketAddr;
// Named by the mesh topology export (a path the operator may override).
use std::path::PathBuf;
// Only the optional-transport paths name a local address (multipath, B23), so the
// type is imported where it is used rather than in every build.
#[cfg(feature = "quic")]
use std::net::IpAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use dashmap::{DashMap, DashSet};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot};
use tokio::time::sleep;

use ml_kem::kem::Decapsulate;
use ml_kem::{Ciphertext, DecapsulationKey512, DecapsulationKey768, KeyExport, MlKem512};
mod cli;
mod control;
mod daemon;
mod socks;
use daemon::auth::*;
use daemon::beacon::*;
use daemon::cover::*;
use daemon::discovery::*;
use daemon::framing::*;
use daemon::ingress::*;
use daemon::node::*;
use daemon::peer_loop::*;
use daemon::ratchet::*;
use daemon::relay_fallback::*;
#[cfg(all(feature = "tray", not(feature = "webview")))]
mod tray;
mod vpn;
#[cfg(feature = "webview")]
mod webview;
use control::{consumer_config_path, control_port_from_env, load_consumer_settings};
use vantablack::ghost::{
    layers::l10_qel::{self, QuantumAnchorController},
    layers::{
        l0_identity,
        l1_kem::{
            build_negotiated_handshake_pdu, build_negotiated_response_pdu, build_response_pdu,
            build_response_pdu_suite, build_uniform_handshake_pdu, build_uniform_response_pdu,
            derive_hybrid_master_key_with_psk, derive_hybrid_master_key_with_suite,
            derive_hybrid_master_key_with_transcript, generate_kyber768_keypair,
            generate_kyber_keypair, generate_x25519_keypair, kyber768_decapsulate,
            kyber768_encapsulate, kyber_encapsulate, negotiate_cipher_suite,
            negotiated_response_len, parse_handshake_pdu, parse_handshake_pdu_suite,
            parse_negotiated_handshake_pdu, parse_negotiated_response_pdu, parse_response_pdu,
            parse_response_pdu_suite, parse_uniform_handshake_pdu, parse_uniform_response_pdu,
            uniform_handshake_signed_material, uniform_response_signed_material, HybridCipherSuite,
            HANDSHAKE_BLOB_LEN, HANDSHAKE_NEGOTIATION_MAGIC, HANDSHAKE_V3_MAGIC, RESPONSE_BLOB_LEN,
            RESPONSE_NEGOTIATION_MAGIC, RESPONSE_V3_MAGIC,
        },
        l2_aead::{
            decrypt_in_place_with_context, random_xnonce, xchacha_open, xchacha_open_with_aad,
            xchacha_seal_in_place, xchacha_seal_in_place_with_aad, NonceDirection,
        },
        l4_rs,
        l7_ldpc::LdpcCodec,
        l8_memsec::VerifiedRingBuffer,
    },
    net::{
        self,
        consumer::ConsumerSettings,
        fallback::{self, Fallback, FallbackPath, TurnPath},
        frame_shard,
        mesh::{ExitIpRotator, TitForTatEnforcer},
        relay::{
            self, build_onion_route, build_relay_packet, parse_relay_header,
            spawn_store_forward_task, BundleBuffer, DerpRelay, MixBatch,
        },
        routing::{ContactPlan, PoissonReputationMatrix},
        security::{
            LockedMemory, RevocationList, RevocationReason, ZkAuthenticator, ZK_CONTEXT_LEN,
            ZK_PROOF_LEN,
        },
        send_gtf, unframe, upnp, BEACON_MULTICAST_ADDR, BEACON_PORT, BEACON_PREFIX, GTF_BULK_SIZE,
    },
    session::{
        build_qel_mix_pdu, build_qel_mix_response_pdu, build_ratchet_step_pdu,
        build_rekey_response_pdu, parse_qel_mix_pdu, parse_qel_mix_response_pdu, parse_rekey_pdu,
        parse_rekey_response_pdu, qel_mix_response_signed_material, qel_mix_signed_material,
        rekey_answer_signed_material, rekey_init_signed_material, RatchetAnswer, Session,
        SessionRole, QEL_MIX_MAGIC, QEL_MIX_RESPONSE_MAGIC, REKEY_MAGIC, REKEY_RESPONSE_MAGIC,
    },
    GhostNode,
};
#[cfg(feature = "vpn")]
use vpn::{hub::VPN_PAYLOAD_MAGIC, tun::TunDevice};
use vpn::{init_vpn_mode_with_rotator, VpnMode};

/// Peer Exchange gossip frame magic — encrypted payload prefix.
const GHOST_PEX_MAGIC: &[u8] = b"GHOST_PEX_____";
/// Peer Exchange v2 gossip frame magic — batches of signed `PeerDescriptorV2`.
const GHOST_PEX_V2_MAGIC: &[u8] = b"GHOST_PEX2____";
const GHOST_BTCR_GOSSIP_MAGIC: &[u8] = b"GHOST_BTCR____";
const GHOST_FLEET_REVOKE_MAGIC: &[u8] = b"GHOST_REVOKE__";
/// Authenticated goodbye / reroute control notification sent when a node
/// disconnects or deactivates the mesh.
pub(crate) const GHOST_BYE_MAGIC: &[u8] = b"GHOST_BYE_____";
/// Maximum peers to advertise per PEX message.
const MAX_PEX_PEERS: usize = 32;

/// Embedded bootstrap seeds (public VPS rendezvous nodes). Override at runtime
/// via `GHOST_SEEDS=ip:port,ip:port,...`. When empty and no env var is set,
/// the node starts in listen-only mode (beacon + accept incoming handshakes).
const EMBEDDED_SEEDS: &[&str] = &[];

/// Cloudflare Worker bootstrap URL. Every node hits this on startup to
/// register its public address and learn about other active nodes.
/// Override with GHOST_BOOTSTRAP_URL env var.
const DEFAULT_BOOTSTRAP_URL: &str = "https://red-star-512e.papababg02.workers.dev/peers?port=55225";

// ── SOCKS5 mesh tunneling (initiator ⇄ exit) ───────────────────────
//
// Wire protocol (all data frames are length-prefixed via enc_split):
//   initiator → exit   ctr = session tx counter   payload "host:port"  (SOCKS5 CONNECT)
//   exit      → init   ctr = exit's tx counter    payload "OK"
//   initiator → exit   ctr = connect_ctr+1, +2…   relayed client bytes
//   exit      → init   ctr = ok_ctr+1, +2…        relayed remote bytes
//
// Nonces are direction-bound (NonceDirection) so the two directions
// never reuse a (key, nonce) pair even at equal counters. Each side
// re-orders out-of-order UDP frames before delivery.
//
// Known limitation: tunnel relays use their own counter space, so a
// keepalive firing while a tunnel is idle >60s could collide counters
// within one direction. Active tunnels reset the idle timer, so this
// cannot happen during live traffic.

// ── Post-Quantum In-Band Authentication ───────────────────

// ═══════════════════════════════════════════════════════════════════
// CONSUMER CONTROL PLANE HELPERS
// ═══════════════════════════════════════════════════════════════════

/// Writes every log line to stderr *and* to `ghost.log`.
///
/// The desktop build runs as a Windows GUI-subsystem process, which has no
/// console attached, so without the file mirror a user could not report what
/// went wrong. `GHOST_LOG=off` disables the mirror; `GHOST_LOG=<path>` moves it.
#[cfg(feature = "webview")]
#[derive(Clone)]
struct TeeWriter {
    file: Option<Arc<std::sync::Mutex<std::fs::File>>>,
}

#[cfg(feature = "webview")]
struct TeeGuard<'a> {
    file: Option<std::sync::MutexGuard<'a, std::fs::File>>,
}

#[cfg(feature = "webview")]
impl std::io::Write for TeeGuard<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let written = std::io::Write::write(&mut std::io::stderr(), buf)?;
        if let Some(file) = self.file.as_mut() {
            let _ = file.write_all(buf);
        }
        Ok(written)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        let _ = std::io::Write::flush(&mut std::io::stderr());
        if let Some(file) = self.file.as_mut() {
            let _ = file.flush();
        }
        Ok(())
    }
}

#[cfg(feature = "webview")]
impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for TeeWriter {
    type Writer = TeeGuard<'a>;

    fn make_writer(&'a self) -> Self::Writer {
        TeeGuard {
            file: self.file.as_ref().and_then(|f| f.lock().ok()),
        }
    }
}

/// True when this process should present a native desktop window. Headless
/// builds (`--no-default-features`) and `GHOST_NO_GUI=1` fall back to the HTTP
/// control center, which is the server/sidenote path.
#[cfg_attr(not(feature = "webview"), allow(dead_code))]
fn gui_enabled() -> bool {
    if !cfg!(feature = "webview") {
        return false;
    }
    std::env::var("GHOST_NO_GUI")
        .map(|v| v != "1" && !v.eq_ignore_ascii_case("true"))
        .unwrap_or(true)
}

fn main() -> anyhow::Result<()> {
    if let Some(res) = cli::handle_cli_args() {
        return res;
    }
    // The desktop window owns the main thread: tao refuses to build an
    // EventLoop anywhere else on Windows, and macOS requires the main thread.
    // The node therefore runs on its own thread and hands its handle back so
    // the tray menu can read and toggle node state.
    #[cfg(feature = "webview")]
    if gui_enabled() {
        let control_port = control_port_from_env();
        let (node_tx, node_rx) = std::sync::mpsc::channel::<Arc<GhostNode>>();
        std::thread::Builder::new()
            .name("ggn-node".to_string())
            .spawn(move || {
                if let Err(e) = run_daemon(true, Some(node_tx)) {
                    tracing::error!("Node stopped: {e:#}");
                }
            })?;
        let node = match node_rx.recv_timeout(Duration::from_secs(15)) {
            Ok(node) => Some(node),
            Err(_) => {
                tracing::warn!("Desktop window starting before the node reported readiness");
                None
            }
        };
        // `run_desktop` never returns; control leaves through `process::exit`.
        webview::run_desktop(control_port, node);
    }

    // Headless / server: no window at all, the HTTP control center is the UI.
    run_daemon(false, None)
}
