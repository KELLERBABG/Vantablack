//! Vantablack Daemon and Desktop Application Entrypoint.
//!
//! Orchestrates the runtime of a Global Ghost Net (GGN) node, bootstrapping
//! cryptographic identities, peer discovery, mesh networking, SOCKS5 proxy,
//! control center REST API, and native desktop UI / system tray integration.

#![cfg_attr(all(windows, feature = "webview"), windows_subsystem = "windows")]

use rand::RngCore;
use std::collections::BTreeMap;
#[cfg(feature = "quic")]
use std::net::IpAddr;
use std::net::SocketAddr;
use std::path::PathBuf;
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

const GHOST_PEX_MAGIC: &[u8] = b"GHOST_PEX_____";
const GHOST_PEX_V2_MAGIC: &[u8] = b"GHOST_PEX2____";
const GHOST_BTCR_GOSSIP_MAGIC: &[u8] = b"GHOST_BTCR____";
const GHOST_FLEET_REVOKE_MAGIC: &[u8] = b"GHOST_REVOKE__";
const GHOST_CENSUS_MAGIC: &[u8] = b"GHOST_CENSUS__";
pub(crate) const GHOST_BYE_MAGIC: &[u8] = b"GHOST_BYE_____";
const MAX_PEX_PEERS: usize = 32;

const EMBEDDED_SEEDS: &[&str] = &[];

const DEFAULT_BOOTSTRAP_URL: &str = "https://red-star-512e.papababg02.workers.dev/peers?port=55225";

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
        webview::run_desktop(control_port, node);
    }

    run_daemon(false, None)
}
