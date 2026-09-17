//! Phase 1 gate: QUIC as an optional transport (SOTA P1-2).
//!
//! The claim under test is not "QUIC works" — that is quinn's claim. It is that
//! *this* transport carries GTF frames unchanged, picks the right framing by
//! size, and refuses a peer whose identity it cannot prove over the session.
//!
//! The identity question is the one worth a test. The certificate is
//! self-signed, so a peer cannot be trusted by its certificate; what is checked
//! instead is that the signature binds the Ed25519 identity to *this* TLS
//! session's keying material. A wrong fingerprint must be refused, and a
//! signature made over a different session must fail — otherwise accepting a
//! self-signed certificate would be a hole rather than a shortcut.
#![cfg(feature = "quic")]

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;

use vantablack::ghost::layers::l0_identity::GhostIdentity;
use vantablack::ghost::net::carrier::Carrier;
use tokio::sync::mpsc;
use vantablack::ghost::net::quic::{FramePath, QuicError, QuicLink, QuicTransport};

fn identities() -> (Arc<GhostIdentity>, Arc<GhostIdentity>) {
    (
        Arc::new(GhostIdentity::generate_fresh()),
        Arc::new(GhostIdentity::generate_fresh()),
    )
}

/// A frame the privacy path would send: small enough to ride a datagram.
const RS_FRAME: &[u8] = b"GTF\x01privacy-shard-1-of-2-with-tag";

/// Await `f` for at most `secs`, naming what was being awaited when it does not
/// finish. A test that hangs tells you nothing; one that fails tells you which
/// step of the sequence stalled.
async fn within<F>(secs: u64, f: F, what: &str) -> F::Output
where
    F: std::future::Future,
{
    tokio::time::timeout(Duration::from_secs(secs), f)
        .await
        .unwrap_or_else(|_| panic!("{what} did not complete within {secs}s"))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_frame_crosses_intact_and_the_identity_is_proven() {
    let (server_id, client_id) = identities();
    let server = QuicTransport::listen("127.0.0.1:0".parse().unwrap(), Arc::clone(&server_id))
        .expect("listen");
    let addr = server.local_addr().expect("a bound port");
    let client_fp = client_id.fingerprint();

    let accept = tokio::spawn({
        let server = Arc::new(server);
        async move {
            // Admission is the mesh's decision, not TLS's: only an identity we
            // already know may open a session on this port.
            server
                .accept_one(move |fp| fp == client_fp)
                .await
                .expect("accept")
        }
    });

    let client = QuicTransport::client(Arc::clone(&client_id)).expect("client endpoint");
    let link = client
        .connect(addr, &server_id.fingerprint())
        .await
        .expect("connect");
    let peer = accept.await.expect("accept task");

    assert_eq!(link.peer_fingerprint(), server_id.fingerprint());
    assert_eq!(peer.peer_fingerprint(), client_id.fingerprint());
    assert!(
        link.max_datagram() > 0,
        "the session must expose a datagram size, not 0"
    );

    // The privacy path's frame goes as one datagram and arrives byte-identical.
    assert_eq!(
        link.send_frame(RS_FRAME).await.expect("send"),
        FramePath::Datagram
    );
    let got = tokio::time::timeout(Duration::from_secs(5), peer.recv_frame())
        .await
        .expect("a frame within the timeout")
        .expect("the link is open");
    assert_eq!(got, RS_FRAME, "the frame must not be altered in flight");
    let (ds, _dr, _ss, _sr, dropped, sent_bytes, _recv) = link.stats().snapshot();
    assert_eq!(ds, 1);
    assert_eq!(dropped, 0, "nothing may be dropped on a loopback idle link");
    assert_eq!(sent_bytes, RS_FRAME.len() as u64);

    // A bulk frame at 1472 bytes cannot fit a datagram, so it must take a stream
    // and still arrive whole — this is the split the transport promises.
    let bulk = vec![0xABu8; 1472];
    assert_eq!(
        link.send_frame(&bulk).await.expect("send bulk"),
        FramePath::Stream,
        "a frame larger than the datagram limit must not be truncated into one"
    );
    let got = tokio::time::timeout(Duration::from_secs(5), peer.recv_frame())
        .await
        .expect("the bulk frame within the timeout")
        .expect("the link is open");
    assert_eq!(got, bulk);
    let (_ds, _dr, ss, sr, _, _, _) = link.stats().snapshot();
    assert_eq!(ss, 1);
    assert_eq!(peer.stats().snapshot().3, sr.max(1));

    link.close();
    peer.close();
    client.close();
}

/// The registry is what the live tunnel consults on every frame, so its two
/// answers are what matter: send on a link when one exists, and say nothing when
/// none does. "Says nothing" must be the answer for an unknown peer, for a link
/// that has closed, and for a node running without the transport at all — each of
/// those keeps the tunnel on the path it already had.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_registry_carries_frames_only_for_peers_it_has_a_link_to() {
    let (server_id, client_id) = identities();
    let server = QuicTransport::listen("127.0.0.1:0".parse().unwrap(), Arc::clone(&server_id))
        .expect("listen");
    let addr = server.local_addr().expect("a bound port");
    let server_fp = server_id.fingerprint();

    let accept = tokio::spawn({
        let server = Arc::new(server);
        async move { server.accept_one(|_| true).await.expect("accept") }
    });

    let client_transport = Arc::new(QuicTransport::client(Arc::clone(&client_id)).expect("client"));
    let link = client_transport
        .connect(addr, &server_fp)
        .await
        .expect("connect");
    let peer = accept.await.expect("accept task");

    // The dialling side's registry, exactly as the tunnel holds it.
    let registry = Carrier::new(Arc::clone(&client_transport));
    assert!(registry.enabled());
    assert_eq!(registry.label(), "quic");
    assert_eq!(registry.peer_count(), 0);
    // Before any link is registered there is nothing to send on, and that is not
    // an error: the caller keeps to UDP.
    assert!(registry.send_frame(&server_fp, b"early").await.is_none());

    registry
        .register(server_fp.clone(), Arc::clone(&link))
        .expect("the first link for this peer pins its post-quantum key");
    assert_eq!(registry.peer_count(), 1);
    let frame = b"GTF\x01registry-carried";
    assert_eq!(
        registry.send_frame(&server_fp, frame).await,
        Some(FramePath::Datagram)
    );
    let got = tokio::time::timeout(Duration::from_secs(5), peer.recv_frame())
        .await
        .expect("a frame within the timeout")
        .expect("the link is open");
    assert_eq!(
        got, frame,
        "the registry must deliver the frame it was given"
    );

    // An unknown fingerprint never reaches a link.
    assert!(registry.send_frame("nobody", frame).await.is_none());

    // A link that has closed is evicted on lookup rather than handed back, so the
    // tunnel cannot keep preferring a carrier that is gone.
    link.close();
    assert!(registry.send_frame(&server_fp, frame).await.is_none());
    assert_eq!(registry.peer_count(), 0, "a closed link must be evicted");

    // A node running without the transport answers the same way.
    let disabled = Carrier::disabled();
    assert!(!disabled.enabled());
    assert_eq!(disabled.label(), "none");
    assert!(disabled.send_frame(&server_fp, frame).await.is_none());
    assert_eq!(disabled.send_shards(&server_fp, &[frame.to_vec()]).await, 0);
    assert!(!disabled.covered(&server_fp));

    client_transport.close();
}

/// P2-1: the peer's post-quantum key is **pinned**, and a different one for the
/// same fingerprint is refused.
///
/// The two servers here share a classical seed, so they present the *same*
/// fingerprint — no verifier can tell them apart by identity — and differ only in
/// their ML-DSA key. That is precisely the position a forger is in once a quantum
/// computer has given them the classical private key: they can reproduce the
/// fingerprint and sign anything, and the hybrid binding will happily accept their
/// own post-quantum key because it only proves that their two keys belong to each
/// other. The pin — the commitment remembered from the first session — is what
/// refuses the second.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_peer_that_changes_its_post_quantum_key_is_refused() {
    // Two identities from one classical seed: writing each as a v1 (32-byte)
    // identity file and loading it upgrades it to the hybrid format with a fresh,
    // independent ML-DSA key, which is exactly what an operator's re-key would
    // look like from the outside.
    let dir = std::env::temp_dir().join(format!("ggn-pq-pin-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    let seed = [9u8; 32];
    let path_a = dir.join("a.key").to_string_lossy().into_owned();
    let path_b = dir.join("b.key").to_string_lossy().into_owned();
    std::fs::write(&path_a, seed).expect("write v1 identity a");
    std::fs::write(&path_b, seed).expect("write v1 identity b");
    let server_a_id = Arc::new(GhostIdentity::load_or_generate(&path_a));
    let server_b_id = Arc::new(GhostIdentity::load_or_generate(&path_b));
    assert_eq!(
        server_a_id.fingerprint(),
        server_b_id.fingerprint(),
        "the fixture must share a classical identity, or it proves nothing"
    );
    assert_ne!(
        server_a_id.pq_public_key_bytes(),
        server_b_id.pq_public_key_bytes()
    );

    let (client_id, _) = identities();
    let server_a = Arc::new(
        QuicTransport::listen("127.0.0.1:0".parse().unwrap(), Arc::clone(&server_a_id))
            .expect("listen a"),
    );
    let server_b = Arc::new(
        QuicTransport::listen("127.0.0.1:0".parse().unwrap(), Arc::clone(&server_b_id))
            .expect("listen b"),
    );
    let addr_a = server_a.local_addr().expect("a bound port");
    let addr_b = server_b.local_addr().expect("a bound port");
    let expected = server_a_id.fingerprint();

    let accept_a = tokio::spawn({
        let server = Arc::clone(&server_a);
        async move { server.accept_one(|_| true).await.expect("accept a") }
    });
    let accept_b = tokio::spawn({
        let server = Arc::clone(&server_b);
        async move { server.accept_one(|_| true).await.expect("accept b") }
    });

    let client = Arc::new(QuicTransport::client(Arc::clone(&client_id)).expect("client"));
    let link_a = within(
        10,
        client.connect(addr_a, &expected),
        "the first handshake",
    )
    .await
    .expect("link a");
    let _peer_a = within(10, accept_a, "the first accept")
        .await
        .expect("accept task");
    let link_b = within(
        10,
        client.connect(addr_b, &expected),
        "the second handshake",
    )
    .await
    .expect("link b");
    let _peer_b = within(10, accept_b, "the second accept")
        .await
        .expect("accept task");

    // Both handshakes succeeded: identity-wise the two servers are
    // indistinguishable, which is the point.
    assert_eq!(link_a.peer_fingerprint(), expected);
    assert_eq!(link_b.peer_fingerprint(), expected);
    assert_ne!(
        link_a.peer_pq_commitment(),
        link_b.peer_pq_commitment(),
        "the two sessions proved different post-quantum keys"
    );

    let registry = Carrier::new(Arc::clone(&client));
    // First sight pins the post-quantum key.
    assert!(registry.register(expected.clone(), Arc::clone(&link_a)).is_ok());
    let pinned = vantablack::ghost::layers::l0_identity::pq_commitment(
        &server_a_id.pq_public_key_bytes(),
    );
    assert_eq!(registry.pinned_commitment(&expected), Some(pinned));
    assert_eq!(registry.peer_count(), 1);

    // A second link for the same fingerprint presenting a different PQ key is
    // refused, not registered, and the pin is unchanged.
    let err = registry
        .register(expected.clone(), Arc::clone(&link_b))
        .expect_err("a changed post-quantum key must be refused");
    assert_eq!(err.pinned, pinned);
    assert_eq!(err.presented, link_b.peer_pq_commitment());
    assert_eq!(registry.pinned_commitment(&expected), Some(pinned));
    assert_eq!(registry.link_count(), 1, "the refused link was not registered");
    assert!(link_b.is_closed(), "the refused link is closed, not left open");

    // A *beacon* naming a different commitment does not move the pin either.
    registry.pin_commitment(&expected, [0xAB; 32]);
    assert_eq!(registry.pinned_commitment(&expected), Some(pinned));

    link_a.close();
    client.close();
    server_a.close();
    server_b.close();
    let _ = std::fs::remove_file(&path_a);
    let _ = std::fs::remove_file(&path_b);
    let _ = std::fs::remove_dir(&dir);
}

/// B23: a host with two local addresses keeps **two links to one peer** and puts
/// one Reed-Solomon shard on each before any path carries a second.
///
/// This is the whole claim of multipath-QUIC, and it is a registry claim rather
/// than a QUIC one: quinn will not migrate a connection between interfaces, so
/// what makes two paths is two endpoints bound to two local addresses, two
/// sessions, and a key that can tell them apart. The two loopback addresses stand
/// in for Wi-Fi and LTE — the address is the only difference that matters here.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn two_local_paths_to_one_peer_carry_a_shard_each() {
    let (server_id, client_id) = identities();
    let server = Arc::new(
        QuicTransport::listen("127.0.0.1:0".parse().unwrap(), Arc::clone(&server_id))
            .expect("listen"),
    );
    let addr = server.local_addr().expect("a bound port");
    let server_fp = server_id.fingerprint();

    // The server accepts two sessions from the same peer. Their local address is
    // the one it listened on — the *destination* the peer dialled — so the two are
    // told apart on that side by where each arrived from, which is the peer's two
    // source addresses.
    // One accept loop, the way the node runs it (`spawn_carrier_tasks` has a single
    // ingress task, not one per session). Each accepted session is handed back over
    // a channel so the test can tell which peer address it arrived from.
    let (tx, mut rx) = mpsc::channel::<Arc<QuicLink>>(8);
    let accept_loop = tokio::spawn({
        let server = Arc::clone(&server);
        async move {
            for _ in 0..3 {
                let link = server.accept_one(|_| true).await.expect("accept");
                if tx.send(link).await.is_err() {
                    return;
                }
            }
        }
    });

    // Two client endpoints, each bound to a named local address: this is exactly
    // how multipath is configured (`GHOST_QUIC_LOCAL_ADDRS`), and binding is what
    // makes the path knowable — a wildcard endpoint's source is the kernel's choice
    // and a client connection may not report it at all.
    let wifi = Arc::new(
        QuicTransport::client_bound("127.0.0.1:0".parse().unwrap(), Arc::clone(&client_id))
            .expect("wifi endpoint"),
    );
    let lte = Arc::new(
        QuicTransport::client_bound("127.0.0.2:0".parse().unwrap(), Arc::clone(&client_id))
            .expect("lte endpoint"),
    );
    // Every await here is bounded: a handshake that never completes is a bug in
    // this test or in the transport, and either way it should name itself rather
    // than hang the suite.
    let link_wifi = within(10, wifi.connect(addr, &server_fp), "the wifi handshake")
        .await
        .expect("wifi link");
    let link_lte = within(10, lte.connect(addr, &server_fp), "the LTE handshake")
        .await
        .expect("lte link");
    let peer_a = within(10, rx.recv(), "the wifi session being accepted")
        .await
        .expect("an accepted session");
    let peer_b = within(10, rx.recv(), "the LTE session being accepted")
        .await
        .expect("an accepted session");

    // Both links must name the local address they send from, or the registry has
    // nothing to key the second path on.
    assert_eq!(link_wifi.local_addr(), IpAddr::V4(Ipv4Addr::LOCALHOST));
    assert_eq!(link_lte.local_addr(), IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)));

    let registry = Carrier::new(Arc::clone(&wifi));
    registry
        .register(server_fp.clone(), Arc::clone(&link_wifi))
        .expect("the first link registers");
    registry
        .register(server_fp.clone(), Arc::clone(&link_lte))
        .expect("a second path to the same peer registers");
    assert_eq!(registry.link_count(), 2, "two paths, two links");
    assert_eq!(registry.peer_count(), 1, "but still one peer");
    assert_eq!(registry.links(&server_fp).len(), 2);
    assert!(registry.link(&server_fp).is_some(), "the single-path answer");

    // Three shards, each carrying its index in byte 8 so the receiving session can
    // say which path it travelled. Spread as evenly as two paths allow: 0 and 2 on
    // the lowest local address, 1 on the other.
    let shards: Vec<Vec<u8>> = (0..3u8)
        .map(|i| {
            let mut f = vec![0u8; 64];
            f[8] = i;
            f
        })
        .collect();
    assert_eq!(registry.send_shards(&server_fp, &shards).await, 3);

    // Which accepted session is which, by the address the peer connected from.
    let from_wifi = peer_a.remote_address().ip() == IpAddr::V4(Ipv4Addr::LOCALHOST);
    let (over_wifi, over_lte) = if from_wifi { (&peer_a, &peer_b) } else { (&peer_b, &peer_a) };
    assert_eq!(over_lte.remote_address().ip(), IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)));

    let mut saw_wifi = Vec::new();
    for _ in 0..2 {
        let got = tokio::time::timeout(Duration::from_secs(5), over_wifi.recv_frame())
            .await
            .expect("two shards within the timeout")
            .expect("the link is open");
        saw_wifi.push(got[8]);
    }
    let got = tokio::time::timeout(Duration::from_secs(5), over_lte.recv_frame())
        .await
        .expect("the third shard within the timeout")
        .expect("the link is open");
    assert_eq!(saw_wifi, vec![0, 2], "the lowest path carried shards 0 and 2");
    assert_eq!(got[8], 1, "the other path carried shard 1, not a copy of 0");

    // A closed path is evicted on its own, and the peer keeps the other one: two
    // links to one peer must not share a fate.
    link_lte.close();
    assert_eq!(registry.links(&server_fp).len(), 1, "the dead path is evicted");
    assert_eq!(registry.link_count(), 1);
    assert_eq!(registry.peer_count(), 1, "the peer keeps its live path");
    assert!(
        registry
            .link_on(&server_fp, IpAddr::V4(Ipv4Addr::LOCALHOST))
            .is_some(),
        "the surviving link is the one on the live path"
    );

    // A second link on an address we already carry is *the same path*, not a
    // third one: sending a shard on each would put two shards of a (2,1) code on
    // one wire while claiming dispersal. The new link displaces the old.
    let wifi_again = Arc::new(
        QuicTransport::client_bound("127.0.0.1:0".parse().unwrap(), Arc::clone(&client_id))
            .expect("endpoint"),
    );
    let duplicate = within(10, wifi_again.connect(addr, &server_fp), "the duplicate handshake")
        .await
        .expect("connect");
    let _peer_c = within(10, rx.recv(), "the duplicate session being accepted")
        .await
        .expect("an accepted session");
    assert_eq!(duplicate.local_addr(), IpAddr::V4(Ipv4Addr::LOCALHOST));
    let displaced = registry
        .register(server_fp.clone(), Arc::clone(&duplicate))
        .expect("the same post-quantum key is not a mismatch")
        .expect("the link on that address is displaced");
    assert!(Arc::ptr_eq(&displaced, &link_wifi));
    assert_eq!(registry.links(&server_fp).len(), 1, "still one path");

    link_wifi.close();
    duplicate.close();
    wifi.close();
    wifi_again.close();
    lte.close();
    server.close();
    accept_loop.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_connection_to_the_wrong_identity_is_refused() {
    let (server_id, client_id) = identities();
    let other = Arc::new(GhostIdentity::generate_fresh());
    let server = QuicTransport::listen("127.0.0.1:0".parse().unwrap(), Arc::clone(&server_id))
        .expect("listen");
    let addr = server.local_addr().expect("a bound port");

    let accept = tokio::spawn({
        let server = Arc::new(server);
        async move {
            let _ = server.accept_one(|_| true).await;
        }
    });

    let client = QuicTransport::client(Arc::clone(&client_id)).expect("client endpoint");
    // The peer identifies as the server, but we expected someone else: the
    // binding check must catch it, which is the whole point of doing it.
    let err = client
        .connect(addr, &other.fingerprint())
        .await
        .expect_err("a wrong identity must not be accepted");
    assert!(
        matches!(err, QuicError::WrongIdentity { .. }),
        "expected a wrong-identity refusal, got {err:?}"
    );
    let _ = accept.await;
    client.close();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unknown_identity_cannot_open_a_session() {
    let (server_id, client_id) = identities();
    let server = QuicTransport::listen("127.0.0.1:0".parse().unwrap(), Arc::clone(&server_id))
        .expect("listen");
    let addr = server.local_addr().expect("a bound port");

    let accept = tokio::spawn({
        let server = Arc::new(server);
        async move { server.accept_one(|_| false).await }
    });

    let client = QuicTransport::client(Arc::clone(&client_id)).expect("client endpoint");
    // The client proves its identity correctly, so the handshake itself succeeds;
    // what stops it is the admission rule, which is where it belongs — the
    // transport cannot know which identities the mesh has verified.
    let _ = client.connect(addr, &server_id.fingerprint()).await;

    let err = accept
        .await
        .expect("accept task")
        .expect_err("an identity we do not know must be refused");
    assert!(
        matches!(err, QuicError::UnknownPeer(_)),
        "expected an unknown-peer refusal, got {err:?}"
    );
    client.close();
}
