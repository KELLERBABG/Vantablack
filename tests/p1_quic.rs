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

use std::sync::Arc;
use std::time::Duration;

use vantablack::ghost::layers::l0_identity::GhostIdentity;
use vantablack::ghost::net::carrier::Carrier;
use vantablack::ghost::net::quic::{FramePath, QuicError, QuicTransport};

fn identities() -> (Arc<GhostIdentity>, Arc<GhostIdentity>) {
    (
        Arc::new(GhostIdentity::generate_fresh()),
        Arc::new(GhostIdentity::generate_fresh()),
    )
}

/// A frame the privacy path would send: small enough to ride a datagram.
const RS_FRAME: &[u8] = b"GTF\x01privacy-shard-1-of-2-with-tag";

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

    registry.register(server_fp.clone(), Arc::clone(&link));
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

    client_transport.close();
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
