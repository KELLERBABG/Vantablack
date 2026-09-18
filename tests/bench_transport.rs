//! `GTF_bulk` vs `QUIC` — the optional-transport verify step.
//!
//! This is the `GTF_bulk` vs `QUIC` bench, and it is a harness rather than a
//! scoreboard: it measures the carriers the tunnel
//! actually has, on the machine it is run on, and prints what it found.
//!
//! Two pairs are compared, because the two GTF framings are not interchangeable
//! and the difference is the finding:
//!
//! * **Bulk** frames are a fixed `GTF_BULK_SIZE` (1472 B) and carry up to 1446 B
//!   of payload. A 1472-byte frame does **not** fit a QUIC datagram — QUIC's
//!   datagram limit is path-MTU-bounded (≈1200 in practice) — so bulk frames take
//!   QUIC streams. That is not a limitation of the harness; it is why
//!   `QuicLink::send_frame` routes by size in the first place, and the bulk rows
//!   exist to measure exactly that route.
//! * **Privacy** frames are small (≤ 486 B of payload here). These fit a QUIC
//!   datagram, so the privacy rows compare an unreliable carrier against an
//!   unreliable carrier: the RS pool at the peer reconstructs from any two of
//!   three shards, which is what makes an unordered, best-effort carrier
//!   acceptable on that path.
//!
//! Every frame is built by the real `net::build_gtf_frame` and recovered by the
//! real `net::unframe`, so what is measured is GTF framing, not a stand-in.
//!
//! Run it with `cargo test --profile bench-transport --features quic --test
//! bench_transport -- --ignored`; it is `#[ignore]`d so an ordinary test run
//! stays fast and quiet.
#![cfg(feature = "quic")]

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::net::UdpSocket;
use vantablack::ghost::layers::l0_identity::GhostIdentity;
use vantablack::ghost::net::quic::{FramePath, QuicTransport};
use vantablack::ghost::net::{
    self, BULK_OFFSET_AUTH_TAG_START, BULK_OFFSET_PAYLOAD_START, OFFSET_PAYLOAD_START,
};

/// Application payload moved per row.
const VOLUME: usize = 4 << 20;
/// Warm-up volume, so lazy initialisation is not charged to the first row.
const WARMUP: usize = 256 << 10;
/// How long to wait for frames still in flight once sending has stopped.
const DRAIN: Duration = Duration::from_secs(20);
/// Bulk frames carry up to `MAX_BULK_PAYLOAD_LEN` — less the 2-byte length prefix
/// `frame_shard` adds, which is exactly the off-by-two that has to be respected to
/// fill a frame rather than overflow it.
const BULK_CHUNK: usize = net::MAX_BULK_PAYLOAD_LEN - 2;
/// A privacy shard's payload, matching what the live shard path produces.
const PRIVACY_CHUNK: usize = net::MAX_PAYLOAD_LEN - 2;

fn gtf_frame(bulk: bool, chunk: &[u8], counter: u32) -> Vec<u8> {
    let sh = [0x47, 0x54, 0x46, 0x31];
    let carrier = net::frame_shard(chunk);
    let mut frame = net::build_gtf_frame(sh, counter, 0, &carrier, &[0u8; 16], bulk);
    if bulk {
        // The bulk flag is what tells the receiver not to wait for RS siblings.
        frame[net::OFFSET_FLAGS] |= 0x02;
    }
    frame
}

/// Recover the payload from a received frame, exactly as the receive path does.
fn payload_of(bulk: bool, frame: &[u8]) -> Option<Vec<u8>> {
    let region = if bulk {
        if net::parse_flags(frame) & 0x02 == 0 {
            return None;
        }
        &frame[BULK_OFFSET_PAYLOAD_START..BULK_OFFSET_AUTH_TAG_START.min(frame.len())]
    } else {
        &frame[OFFSET_PAYLOAD_START..net::OFFSET_AUTH_TAG_START.min(frame.len())]
    };
    net::unframe(region)
}

/// One row of the table.
struct Row {
    carrier: &'static str,
    framing: &'static str,
    frames: u64,
    delivered: u64,
    payload_bytes: u64,
    wire_bytes: u64,
    dropped: u64,
    secs: f64,
}

impl Row {
    fn payload_mibs(&self) -> f64 {
        self.payload_bytes as f64 / (1024.0 * 1024.0)
    }
    fn throughput(&self) -> f64 {
        if self.secs > 0.0 {
            self.payload_mibs() / self.secs
        } else {
            0.0
        }
    }
}

/// Counters shared with a receiver task.
#[derive(Default)]
struct Counters {
    frames: AtomicU64,
    payload: AtomicU64,
    wire: AtomicU64,
}

fn print_table(rows: &[Row]) {
    println!();
    println!(
        "{:<22} {:<10} {:>7} {:>10} {:>11} {:>10} {:>8} {:>9} {:>8}",
        "carrier",
        "framing",
        "frames",
        "delivered",
        "payload MiB",
        "wire MiB",
        "secs",
        "MiB/s",
        "dropped"
    );
    println!("{}", "-".repeat(101));
    for r in rows {
        println!(
            "{:<22} {:<10} {:>7} {:>10} {:>11.2} {:>10.2} {:>8.3} {:>9.1} {:>8}",
            r.carrier,
            r.framing,
            r.frames,
            r.delivered,
            r.payload_mibs(),
            r.wire_bytes as f64 / (1024.0 * 1024.0),
            r.secs,
            r.throughput(),
            r.dropped
        );
    }
    println!();
    println!("payload MiB/s is application bytes; wire MiB counts GTF frames only");
    println!("(IP/UDP headers and QUIC's own overhead are excluded from both).");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "benchmark: cargo test --profile bench-transport --features quic --test bench_transport -- --ignored"]
async fn gtf_bulk_versus_quic() {
    let mut rows = Vec::new();

    // Pair 1: the bulk carrier, 1446-byte chunks in 1472-byte frames.
    rows.push(udp_row("GTF bulk", "UDP", true, BULK_CHUNK).await);
    rows.push(quic_row("GTF bulk", "stream", true, BULK_CHUNK, FramePath::Stream).await);

    // Pair 2: the privacy carrier, where a QUIC datagram can carry the frame.
    rows.push(udp_row("GTF privacy", "UDP", false, PRIVACY_CHUNK).await);
    rows.push(
        quic_row(
            "GTF privacy",
            "datagram",
            false,
            PRIVACY_CHUNK,
            FramePath::Datagram,
        )
        .await,
    );

    print_table(&rows);

    // The harness is the thing under test here: a row that moved nothing would
    // make the table a lie. Throughput itself is a measurement, not an assertion —
    // a shared CI runner is not a benchmark rig, and a threshold would only make
    // this flaky.
    for r in &rows {
        assert!(
            r.frames > 0,
            "{} ({}) sent nothing: the bench is not measuring",
            r.carrier,
            r.framing
        );
        assert!(
            r.payload_bytes > 0,
            "{} ({}) delivered nothing",
            r.carrier,
            r.framing
        );
    }
    assert!(
        rows[0].payload_bytes == rows[1].payload_bytes,
        "the bulk rows must carry the same payload for the comparison to mean anything"
    );
}

/// Send `VOLUME` of payload as GTF frames over UDP, as fast as the OS accepts.
async fn udp_row(carrier: &'static str, framing: &'static str, bulk: bool, chunk: usize) -> Row {
    let rx = UdpSocket::bind("127.0.0.1:0").await.expect("bind rx");
    let addr = rx.local_addr().expect("rx addr");
    let tx = UdpSocket::bind("127.0.0.1:0").await.expect("bind tx");
    let counters = Arc::new(Counters::default());

    let reader = {
        let counters = Arc::clone(&counters);
        tokio::spawn(async move {
            let mut buf = vec![0u8; 2048];
            loop {
                let Ok((n, _)) = rx.recv_from(&mut buf).await else {
                    return;
                };
                counters.wire.fetch_add(n as u64, Ordering::Relaxed);
                if let Some(p) = payload_of(bulk, &buf[..n]) {
                    counters.frames.fetch_add(1, Ordering::Relaxed);
                    counters
                        .payload
                        .fetch_add(p.len() as u64, Ordering::Relaxed);
                }
            }
        })
    };

    let frames_to_send = (VOLUME / chunk) as u64;
    let warm = (WARMUP / chunk) as u64;

    // Warm-up, then drain what it produced so the sender starts from a clean,
    // already-warm path.
    for i in 0..warm {
        let _ = tx
            .send_to(&gtf_frame(bulk, &vec![0x5Au8; chunk], i as u32), addr)
            .await;
    }
    let warm_deadline = Instant::now() + DRAIN;
    while counters.frames.load(Ordering::Relaxed) < warm && Instant::now() < warm_deadline {
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
    let before = counters.frames.load(Ordering::Relaxed);

    let start = Instant::now();
    for i in 0..frames_to_send {
        // A distinct counter per frame, as the live path sends.
        let _ = tx
            .send_to(&gtf_frame(bulk, &vec![0x5Au8; chunk], i as u32), addr)
            .await;
    }
    let deadline = Instant::now() + DRAIN;
    while counters.frames.load(Ordering::Relaxed) < before + frames_to_send
        && Instant::now() < deadline
    {
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
    let secs = start.elapsed().as_secs_f64();
    reader.abort();

    Row {
        carrier,
        framing,
        frames: frames_to_send,
        delivered: counters.frames.load(Ordering::Relaxed) - before,
        payload_bytes: counters.payload.load(Ordering::Relaxed),
        wire_bytes: counters.wire.load(Ordering::Relaxed),
        dropped: 0,
        secs,
    }
}

/// Send the same frames over an established QUIC link, with the framing fixed.
async fn quic_row(
    carrier: &'static str,
    framing: &'static str,
    bulk: bool,
    chunk: usize,
    path: FramePath,
) -> Row {
    let server_id = Arc::new(GhostIdentity::generate_fresh());
    let client_id = Arc::new(GhostIdentity::generate_fresh());
    let server = QuicTransport::listen("127.0.0.1:0".parse().unwrap(), Arc::clone(&server_id))
        .expect("listen");
    let addr = server.local_addr().expect("a bound port");
    let server_fp = server_id.fingerprint();

    let accept = tokio::spawn({
        let server = Arc::new(server);
        async move { server.accept_one(|_| true).await.expect("accept") }
    });
    let client = QuicTransport::client(Arc::clone(&client_id)).expect("client endpoint");
    let link = client.connect(addr, &server_fp).await.expect("connect");
    let peer = accept.await.expect("accept task");

    let counters = Arc::new(Counters::default());
    let reader = {
        let counters = Arc::clone(&counters);
        tokio::spawn(async move {
            while let Some(frame) = peer.recv_frame().await {
                counters
                    .wire
                    .fetch_add(frame.len() as u64, Ordering::Relaxed);
                if let Some(p) = payload_of(bulk, &frame) {
                    counters.frames.fetch_add(1, Ordering::Relaxed);
                    counters
                        .payload
                        .fetch_add(p.len() as u64, Ordering::Relaxed);
                }
            }
        })
    };

    // A 1472-byte frame cannot ride a datagram, so the caller must have been told
    // the truth about the framing it asked for.
    if path == FramePath::Datagram {
        assert!(
            gtf_frame(bulk, &vec![0u8; chunk], 0).len() <= link.max_datagram(),
            "the datagram row must only be asked for frames that fit a datagram \
             (max {} bytes)",
            link.max_datagram()
        );
    }

    let frames_to_send = (VOLUME / chunk) as u64;
    let warm = (WARMUP / chunk) as u64;
    for i in 0..warm {
        let frame = gtf_frame(bulk, &vec![0x5Au8; chunk], i as u32);
        link.send_frame_as(&frame, path)
            .await
            .expect("warm-up send");
    }
    let warm_deadline = Instant::now() + DRAIN;
    while counters.frames.load(Ordering::Relaxed) < warm && Instant::now() < warm_deadline {
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
    let before = counters.frames.load(Ordering::Relaxed);

    let start = Instant::now();
    for i in 0..frames_to_send {
        let frame = gtf_frame(bulk, &vec![0x5Au8; chunk], i as u32);
        if let Err(e) = link.send_frame_as(&frame, path).await {
            // A frame the carrier refused is reported, not hidden: it is the
            // difference between a slow carrier and a carrier that will not take
            // the traffic.
            eprintln!("carrier refused a frame after {i}: {e}");
            break;
        }
    }
    let deadline = Instant::now() + DRAIN;
    while counters.frames.load(Ordering::Relaxed) < before + frames_to_send
        && Instant::now() < deadline
    {
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
    let secs = start.elapsed().as_secs_f64();

    let (_, _, _, _, dropped, _, _) = link.stats().snapshot();
    reader.abort();
    link.close();
    client.close();

    Row {
        carrier,
        framing,
        frames: frames_to_send,
        delivered: counters.frames.load(Ordering::Relaxed) - before,
        payload_bytes: counters.payload.load(Ordering::Relaxed),
        wire_bytes: counters.wire.load(Ordering::Relaxed),
        dropped,
        secs,
    }
}
