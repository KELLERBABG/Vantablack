//! daemon::cover — extracted from `src/main.rs` (Phase 1 modularization).
//!
//! Moved verbatim: same functions, same behaviour. Crate visibility is widened
//! to `pub(crate)` so the daemon orchestrator and sibling modules can call it.

use crate::*;

pub(crate) const COVER_FRAMES_PER_SEC: f64 = 2.0;

pub(crate) const COVER_IDLE_FRAMES_PER_SEC: f64 = 0.05;

pub(crate) const COVER_ACTIVE_TAIL_SECS: u64 = 5;

pub(crate) const COVER_FRAMES_PER_MESSAGE: f64 = 3.0;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CoverShapingMode {
    Adaptive,
    Always,
    Off,
}

pub(crate) fn cover_shaping_mode() -> CoverShapingMode {
    match std::env::var("GHOST_COVER_MODE")
        .unwrap_or_default()
        .to_ascii_lowercase()
        .as_str()
    {
        "off" | "0" | "false" => CoverShapingMode::Off,
        "always" | "2hz" => CoverShapingMode::Always,
        _ => CoverShapingMode::Adaptive,
    }
}

pub(crate) fn effective_cover_rate(mode: CoverShapingMode, active_tail: bool) -> f64 {
    match mode {
        CoverShapingMode::Off => 0.0,
        CoverShapingMode::Always => COVER_FRAMES_PER_SEC,
        CoverShapingMode::Adaptive => {
            if active_tail {
                COVER_FRAMES_PER_SEC
            } else {
                COVER_IDLE_FRAMES_PER_SEC
            }
        }
    }
}

pub(crate) fn cover_gap(uniform: f64, frames_per_sec: f64) -> Duration {
    let per_message = frames_per_sec / COVER_FRAMES_PER_MESSAGE;
    if !matches!(
        per_message.partial_cmp(&0.0),
        Some(std::cmp::Ordering::Greater)
    ) {
        return Duration::from_secs(3600);
    }
    let u = uniform.clamp(0.0, 1.0 - f64::EPSILON);
    let secs = -(1.0 - u).ln() / per_message;
    Duration::from_secs_f64(secs.clamp(0.005, 30.0))
}

pub(crate) async fn send_cover(sock: &UdpSocket, dst: &SocketAddr, ctx: &SealCtx) {
    match vantablack::ghost::v2::racs::observe_cover(
        vantablack::ghost::v2::racs::take_real_pending(),
    ) {
        vantablack::ghost::v2::racs::Action::EmitFrame { .. } => {}
        vantablack::ghost::v2::racs::Action::Sleep { .. } => return,
    }
    let (shards, tag) = enc_split(ctx, net::DUMMY_MAGIC);
    let mut batch = MixBatch::new(3, Duration::ZERO);
    let mut ready = None;
    for (i, shard) in shards.iter().take(3).enumerate() {
        if let Some(flushed) = batch.push((i as u8, shard.clone())) {
            ready = Some(flushed);
        }
    }
    for (shard_index, payload) in ready.unwrap_or_else(|| batch.drain_randomized()) {
        let header = ctx.data_header(shard_index, false, 0);
        let _ = super::srtp::send_v2(sock, dst, &header, &payload, &tag).await;
    }
}

pub(crate) fn spawn_cover_task(
    node: Arc<GhostNode>,
    addrs: Arc<DashMap<String, SocketAddr>>,
    relay_role: Option<Arc<DerpRelay>>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut next_emit: std::collections::HashMap<String, tokio::time::Instant> =
            std::collections::HashMap::new();
        let mut last_tx: std::collections::HashMap<String, (u64, tokio::time::Instant)> =
            std::collections::HashMap::new();
        let mode = cover_shaping_mode();
        loop {
            if mode == CoverShapingMode::Off {
                tokio::time::sleep(Duration::from_secs(30)).await;
                continue;
            }
            let now = tokio::time::Instant::now();
            if vantablack::ghost::v2::racs::enabled()
                && !vantablack::ghost::v2::racs::cover_allowed()
            {
                tokio::time::sleep(Duration::from_millis(10)).await;
                continue;
            }
            let peer_states: Vec<(String, u64)> = node
                .sessions
                .iter()
                .map(|e| {
                    (
                        e.peer_fingerprint.clone(),
                        e.tx_counter.load(std::sync::atomic::Ordering::Relaxed),
                    )
                })
                .collect();
            next_emit.retain(|peer, _| peer_states.iter().any(|(p, _)| p == peer));
            last_tx.retain(|peer, _| peer_states.iter().any(|(p, _)| p == peer));

            let mut due = Vec::new();
            for (peer, tx_ctr) in peer_states {
                let (prev_ctr, active_at) = last_tx.entry(peer.clone()).or_insert((tx_ctr, now));
                if tx_ctr > *prev_ctr {
                    *prev_ctr = tx_ctr;
                    *active_at = now;
                }
                let in_active_tail = now.saturating_duration_since(*active_at)
                    <= Duration::from_secs(COVER_ACTIVE_TAIL_SECS);
                let rate = effective_cover_rate(mode, in_active_tail);
                let deadline = next_emit
                    .entry(peer.clone())
                    .or_insert_with(|| now + cover_gap(rand::random::<f64>(), rate));
                if in_active_tail && *deadline > now + Duration::from_secs(3) {
                    *deadline = now + cover_gap(rand::random::<f64>(), rate);
                }
                if now >= *deadline {
                    *deadline = now + cover_gap(rand::random::<f64>(), rate);
                    if let Some(sess) = node.sessions.get(&peer) {
                        let ctx = SealCtx::from_session(&sess);
                        if let Some((c, _)) = last_tx.get_mut(&peer) {
                            *c = sess.tx_counter.load(std::sync::atomic::Ordering::Relaxed);
                        }
                        due.push((peer, ctx));
                    }
                }
            }
            for (peer, ctx) in due {
                let Some(dst) = addrs.get(&peer).map(|a| *a.value()) else {
                    continue;
                };
                let me = node.fingerprint();
                let decoy_sent = if !shardsec_default_enabled() {
                    relay_role
                        .as_ref()
                        .and_then(|relay| relay.pick_relay(&me, &peer))
                        .map(|(relay_fp, relay_addr)| {
                            let node_for_decoy = Arc::clone(&node);
                            let ctx_for_decoy = ctx.clone();
                            let peer_for_decoy = peer.clone();
                            async move {
                                let frame = seal_single(&ctx_for_decoy, net::DUMMY_MAGIC);
                                send_datagram_via_relay(
                                    &node_for_decoy,
                                    &node_for_decoy.socket,
                                    &relay_fp,
                                    &relay_addr,
                                    &peer_for_decoy,
                                    &frame,
                                )
                                .await
                            }
                        })
                } else {
                    None
                };
                if let Some(future) = decoy_sent {
                    if !future.await {
                        send_cover(&node.socket, &dst, &ctx).await;
                    }
                } else {
                    send_cover(&node.socket, &dst, &ctx).await;
                }
            }
            let max_sleep = tokio::time::Instant::now() + Duration::from_millis(500);
            let next_wakeup = next_emit
                .values()
                .copied()
                .min()
                .map_or(max_sleep, |t| t.min(max_sleep));
            tokio::time::sleep_until(next_wakeup).await;
        }
    })
}

#[cfg(test)]
mod p3_1_cover_tests {
    //! Cover traffic: the flag reaches the wire, the shape is the same
    //! as a data message, the receiver decides on the authenticated marker rather
    //! than the header bit, and the gaps are drawn rather than fixed.
    use crate::*;

    pub(crate) fn ctx(seed: u8) -> SealCtx {
        let s = Session::new_with_role([seed; 32], "peer".into(), SessionRole::Initiator);
        SealCtx::from_session(&s)
    }

    #[test]
    pub(crate) fn the_cover_bit_reaches_the_wire_and_is_not_a_version_marker() {
        use vantablack::ghost::net::{parse_gtf_v2_header, GTF_BASE_SIZE, JITTER_MAX};

        let ctx = ctx(0x5A);
        let (shards, tag) = enc_split(&ctx, net::DUMMY_MAGIC);
        assert_eq!(
            shards.len(),
            3,
            "cover is an ordinary RS(2,1) group, like data"
        );

        for (i, shard) in shards.iter().take(3).enumerate() {
            let frame =
                net::build_gtf_v2_frame(&ctx.header(i as u8, false, net::FLAG_DUMMY), shard, &tag);
            let h = parse_gtf_v2_header(&frame).expect("a v2 header");
            assert_ne!(
                h.flags & net::FLAG_DUMMY,
                0,
                "the caller bit must survive the builder's mask — before P3-1 it was masked off"
            );
            assert_eq!(
                h.flags & net::FLAG_V2,
                0,
                "the v2 marker is not a caller bit"
            );
            assert_eq!(
                frame.len(),
                GTF_BASE_SIZE + JITTER_MAX,
                "cover is a privacy frame, not a bulk one: same shape as data"
            );
            assert!(!h.bulk);
        }
    }

    #[test]
    pub(crate) fn cover_traffic_is_recognised_by_its_marker_not_by_its_header_bit() {
        use vantablack::ghost::net::{is_dummy_payload, random_tail, DUMMY_MAGIC};

        let ctx = ctx(0x33);
        let tail = random_tail();

        let mut framed = (DUMMY_MAGIC.len() as u16).to_be_bytes().to_vec();
        framed.extend_from_slice(DUMMY_MAGIC);
        xchacha_seal_in_place_with_aad(
            &ctx.key,
            &ctx.nonce,
            ctx.epoch,
            ctx.direction,
            &mut framed,
            &tail,
        )
        .expect("seal");
        let opened = xchacha_open_with_aad(
            &ctx.key,
            &ctx.nonce,
            ctx.epoch,
            ctx.direction,
            &mut framed,
            &tail,
        )
        .expect("opens");
        assert!(
            frame_payload(opened).is_some_and(is_dummy_payload),
            "a cover frame must be recognised after decryption"
        );

        let mut real = 4u16.to_be_bytes().to_vec();
        real.extend_from_slice(b"data");
        assert!(!frame_payload(&real).is_some_and(is_dummy_payload));
        assert!(!is_dummy_payload(b"DUMMY"), "a prefix is not the marker");
        assert!(
            !is_dummy_payload(b"DUMMY?"),
            "one byte off is not the marker"
        );
        assert!(!is_dummy_payload(b""));

        assert!(
            !is_dummy_payload(frame_payload(&real).expect("a framed data payload")),
            "FLAG_DUMMY on a real payload must not make it cover"
        );
    }

    #[test]
    pub(crate) fn adaptive_cover_drops_to_idle_rate_outside_active_tail() {
        assert_eq!(
            effective_cover_rate(CoverShapingMode::Adaptive, true),
            COVER_FRAMES_PER_SEC
        );
        assert_eq!(
            effective_cover_rate(CoverShapingMode::Adaptive, false),
            COVER_IDLE_FRAMES_PER_SEC
        );
        assert_eq!(effective_cover_rate(CoverShapingMode::Off, true), 0.0);
        assert_eq!(
            effective_cover_rate(CoverShapingMode::Always, false),
            COVER_FRAMES_PER_SEC
        );
    }

    #[test]
    pub(crate) fn rx_push_advances_past_permanent_gap_without_deadlock() {
        let mut st = RxState {
            next: None,
            buf: std::collections::BTreeMap::new(),
        };
        assert_eq!(rx_push(&mut st, 1, b"one".to_vec()), vec![b"one".to_vec()]);
        let mut flushed = Vec::new();
        for c in 3..=(2 + MAX_REORDER_GAP) {
            flushed.extend(rx_push(&mut st, c, format!("p{c}").into_bytes()));
        }
        assert!(!flushed.is_empty());
        assert_eq!(flushed[0], b"p3");
    }

    #[test]
    pub(crate) fn cover_gaps_are_drawn_not_a_metronome() {
        let draws = 20_000;
        let mut total = 0.0f64;
        let mut distinct = std::collections::HashSet::new();
        for i in 0..draws {
            let u = (i as f64 + 0.5) / draws as f64;
            let gap = cover_gap(u, COVER_FRAMES_PER_SEC).as_secs_f64();
            total += gap;
            distinct.insert((gap * 1000.0) as u64);
        }
        let mean = total / draws as f64;
        let expected = COVER_FRAMES_PER_MESSAGE / COVER_FRAMES_PER_SEC;
        assert!(
            (mean - expected).abs() < 0.15 * expected,
            "mean gap {mean:.3}s should be near {expected:.3}s"
        );
        assert!(distinct.len() > 100, "gaps must vary, not repeat");

        for u in [0.0, 0.999_999] {
            let g = cover_gap(u, COVER_FRAMES_PER_SEC);
            assert!(g >= Duration::from_millis(5) && g <= Duration::from_secs(30));
        }
        assert_eq!(cover_gap(0.5, 0.0), Duration::from_secs(3600));
    }
}
