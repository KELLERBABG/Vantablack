//! Integration tests for Skywave SDR Carrier and ABOS Bridge.

use vantablack::ghost::net::dtn_reconcile::DtnBundle;
use vantablack::ghost::net::fallback::{self, FallbackPath};
use vantablack::ghost::net::sdr_bridge::SkywaveBridge;

/// Poll until `cond` holds (the virtual carrier is asynchronous).
async fn wait_for(cond: impl Fn() -> bool) {
    for _ in 0..100 {
        if cond() {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
}

#[tokio::test]
async fn virtual_carrier_defaults_to_loopback_ephemeral() {
    std::env::remove_var("GHOST_SKYWAVE_UDP");
    let bridge = SkywaveBridge::with_virtual_carrier(true)
        .await
        .expect("bridge init");
    wait_for(|| bridge.telemetry().virtual_carrier.is_some()).await;

    let bind = bridge
        .telemetry()
        .virtual_carrier
        .expect("virtual carrier bound");
    assert!(
        bind.ip().is_loopback(),
        "default bind must never open an unauthenticated port on an external interface"
    );
    assert_ne!(bind.port(), 0, "OS resolves the ephemeral port at bind");
    assert_eq!(
        bridge.telemetry().virtual_carrier_peer,
        None,
        "no peer configured means datagrams are shipped nowhere"
    );
}

#[tokio::test]
async fn virtual_carrier_self_loop_round_trips_frames() {
    std::env::remove_var("GHOST_SKYWAVE_UDP");
    let bridge = SkywaveBridge::with_virtual_carrier(true)
        .await
        .expect("bridge init");
    wait_for(|| bridge.telemetry().virtual_carrier.is_some()).await;
    let addr = bridge.telemetry().virtual_carrier.unwrap();

    // Point the carrier at itself: outbound datagrams come straight back —
    // the whole ionosphere, simulated as one loopback socket.
    let _ = bridge.ship_to_peer(addr);
    bridge.transmit(b"gtf-frame-over-the-air").await.unwrap();
    wait_for(|| bridge.has_inbound()).await;

    let rx = bridge.try_rx();
    assert_eq!(rx.len(), 1);
    assert_eq!(rx[0], b"gtf-frame-over-the-air".to_vec());

    let telem = bridge.telemetry();
    assert!(telem.tx_packet_count >= 1);
    assert!(telem.rx_packet_count >= 1);
    assert!(telem.tx_dsp_bytes >= b"gtf-frame-over-the-air".len() as u64);
}

#[tokio::test]
async fn inactive_bridge_is_not_ladder_selectable() {
    std::env::remove_var("GHOST_SKYWAVE_UDP");
    let bridge = SkywaveBridge::with_virtual_carrier(false)
        .await
        .expect("bridge init");

    assert!(!bridge.is_active());
    assert_eq!(
        bridge.nvis_freq_khz(),
        None,
        "an inactive bridge must not arm the ladder's skywave rung"
    );

    // Activation is explicit and flips exactly the ladder gate.
    bridge.activate_synthetic(5_350_000);
    assert!(bridge.is_active());
    assert_eq!(bridge.nvis_freq_khz(), Some(5350));

    // ...and the ladder itself only offers the rung with the bridge armed.
    assert_eq!(
        fallback::choose_fallback_with_skywave("a", "b", &[], None, None),
        None
    );
    assert_eq!(
        fallback::choose_fallback_with_skywave("a", "b", &[], None, bridge.nvis_freq_khz()),
        Some(FallbackPath::Skywave {
            nvis_freq_khz: 5350
        })
    );
}

#[tokio::test]
async fn test_skywave_bridge_initialization_and_telemetry() {
    let bridge = SkywaveBridge::new()
        .await
        .expect("Bridge should initialize");
    let telem = bridge.telemetry();

    assert_eq!(telem.carrier_freq_hz, 5_350_000); // 60m NVIS band
    assert!(telem.estimated_f0f2_hz > 0.0);
    assert_eq!(telem.dsss_processing_gain_db, 24.0);
    assert_eq!(telem.tx_packet_count, 0);

    // Update cognitive ionospheric metrics
    bridge.update_iono_metrics(7_150_000.0, true);
    let updated = bridge.telemetry();
    assert_eq!(updated.estimated_f0f2_hz, 7_150_000.0);
    assert!(updated.meteor_burst_window_open);
    // Synthetic (no `sdr` feature / no hardware): the bridge never claims to be
    // a radio until explicitly activated.
    assert!(
        !bridge.is_active(),
        "synthetic bridge must not self-claim active"
    );

    bridge.activate_synthetic(5_350_000);
    assert!(bridge.is_active());
    assert_eq!(bridge.nvis_freq_khz(), Some(5350));
}

#[tokio::test]
async fn test_dtn_bundle_skywave_serialization_roundtrip() {
    let bundle_id = [0x42u8; 16];
    let sequence = 1001;
    let payload = b"VANTABLACK_TO_ABOS_SKYWAVE_PAYLOAD_TEST".to_vec();

    let bundle = DtnBundle::new(bundle_id, sequence, payload.clone());
    let wire_bytes = bundle.to_skywave_payload();

    // Verify magic prefix
    assert_eq!(&wire_bytes[..4], b"MREC");

    // Deserialize
    let recovered = DtnBundle::from_skywave_payload(&wire_bytes)
        .expect("Payload should deserialize successfully");

    assert_eq!(recovered.bundle_id, bundle_id);
    assert_eq!(recovered.sequence, sequence);
    assert_eq!(recovered.payload, payload);
    assert_eq!(recovered.payload_hash, bundle.payload_hash);
}

#[test]
fn test_fallback_path_skywave_invariants() {
    let skywave = FallbackPath::Skywave {
        nvis_freq_khz: 5350,
    };

    // The atmosphere is a passive reflector, not a third-party relay
    assert!(!skywave.is_relayed());
    // Egress is via RF antenna, not IP socket
    assert_eq!(skywave.egress_addr(), None);
    assert_eq!(skywave.label(), "skywave-nvis");
}
