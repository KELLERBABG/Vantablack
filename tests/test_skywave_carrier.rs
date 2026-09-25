//! Integration tests for Skywave SDR Carrier and ABOS Bridge.

use vantablack::ghost::net::dtn_reconcile::DtnBundle;
use vantablack::ghost::net::fallback::FallbackPath;
use vantablack::ghost::net::sdr_bridge::SkywaveBridge;

#[tokio::test]
async fn test_skywave_bridge_initialization_and_telemetry() {
    let bridge = SkywaveBridge::new().await.expect("Bridge should initialize");
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
