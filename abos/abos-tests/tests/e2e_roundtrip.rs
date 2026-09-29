//! End-to-end roundtrip: payload → modem → channel → modem → payload.
//!
//! Asserts byte-identical recovery on clean and noisy channels, plus
//! graceful failure (never silent corruption) when the stream is truncated.

use abos_tests::channel::LoopbackChannel;
use abos_tests::pipeline::Modem;

#[test]
fn e2e_clean_channel_byte_identical() {
    let mut modem = Modem::new();
    let payloads: Vec<Vec<u8>> = vec![
        b"".to_vec(),
        b"The atmosphere is the relay.".to_vec(),
        (0..=255u8).collect(),
        vec![0x00; 1024], // page-aligned zeros
        vec![0xFF; 3000], // multi-codeword payload
    ];
    for payload in payloads {
        let samples = modem.transmit(&payload);
        let clean = LoopbackChannel::clean().deliver_samples(&samples);
        let recovered = modem.receive(&clean, 0.0).expect("clean decode");
        assert_eq!(recovered, payload, "must roundtrip byte-identical");
    }
}

#[test]
fn e2e_noisy_channel_still_decodes() {
    // Noise is injected in the time domain; the demodulator's FFT scales
    // per-bin noise variance by N_SUBCARRIERS, so the effective symbol
    // noise is N·σ². Choose σ = 0.02 → post-FFT σ ≈ 0.32 on unit symbols
    // (≈10 dB Eb/N0) — squarely in LDPC's correction range.
    let mut modem = Modem::new();
    let payload: Vec<u8> = (0..4096u32).map(|i| (i % 251) as u8).collect();
    let samples = modem.transmit(&payload);

    let mut channel = LoopbackChannel::seeded(99, 0.0, 0.0, 0.0, 0.02);
    let noisy = channel.deliver_samples(&samples);

    let n_subcarriers = 256.0;
    let llr_var = n_subcarriers * 0.02 * 0.02;
    let recovered = modem.receive(&noisy, llr_var);
    match recovered {
        Ok(data) => assert_eq!(data, payload, "noisy decode must be exact"),
        Err(e) => panic!("LDPC should absorb this noise level, got: {}", e),
    }
}

#[test]
fn e2e_dsss_clean_roundtrip_via_channel() {
    let mut modem = Modem::with_dsss(Some(8));
    let payload = b"ghost node calling home".to_vec();
    let samples = modem.transmit(&payload);
    let delivered = LoopbackChannel::clean().deliver_samples(&samples);
    let recovered = modem.receive(&delivered, 0.0).expect("decode");
    assert_eq!(recovered, payload);
}

#[test]
fn e2e_truncated_stream_fails_without_panic() {
    let mut modem = Modem::new();
    let payload = vec![0x42u8; 512];
    let mut samples = modem.transmit(&payload);
    samples.truncate(samples.len() / 3);
    let result = modem.receive(&samples, 0.0);
    assert!(result.is_err(), "truncation must surface as an error");
}

#[test]
fn e2e_corrupted_stream_never_returns_wrong_bytes_silently() {
    // Even if LDPC fails to converge the caller must get an error, not
    // silently wrong data. Flip a large chunk of samples.
    let mut modem = Modem::new();
    let payload = vec![0x77u8; 256];
    let mut samples = modem.transmit(&payload);
    for s in samples.iter_mut().skip(300).step_by(7) {
        *s = -*s;
    }
    if let Ok(data) = modem.receive(&samples, 1.0) {
        assert_eq!(data, payload, "if it decodes, it must be right");
    }
    // Rejecting garbage is equally acceptable.
}
