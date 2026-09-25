#![no_main]

use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

static DUMMY_KEY: OnceLock<vantablack::ghost::layers::l1_kem::DecapsulationKey512> =
    OnceLock::new();

fuzz_target!(|data: &[u8]| {
    // Malformed ML-KEM-512 ciphertexts (expected 768 bytes)
    // Feed arbitrary bytes — should not panic
    if data.len() < 32 {
        return;
    }

    if data.len() >= 768 {
        let mut ct_arr = [0u8; 768];
        ct_arr.copy_from_slice(&data[..768]);
        let sk = DUMMY_KEY.get_or_init(|| {
            vantablack::ghost::layers::l1_kem::generate_kyber_keypair().1
        });
        let _ = vantablack::ghost::net::security::TemporalIsolator::fixed_time_decapsulate(
            &ct_arr, sk,
        );
    }
});
