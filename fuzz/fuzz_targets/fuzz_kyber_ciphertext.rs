#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Malformed ML-KEM-512 ciphertexts (expected 768 bytes)
    // Feed arbitrary bytes — should not panic
    if data.len() < 32 {
        return;
    }

    // Try to parse as ML-KEM ciphertext (hybrid-array TryFrom — length-checked)
    let _ = <ml_kem::Ciphertext::<ml_kem::MlKem512> as TryFrom<&[u8]>>::try_from(data);

    // Try the temporal isolation decapsulate with a dummy key
    if data.len() >= 768 {
        let ct_arr = {
            let mut arr = [0u8; 768];
            let copy_len = data.len().min(768);
            arr[..copy_len].copy_from_slice(&data[..copy_len]);
            arr
        };
        let sk = ml_kem::DecapsulationKey512::from_seed([0u8; 64]); // Dummy ML-KEM-512 key
        let _ = vantablack::ghost::net::security::TemporalIsolator::fixed_time_decapsulate(&ct_arr, &sk);
    }
});
