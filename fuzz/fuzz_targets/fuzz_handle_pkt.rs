#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Feed arbitrary byte slices to the packet handler via simulated state
    // The handle_pkt function in main.rs expects (counter, payload, session_key)
    if data.len() < 10 {
        return;
    }

    let counter = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    let payload = &data[4..];

    // Try to decrypt with a dummy key (should not panic)
    let key = [0x42u8; 32];
    let mut msg = payload.to_vec();
    let _ = vantablack::ghost::layers::l2_aead::decrypt_in_place(&key, counter, &mut msg);
});