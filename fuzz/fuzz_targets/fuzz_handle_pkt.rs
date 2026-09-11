#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Fuzz packet parsing, frame extraction, and AEAD decrypt pipeline
    if data.len() < 10 {
        return;
    }

    let _ = vantablack::ghost::net::parse_packet_counter(data);
    let _ = vantablack::ghost::net::parse_session_hash(data);
    let _ = vantablack::ghost::net::parse_flags(data);
    let _ = vantablack::ghost::net::extract_payload(data);
    let _ = vantablack::ghost::net::extract_auth_tag(data);

    let counter = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    let payload = &data[4..];

    let key = [0x42u8; 32];
    let sh = [0x01, 0x02, 0x03, 0x04];
    let mut msg = payload.to_vec();
    let _ = vantablack::ghost::layers::l2_aead::decrypt_in_place(&key, counter, &mut msg);
    let _ = vantablack::ghost::layers::l2_aead::decrypt_in_place_with_context(
        &key,
        counter,
        &sh,
        vantablack::ghost::layers::l2_aead::NonceDirection::InitiatorToResponder,
        &mut msg,
    );
});