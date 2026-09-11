#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // 944-byte blob fuzzer for handshake PDU parsing
    // Checks for panics, OOM, infinite loops
    if data.len() < 32 {
        return;
    }

    // Fuzz the actual handshake and response parsers
    let _ = vantablack::ghost::layers::l1_kem::parse_handshake_pdu(data);
    let _ = vantablack::ghost::layers::l1_kem::parse_response_pdu(data);

    // Try to parse as rekey handshake structure
    let _ = vantablack::ghost::session::parse_rekey_pdu(data);

    // Try unframe
    let _ = vantablack::ghost::net::unframe(data);

    // Test the relay header parsing
    let _ = vantablack::ghost::net::relay::parse_relay_header(data);
});