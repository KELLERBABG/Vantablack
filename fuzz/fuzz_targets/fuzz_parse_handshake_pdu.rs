#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // 944-byte blob fuzzer for handshake PDU parsing
    // Checks for panics, OOM, infinite loops
    if data.len() < 32 {
        return;
    }

    // Try to parse as various handshake-like structures
    // These are safe to call with arbitrary data and should never panic
    let _ = vantablack::ghost::session::parse_rekey_pdu(data);

    // Try unframe
    let _ = vantablack::ghost::net::unframe(data);

    // Test the relay header parsing
    let _ = vantablack::ghost::net::relay::parse_relay_header(data);
});