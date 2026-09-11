#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Variable-length relay packet fuzzer
    if data.len() < 4 {
        return;
    }

    // Try to parse as relay header (should not panic)
    let _ = vantablack::ghost::net::relay::parse_relay_header(data);
});