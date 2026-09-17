#![no_main]

use libfuzzer_sys::fuzz_target;
use vantablack::ghost::net::quic::verify_identity_binding;

fuzz_target!(|data: &[u8]| {
    // The verifier must fail closed for arbitrary lengths and bytes without
    // panicking or allocating proportional to attacker-controlled input.
    let _ = verify_identity_binding("0000000000000000", data, b"fuzz-channel-binding");
});
