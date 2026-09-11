#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // 2-byte length prefix + arbitrary data
    // Feed arbitrary byte slices to unframe — should never panic
    let _ = vantablack::ghost::net::unframe(data);
});