#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Fuzz the GTF frame builder with arbitrary payloads
    // Should never panic regardless of input
    let session_hash = [0xAB, 0xCD, 0xEF, 0x01];
    let counter = 42;
    let shard_index = 0u8;
    let auth_tag = [0u8; 16];

    if data.len() <= 486 {
        // Privacy mode frame
        let _ = vantablack::ghost::net::build_gtf_frame(
            session_hash, counter, shard_index, data, &auth_tag, false,
        );
    }

    if data.len() <= 1446 {
        // Bulk mode frame
        let _ = vantablack::ghost::net::build_gtf_frame(
            session_hash, counter, shard_index, data, &auth_tag, true,
        );
    }
});