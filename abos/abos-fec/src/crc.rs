/// CRC-32 checksum computation using the standard IEEE polynomial
const CRC32_POLY: u32 = 0xEDB88320;

/// Pre-computed CRC-32 lookup table
fn crc32_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    for (i, slot) in table.iter_mut().enumerate() {
        let mut crc = i as u32;
        for _ in 0..8 {
            if crc & 1 == 1 {
                crc = (crc >> 1) ^ CRC32_POLY;
            } else {
                crc >>= 1;
            }
        }
        *slot = crc;
    }
    table
}

/// Compute CRC-32 checksum for the given data
pub fn crc32(data: &[u8]) -> u32 {
    let table = crc32_table();
    let mut crc = 0xFFFFFFFFu32;
    for &byte in data {
        let idx = ((crc ^ byte as u32) & 0xFF) as usize;
        crc = (crc >> 8) ^ table[idx];
    }
    crc ^ 0xFFFFFFFF
}

/// Verify CRC-32 checksum
pub fn crc32_verify(data: &[u8], expected: u32) -> bool {
    crc32(data) == expected
}
