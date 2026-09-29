use abos_common::crypto;
use abos_common::error::{Error, Result};
use abos_common::types::*;

/// Split a file into shards with Fountain/RaptorQ-style redundancy.
/// `redundancy` is a multiplier (e.g., 1.5 = 50% extra shards).
/// Each shard contains a portion of the data with a unique index.
pub fn split_file(data: &[u8], shard_size: usize, redundancy: f64) -> Vec<Shard> {
    let file_id = crypto::hmac_sha256(b"file_id", data);
    let total_shards = (data.len() as f64 / shard_size as f64).ceil() as u32;
    let target_shards = (total_shards as f64 * redundancy).ceil() as u32;

    let mut shards = Vec::with_capacity(target_shards as usize);

    for i in 0..target_shards {
        let start = (i as usize % total_shards as usize) * shard_size;
        let mut shard_data = if start < data.len() {
            let end = (start + shard_size).min(data.len());
            data[start..end].to_vec()
        } else {
            Vec::new()
        };

        // Pad to shard_size
        if shard_data.len() < shard_size {
            shard_data.resize(shard_size, 0);
        }

        // Redundancy: shard i >= total_shards is a repetition copy of source
        // shard (i % total_shards) — the receiver can use it to fill any gap
        // left by a lost original. (`start` above already points at that
        // source shard's range because it uses `i % total_shards`.)

        let checksum = crc32fast::hash(&shard_data);

        let shard = Shard {
            file_id,
            shard_index: i,
            total_shards,
            data: shard_data,
            checksum,
        };

        shards.push(shard);
    }

    shards
}

/// Reconstruct a file from shards.
/// Needs at least `total_shards` unique shards (index-based).
pub fn reconstruct_file(shards: &[Shard]) -> Result<Vec<u8>> {
    if shards.is_empty() {
        return Err(Error::ProtocolError("No shards provided".into()));
    }

    let file_id = shards[0].file_id;
    let total = shards[0].total_shards;
    // Pass 1: place original shards (index < total) into their own slots
    let mut collected: Vec<Option<&Shard>> = vec![None; total as usize];
    for shard in shards {
        if shard.file_id != file_id {
            return Err(Error::ProtocolError("Shard file_id mismatch".into()));
        }
        let idx = shard.shard_index as usize;
        if idx < total as usize && collected[idx].is_none() {
            collected[idx] = Some(shard);
        }
    }

    // Pass 2: fill remaining gaps from repetition copies (index >= total,
    // which repeat source shard index % total).
    for shard in shards {
        let idx = shard.shard_index as usize;
        if idx >= total as usize {
            let slot = idx % total as usize;
            if collected[slot].is_none() {
                collected[slot] = Some(shard);
            }
        }
    }

    // Check if we have enough shards
    let available = collected.iter().filter(|s| s.is_some()).count();
    if available < (total as usize * 3 / 4).max(1) {
        return Err(Error::ProtocolError(format!(
            "Insufficient shards: {}/{}",
            available, total
        )));
    }

    // Reconstruct (verify checksums first so a corrupt shard is rejected
    // rather than silently copied into the output).
    let shard_size = shards[0].data.len();
    let mut file_data = Vec::with_capacity(total as usize * shard_size);

    for shard_opt in &collected {
        if let Some(shard) = shard_opt {
            // Verify checksum
            let expected_crc = crc32fast::hash(&shard.data);
            if expected_crc != shard.checksum {
                return Err(Error::ProtocolError("Shard checksum mismatch".into()));
            }
            file_data.extend_from_slice(&shard.data);
        } else {
            // Missing shard - fill with zeros; the file-level HMAC check
            // below rejects the result, so corruption is never silent.
            file_data.extend(std::iter::repeat_n(0u8, shard_size));
        }
    }

    // Trim trailing zeros
    while let Some(&0) = file_data.last() {
        file_data.pop();
    }

    // Verify file integrity
    let expected_id = crypto::hmac_sha256(b"file_id", &file_data);
    if expected_id != file_id {
        return Err(Error::ProtocolError(
            "File hash mismatch - data corruption".into(),
        ));
    }

    Ok(file_data)
}

/// CRC32 fast implementation for shard verification
mod crc32fast {
    const CRC32_POLY: u32 = 0xEDB88320;

    fn table() -> [u32; 256] {
        let mut t = [0u32; 256];
        for (i, slot) in t.iter_mut().enumerate() {
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
        t
    }

    pub fn hash(data: &[u8]) -> u32 {
        let table = table();
        let mut crc = 0xFFFFFFFFu32;
        for &byte in data {
            let idx = ((crc ^ byte as u32) & 0xFF) as usize;
            crc = (crc >> 8) ^ table[idx];
        }
        crc ^ 0xFFFFFFFF
    }
}
