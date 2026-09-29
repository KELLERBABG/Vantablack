use abos_common::types::*;
use num_complex::Complex64;

/// Generate a preamble sequence (known pilot symbols for AGC and timing recovery)
pub fn generate_preamble(n_samples: usize) -> Vec<Complex64> {
    (0..n_samples)
        .map(|i| {
            let phase = 2.0 * std::f64::consts::PI * i as f64 / n_samples as f64;
            Complex64::new(phase.cos(), phase.sin())
        })
        .collect()
}

/// Generate a sync word from a crypto-deterministic seed
pub fn generate_sync_word(seed: &[u8; 32]) -> Vec<Complex64> {
    use abos_common::pn_gen::PNGenerator;
    let mut pn_gen = PNGenerator::new(seed);
    let chips = pn_gen.generate_chips(64);
    chips.iter().map(|&c| Complex64::new(c, 0.0)).collect()
}

/// Build a burst packet into a vector of I/Q samples
/// Structure: [preamble][sync_word][header][payload]
pub fn build_burst(packet: &BurstPacket) -> Vec<Complex64> {
    let header_syms = encode_header(&packet.header);
    let mut burst = Vec::with_capacity(
        packet.preamble.len() + packet.sync_word.len() + header_syms.len() + packet.payload.len(),
    );
    burst.extend_from_slice(&packet.preamble);
    burst.extend_from_slice(&packet.sync_word);
    burst.extend_from_slice(&header_syms);
    burst.extend_from_slice(&packet.payload);
    burst
}

/// Encode burst header as QPSK symbols
fn encode_header(header: &BurstHeader) -> Vec<Complex64> {
    let mut bytes = Vec::with_capacity(10);
    bytes.push(header.mcs as u8);
    bytes.extend_from_slice(&header.shard_id[..4]);
    bytes.extend_from_slice(&header.length_bytes.to_le_bytes());
    bytes.extend_from_slice(&header.crc.to_le_bytes());

    bytes
        .iter()
        .flat_map(|&b| {
            let mut syms = Vec::with_capacity(4);
            for i in 0..4 {
                let bits = (b >> (i * 2)) & 0x03;
                match bits {
                    0 => syms.push(Complex64::new(1.0, 1.0)),
                    1 => syms.push(Complex64::new(-1.0, 1.0)),
                    2 => syms.push(Complex64::new(-1.0, -1.0)),
                    3 => syms.push(Complex64::new(1.0, -1.0)),
                    _ => unreachable!(),
                }
            }
            syms
        })
        .collect()
}

/// Parse a burst from received I/Q samples by correlating the sync word
///
/// `sync_seed` must match the seed used by [`generate_sync_word`] at the
/// transmitter.
pub fn parse_burst(samples: &[Complex64], sync_seed: &[u8; 32]) -> Option<BurstPacket> {
    // Simple sync word correlation - find peak
    // In production, this would use a proper preamble + sync correlator
    if samples.len() < 128 {
        return None;
    }

    // Assume sync word starts after a fixed preamble length
    let preamble_len = 32;
    let sync_word = generate_sync_word(sync_seed);
    let sync_len = sync_word.len();

    if samples.len() < preamble_len + sync_len {
        return None;
    }

    let sync_region = &samples[preamble_len..preamble_len + sync_len];
    let mut correlation = 0.0f64;
    for (s, c) in sync_region.iter().zip(sync_word.iter()) {
        correlation += (s * c.conj()).norm_sqr();
    }

    if correlation < 10.0 {
        return None;
    }

    // Decode header (13 bytes = 52 QPSK symbols — must match encode_header)
    let header_start = preamble_len + sync_len;
    if samples.len() < header_start + 52 {
        return None;
    }

    let header_syms = &samples[header_start..header_start + 52];
    let mut header_bytes = [0u8; 13];
    for (byte_idx, byte) in header_bytes.iter_mut().enumerate() {
        for sym_idx in 0..4 {
            let sym = header_syms[byte_idx * 4 + sym_idx];
            let bits = if sym.re >= 0.0 && sym.im >= 0.0 {
                0u8
            } else if sym.re < 0.0 && sym.im >= 0.0 {
                1u8
            } else if sym.re < 0.0 && sym.im < 0.0 {
                2u8
            } else {
                3u8
            };
            *byte |= bits << (sym_idx * 2);
        }
    }

    let mcs = match header_bytes[0] {
        0 => MCS::Bpsk12,
        1 => MCS::Qpsk12,
        2 => MCS::Qpsk34,
        3 => MCS::Qam1612,
        4 => MCS::Qam1634,
        5 => MCS::Qam6434,
        _ => return None,
    };

    let mut shard_id = [0u8; 32];
    shard_id[..4].copy_from_slice(&header_bytes[1..5]);
    let length_bytes = u32::from_le_bytes([
        header_bytes[5],
        header_bytes[6],
        header_bytes[7],
        header_bytes[8],
    ]);
    let crc = u32::from_le_bytes([
        header_bytes[9],
        header_bytes[10],
        header_bytes[11],
        header_bytes[12],
    ]);

    let header = BurstHeader {
        mcs,
        shard_id,
        length_bytes,
        crc,
    };

    // Extract payload
    let payload_start = header_start + 52;
    let payload_end = payload_start + length_bytes as usize;
    let payload = if payload_end <= samples.len() {
        samples[payload_start..payload_end].to_vec()
    } else {
        return None;
    };

    Some(BurstPacket {
        preamble: samples[..preamble_len].to_vec(),
        sync_word,
        header,
        payload,
    })
}
