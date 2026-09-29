//! Digital TX/RX pipeline composed from the workspace's real components.
//!
//! Chain (byte-identical roundtrip on a clean channel):
//!
//! **TX**: length-frame → scramble → per-32-byte block: LDPC encode → unpack →
//! interleaver → QPSK (LLR-consistent mapping) → OFDM blocks → optional DSSS
//! spread.
//!
//! **RX**: (despread) → OFDM demodulate per block → soft LLR → deinterleave
//! (permuting the LLR vector) → LDPC decode → descramble → unframe.
//!
//! This is the honest integration test of `abos-fec` + `abos-dsp` +
//! `abos-phy` + `abos-phy::scrambler`: every stage is the same code the
//! orchestrator calls, wired so the roundtrip is mathematically invertible.
//! (The orchestrator's `receive()` additionally runs DDC/AGC/Costas/Gardner
//! and burst parsing — those need real channel sync and are exercised
//! separately at burst level.)

use abos_common::error::{Error, Result};
use abos_dsp::ofdm::{OFDMDemodulator, OFDMModulator};
use abos_fec::interleaver::Interleaver;
use abos_fec::ldpc::LDPCCode;
use abos_fec::soft_decision::qpsk_llr;
use abos_phy::dsss::{DSSSDemodulator, DSSSModulator};
use abos_phy::scrambler::Scrambler;
use num_complex::Complex64;

/// Max payload bytes per LDPC block (k=256 bits).
const BLOCK_BYTES: usize = 32;
/// LDPC codeword length in bits (n=512).
const CODEWORD_BITS: usize = 512;
/// QPSK symbols per codeword.
const SYMBOLS_PER_CODEWORD: usize = CODEWORD_BITS / 2;
/// OFDM shape — must leave enough non-pilot subcarriers for the symbols we
/// place per block; with 4 pilots in 256 carriers there are 252 data
/// carriers, so a 256-symbol codeword is split across two OFDM blocks.
const N_SUBCARRIERS: usize = 256;
const CP_LENGTH: usize = 32;
const PILOTS: [usize; 4] = [0, 64, 128, 192];
const DATA_CARRIERS: usize = N_SUBCARRIERS - PILOTS.len(); // 252

/// A full digital modem built from workspace components.
pub struct Modem {
    ldpc: LDPCCode,
    interleaver: Interleaver,
    ofdm_mod: OFDMModulator,
    ofdm_demod: OFDMDemodulator,
    dsss_chips: Option<usize>,
    dsss_seed: [u8; 32],
}

impl Modem {
    /// Modem without DSSS spreading.
    pub fn new() -> Self {
        Self::with_dsss(None)
    }

    /// Modem with DSSS spreading at `chips_per_symbol` (shared seed).
    pub fn with_dsss(chips_per_symbol: Option<usize>) -> Self {
        Self {
            ldpc: LDPCCode::new(256, 512),
            interleaver: Interleaver::new(CODEWORD_BITS, 42),
            ofdm_mod: OFDMModulator::new(N_SUBCARRIERS, CP_LENGTH, PILOTS.to_vec()),
            ofdm_demod: OFDMDemodulator::new(N_SUBCARRIERS, CP_LENGTH, PILOTS.to_vec()),
            dsss_chips: chips_per_symbol,
            dsss_seed: [7u8; 32],
        }
    }

    /// Transmit `payload` to a baseband I/Q vector.
    pub fn transmit(&mut self, payload: &[u8]) -> Vec<Complex64> {
        // Frame: u32 LE length prefix, then scramble the whole frame so the
        // receiver learns the exact byte count after descrambling.
        let mut frame = Vec::with_capacity(payload.len() + 4);
        frame.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        frame.extend_from_slice(payload);
        let mut scrambler = Scrambler::default();
        let scrambled = scrambler.scramble(&frame);

        let mut samples = Vec::with_capacity(
            scrambled.len().div_ceil(BLOCK_BYTES)
                * ((SYMBOLS_PER_CODEWORD.div_ceil(DATA_CARRIERS)) * (N_SUBCARRIERS + CP_LENGTH)),
        );

        for block in scrambled.chunks(BLOCK_BYTES) {
            // LDPC encode: bytes → codeword bytes (n=512 bits = 64 bytes).
            let codeword = self.ldpc.encode(block);

            // Unpack codeword bits, interleave them (512-bit blocks).
            let bits = unpack_bits(&codeword, CODEWORD_BITS);
            let interleaved = self.interleaver.interleave(&bits);

            // QPSK map with the same sign convention as `qpsk_llr`
            // (bit=1 → +1 on that axis).
            let symbols: Vec<Complex64> = interleaved
                .chunks(2)
                .map(|pair| {
                    let re = if pair[0] == 1 { 1.0 } else { -1.0 };
                    let im = if pair[1] == 1 { 1.0 } else { -1.0 };
                    Complex64::new(re, im)
                })
                .collect();

            // Two OFDM blocks carry the 256 symbols (252 data carriers each).
            for group in symbols.chunks(DATA_CARRIERS) {
                samples.extend(self.ofdm_mod.modulate(group));
            }
        }

        if let Some(chips) = self.dsss_chips {
            let mut spreader = DSSSModulator::new(&self.dsss_seed, chips);
            samples = spreader.spread(&samples);
        }

        samples
    }

    /// Receive baseband I/Q samples back to bytes.
    ///
    /// `noise_variance` feeds the soft LLR computation (0.0 → hard
    /// decisions, which is optimal for a clean loopback).
    pub fn receive(&mut self, samples: &[Complex64], noise_variance: f64) -> Result<Vec<u8>> {
        let samples = if let Some(chips) = self.dsss_chips {
            let mut despreader = DSSSDemodulator::new(&self.dsss_seed, chips);
            despreader.despread(samples)
        } else {
            samples.to_vec()
        };

        let block_samples = N_SUBCARRIERS + CP_LENGTH;
        if samples.is_empty() || samples.len() % block_samples != 0 {
            return Err(Error::ProtocolError(format!(
                "Sample stream {} is not a whole number of OFDM blocks",
                samples.len()
            )));
        }

        let mut decoded_blocks: Vec<Vec<u8>> = Vec::new();

        // Two consecutive OFDM blocks hold one 512-bit codeword.
        for pair in samples.chunks(2 * block_samples) {
            let mut llrs: Vec<f64> = Vec::with_capacity(CODEWORD_BITS);

            for block in pair.chunks(block_samples) {
                let (data_syms, _pilots) = self.ofdm_demod.demodulate(block);
                for sym in &data_syms {
                    let (llr0, llr1) = qpsk_llr(*sym, noise_variance);
                    llrs.push(llr0);
                    llrs.push(llr1);
                    if llrs.len() == CODEWORD_BITS {
                        break;
                    }
                }
                if llrs.len() == CODEWORD_BITS {
                    break;
                }
            }

            if llrs.len() < CODEWORD_BITS {
                return Err(Error::ProtocolError(
                    "Incomplete codeword in sample stream".into(),
                ));
            }

            // Deinterleave the LLR vector (inverse of the TX bit shuffle),
            // then LDPC-decode to recover the 32-byte payload block.
            let deinterleaved = self.deinterleave_llrs(&llrs);
            let block_bytes = self.ldpc.decode(&deinterleaved, 50)?;
            decoded_blocks.push(block_bytes);
        }

        // Concatenate decoded blocks (scrambled), then descramble ONCE with a
        // fresh LFSR — matching TX, where the frame was scrambled as a whole
        // before chunking.
        let scrambled: Vec<u8> = decoded_blocks.into_iter().flatten().collect();
        let mut scrambler = Scrambler::default();
        let stream = scrambler.descramble(&scrambled);
        if stream.len() < 4 {
            return Err(Error::ProtocolError("Frame too short".into()));
        }
        let payload_len = u32::from_le_bytes([stream[0], stream[1], stream[2], stream[3]]) as usize;
        if stream.len() < 4 + payload_len {
            return Err(Error::ProtocolError(format!(
                "Truncated frame: header says {} bytes, have {}",
                payload_len,
                stream.len() - 4
            )));
        }
        Ok(stream[4..4 + payload_len].to_vec())
    }

    /// Inverse of the TX interleaver applied to an LLR vector.
    ///
    /// TX: `out[perm[i]] = in[i]`, so `in[i] = out[perm[i]]`.
    fn deinterleave_llrs(&self, llrs: &[f64]) -> Vec<f64> {
        let mut out = vec![0.0; llrs.len()];
        for (i, &pos) in self.interleaver.permutation.iter().enumerate() {
            if i < llrs.len() && pos < llrs.len() {
                out[i] = llrs[pos];
            }
        }
        out
    }
}

impl Default for Modem {
    fn default() -> Self {
        Self::new()
    }
}

/// Unpack `count` bits from packed bytes (LSB-first per byte).
fn unpack_bits(bytes: &[u8], count: usize) -> Vec<u8> {
    let mut bits = Vec::with_capacity(count);
    for i in 0..count {
        let b = (bytes[i / 8] >> (i % 8)) & 0x01;
        bits.push(b);
    }
    bits
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_roundtrip_byte_identical() {
        let mut modem = Modem::new();
        for payload in [
            vec![],
            vec![0u8],
            b"hello ionosphere".to_vec(),
            (0..=255u8).collect::<Vec<u8>>(),
            vec![0xAB; 32],
            vec![0xCD; 100],
        ] {
            let samples = modem.transmit(&payload);
            let recovered = modem
                .receive(&samples, 0.0)
                .expect("clean channel must decode");
            assert_eq!(recovered, payload, "payload must roundtrip byte-identical");
        }
    }

    #[test]
    fn roundtrip_with_dsss_spreading() {
        let mut modem = Modem::with_dsss(Some(4));
        let payload = b"spread spectrum payload".to_vec();
        let samples = modem.transmit(&payload);
        // Spreading expands the stream by the chip factor relative to the
        // un-spread length (2 OFDM blocks of 288 samples for a short frame).
        assert!(samples.len() > 2 * (N_SUBCARRIERS + CP_LENGTH));
        let recovered = modem.receive(&samples, 0.0).expect("decode");
        assert_eq!(recovered, payload);
    }

    #[test]
    fn length_prefix_rejects_truncation() {
        let mut modem = Modem::new();
        let payload = vec![0xEE; 64];
        let mut samples = modem.transmit(&payload);
        samples.truncate(samples.len() / 2);
        assert!(modem.receive(&samples, 0.0).is_err());
    }

    #[test]
    fn noiseless_llr_signs_match_convention() {
        // bit=1 maps to +1 axis; qpsk_llr must return positive LLR there.
        let (llr0, llr1) = qpsk_llr(Complex64::new(1.0, -1.0), 0.1);
        assert!(llr0 > 0.0, "I-axis +1 → bit0 = 1");
        assert!(llr1 < 0.0, "Q-axis -1 → bit1 = 0");
    }
}
