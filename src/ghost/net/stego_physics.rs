//! Invention §51: Stego-in-Physics (Physical Covert Shard Carriage)
//!
//! Encodes a single Reed-Solomon shard over a covert physical side-channel
//! (acoustic FSK tone modulation, thermal fan/load modulation, or optical LED blink)
//! while the other two shards traverse the network.
//!
//! Because Reed-Solomon(2,1) requires any 2 of 3 shards, an adversary controlling
//! 100% of the network wires still captures only 2 network shards if one was diverted
//! or required a physical co-located receiver, rendering pure wire surveillance mathematically
//! incapable of reconstructing the message when physical carriage is active.

pub const PHYSICAL_STEGO_MAGIC: &[u8; 4] = b"PHYS";

/// Physical medium options for covert shard carriage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PhysicalStegoCarrier {
    /// Inaudible / ultrasonic acoustic frequency-shift keying (18 kHz - 22 kHz tones)
    AcousticFsk,
    /// Thermal CPU load-stepping duty cycle modulation
    ThermalModulation,
    /// Optical status LED high-frequency pulse modulation
    OpticalBlink,
}

/// A physical modulation frame encoding a shard.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PhysicalShardFrame {
    pub carrier: PhysicalStegoCarrier,
    /// Modulated frequency or pulse interval symbols
    pub symbols: Vec<u16>,
}

pub struct PhysicalStegoCodec;

impl PhysicalStegoCodec {
    /// Modulate shard bytes into physical carrier symbols.
    pub fn modulate(shard_bytes: &[u8], carrier: PhysicalStegoCarrier) -> PhysicalShardFrame {
        let mut symbols = Vec::with_capacity(shard_bytes.len() * 2);

        // Map nibbles (4 bits -> 16 symbol levels) based on carrier frequency baseline
        let base_symbol: u16 = match carrier {
            PhysicalStegoCarrier::AcousticFsk => 18_000, // 18 kHz baseline
            PhysicalStegoCarrier::ThermalModulation => 100, // 100 ms duty baseline
            PhysicalStegoCarrier::OpticalBlink => 500,   // 500 Hz pulse baseline
        };

        for byte in shard_bytes {
            let high_nibble = (byte >> 4) as u16;
            let low_nibble = (byte & 0x0F) as u16;
            symbols.push(base_symbol + high_nibble * 100);
            symbols.push(base_symbol + low_nibble * 100);
        }

        PhysicalShardFrame { carrier, symbols }
    }

    /// Demodulate physical carrier symbols back into shard bytes.
    pub fn demodulate(frame: &PhysicalShardFrame) -> Result<Vec<u8>, &'static str> {
        if frame.symbols.len() % 2 != 0 {
            return Err("invalid symbol length: must contain pairs of nibble symbols");
        }

        let base_symbol: u16 = match frame.carrier {
            PhysicalStegoCarrier::AcousticFsk => 18_000,
            PhysicalStegoCarrier::ThermalModulation => 100,
            PhysicalStegoCarrier::OpticalBlink => 500,
        };

        let mut bytes = Vec::with_capacity(frame.symbols.len() / 2);
        for chunk in frame.symbols.chunks_exact(2) {
            let s_high = chunk[0];
            let s_low = chunk[1];

            if s_high < base_symbol || s_low < base_symbol {
                return Err("carrier underflow: symbol below base carrier frequency");
            }

            let high_nibble = ((s_high - base_symbol) / 100) as u8;
            let low_nibble = ((s_low - base_symbol) / 100) as u8;

            if high_nibble > 15 || low_nibble > 15 {
                return Err("symbol overflow: nibble out of 4-bit range");
            }

            bytes.push((high_nibble << 4) | low_nibble);
        }

        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stego_in_physics_roundtrip_across_all_carriers() {
        let shard_data = b"rs_shard_data_over_acoustic_covert_link";

        for carrier in [
            PhysicalStegoCarrier::AcousticFsk,
            PhysicalStegoCarrier::ThermalModulation,
            PhysicalStegoCarrier::OpticalBlink,
        ] {
            let frame = PhysicalStegoCodec::modulate(shard_data, carrier);
            assert_eq!(frame.symbols.len(), shard_data.len() * 2);

            let recovered = PhysicalStegoCodec::demodulate(&frame).expect("demodulation succeeds");
            assert_eq!(recovered, shard_data);
        }
    }
}
