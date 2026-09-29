/// Data scrambler using a Linear Feedback Shift Register (LFSR)
///
/// The same operation is used for scrambling and descrambling (XOR with LFSR output).
pub struct Scrambler {
    lfsr_state: u16,
}

impl Scrambler {
    /// Create a new scrambler with given polynomial and initial state
    /// Default polynomial: x^16 + x^14 + x^13 + x^11 + 1 (CCITT V.34)
    pub fn new(initial_state: u16) -> Self {
        Self {
            lfsr_state: initial_state,
        }
    }

    /// Generate next scrambler bit and advance state
    fn next_bit(&mut self) -> u8 {
        let feedback = (self.lfsr_state & 0x0001)
            ^ ((self.lfsr_state >> 2) & 0x0001)
            ^ ((self.lfsr_state >> 3) & 0x0001)
            ^ ((self.lfsr_state >> 5) & 0x0001);
        let output = (self.lfsr_state & 0x0001) as u8;
        self.lfsr_state = (self.lfsr_state >> 1) | (feedback << 15);
        output
    }

    /// Scramble data by XORing with LFSR output
    pub fn scramble(&mut self, data: &[u8]) -> Vec<u8> {
        data.iter()
            .map(|&byte| {
                let mut scrambled = 0u8;
                for bit in 0..8 {
                    let data_bit = (byte >> bit) & 0x01;
                    let scrambler_bit = self.next_bit();
                    scrambled |= (data_bit ^ scrambler_bit) << bit;
                }
                scrambled
            })
            .collect()
    }

    /// Descramble data (identical to scramble for LFSR-based scramblers)
    pub fn descramble(&mut self, data: &[u8]) -> Vec<u8> {
        self.scramble(data)
    }

    /// Reset the scrambler to its initial state
    pub fn reset(&mut self, initial_state: u16) {
        self.lfsr_state = initial_state;
    }
}

impl Default for Scrambler {
    fn default() -> Self {
        Self::new(0xFFFF)
    }
}
