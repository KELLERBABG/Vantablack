use abos_common::types::MCS;

pub struct AdaptiveController {
    pub current_mcs: MCS,
    pub current_symbol_rate: f64,
}

impl AdaptiveController {
    pub fn new(initial_mcs: MCS, symbol_rate: f64) -> Self {
        Self {
            current_mcs: initial_mcs,
            current_symbol_rate: symbol_rate,
        }
    }

    pub fn adapt_to_channel(&mut self, snr: f64, ber: f64) -> MCS {
        if ber > 0.1 || snr < 5.0 {
            self.current_mcs = MCS::Bpsk12;
        } else if ber > 0.05 || snr < 10.0 {
            self.current_mcs = MCS::Qpsk12;
        } else if ber > 0.01 || snr < 15.0 {
            self.current_mcs = MCS::Qpsk34;
        } else if ber > 0.005 || snr < 20.0 {
            self.current_mcs = MCS::Qam1612;
        } else if ber > 0.001 || snr < 25.0 {
            self.current_mcs = MCS::Qam1634;
        } else {
            self.current_mcs = MCS::Qam6434;
        }
        self.current_mcs
    }
}
