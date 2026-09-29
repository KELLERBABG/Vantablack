/// GPIO pin mapping for SDR transceiver control
pub struct GPIO {
    #[allow(dead_code)]
    /// Pin numbers for each function: [TX_EN, RX_EN, PA_EN, ANT_SEL_0, ANT_SEL_1, TR_SW]
    pins: [u8; 6],
}

impl Default for GPIO {
    fn default() -> Self {
        Self::new()
    }
}

impl GPIO {
    pub fn new() -> Self {
        Self {
            pins: [17, 18, 22, 23, 24, 25],
        }
    }
    pub fn with_pins(pins: [u8; 6]) -> Self {
        Self { pins }
    }
    pub fn set_antenna(&self, _port: u8) {}
    pub fn set_pa_enable(&self, _enabled: bool) {}
    pub fn set_tr_switch(&self, _tx_mode: bool) {}
}
