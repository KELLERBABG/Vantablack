use abos_common::error::Result;
use abos_common::types::{FrequencyHz, SampleRate, MCS};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemConfig {
    pub node_id: [u8; 32],
    pub center_frequency: FrequencyHz,
    pub sample_rate: SampleRate,
    pub tx_gain: f64,
    pub rx_gain: f64,
    pub bandwidth: f64,
    pub default_mcs: MCS,
    pub data_dir: PathBuf,
    pub log_level: String,
}

impl Default for SystemConfig {
    fn default() -> Self {
        Self {
            node_id: [0u8; 32],
            center_frequency: 7_100_000,
            sample_rate: 1_000_000.0,
            tx_gain: 40.0,
            rx_gain: 30.0,
            bandwidth: 12_000.0,
            default_mcs: MCS::Bpsk12,
            data_dir: PathBuf::from("./data"),
            log_level: String::from("info"),
        }
    }
}

impl SystemConfig {
    pub fn load() -> Result<Self> {
        let config_path = PathBuf::from("abos_config.json");
        if config_path.exists() {
            let data = std::fs::read_to_string(&config_path)
                .map_err(abos_common::error::Error::IoError)?;
            let config: SystemConfig = serde_json::from_str(&data)
                .map_err(|e| abos_common::error::Error::ConfigError(e.to_string()))?;
            Ok(config)
        } else {
            let config = SystemConfig::default();
            config.save()?;
            Ok(config)
        }
    }

    pub fn save(&self) -> Result<()> {
        let config_path = PathBuf::from("abos_config.json");
        let data = serde_json::to_string_pretty(self)
            .map_err(|e| abos_common::error::Error::ConfigError(e.to_string()))?;
        std::fs::write(&config_path, data).map_err(abos_common::error::Error::IoError)?;
        Ok(())
    }
}
