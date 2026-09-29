use crate::dma::DMABuffer;
use abos_common::error::{Error, Result};
use abos_common::types::SDRConfig;
use num_complex::Complex64;

pub trait SDRDevice {
    fn configure(&mut self, config: SDRConfig) -> Result<()>;
    fn start_stream(&mut self) -> Result<()>;
    fn stop_stream(&mut self) -> Result<()>;
    fn read_samples(&mut self, buffer: &mut [Complex64]) -> Result<usize>;
    fn write_samples(&mut self, samples: &[Complex64]) -> Result<usize>;
}

pub struct USRPSDR {
    config: Option<SDRConfig>,
    running: bool,
    buffer: DMABuffer,
}

impl Default for USRPSDR {
    fn default() -> Self {
        Self::new()
    }
}

impl USRPSDR {
    pub fn new() -> Self {
        Self {
            config: None,
            running: false,
            buffer: DMABuffer::new(4096),
        }
    }
}

impl SDRDevice for USRPSDR {
    fn configure(&mut self, config: SDRConfig) -> Result<()> {
        self.config = Some(config);
        Ok(())
    }
    fn start_stream(&mut self) -> Result<()> {
        if self.config.is_none() {
            return Err(Error::ConfigError("USRP not configured".into()));
        }
        self.running = true;
        Ok(())
    }
    fn stop_stream(&mut self) -> Result<()> {
        self.running = false;
        Ok(())
    }
    fn read_samples(&mut self, buffer: &mut [Complex64]) -> Result<usize> {
        if !self.running {
            return Err(Error::SdrError("USRP stream not started".into()));
        }
        let n = buffer.len().min(1024);
        buffer[..n].fill(Complex64::new(0.0, 0.0));
        Ok(n)
    }
    fn write_samples(&mut self, samples: &[Complex64]) -> Result<usize> {
        if !self.running {
            return Err(Error::SdrError("USRP stream not started".into()));
        }
        self.buffer.write_samples(samples);
        Ok(samples.len())
    }
}

pub struct LimeSDR {
    config: Option<SDRConfig>,
    running: bool,
    buffer: DMABuffer,
}

impl Default for LimeSDR {
    fn default() -> Self {
        Self::new()
    }
}

impl LimeSDR {
    pub fn new() -> Self {
        Self {
            config: None,
            running: false,
            buffer: DMABuffer::new(4096),
        }
    }
}

impl SDRDevice for LimeSDR {
    fn configure(&mut self, config: SDRConfig) -> Result<()> {
        self.config = Some(config);
        Ok(())
    }
    fn start_stream(&mut self) -> Result<()> {
        if self.config.is_none() {
            return Err(Error::ConfigError("LimeSDR not configured".into()));
        }
        self.running = true;
        Ok(())
    }
    fn stop_stream(&mut self) -> Result<()> {
        self.running = false;
        Ok(())
    }
    fn read_samples(&mut self, buffer: &mut [Complex64]) -> Result<usize> {
        if !self.running {
            return Err(Error::SdrError("LimeSDR stream not started".into()));
        }
        let n = buffer.len().min(1024);
        buffer[..n].fill(Complex64::new(0.0, 0.0));
        Ok(n)
    }
    fn write_samples(&mut self, samples: &[Complex64]) -> Result<usize> {
        if !self.running {
            return Err(Error::SdrError("LimeSDR stream not started".into()));
        }
        self.buffer.write_samples(samples);
        Ok(samples.len())
    }
}

pub struct HackRFSDR {
    config: Option<SDRConfig>,
    running: bool,
    buffer: DMABuffer,
}

impl Default for HackRFSDR {
    fn default() -> Self {
        Self::new()
    }
}

impl HackRFSDR {
    pub fn new() -> Self {
        Self {
            config: None,
            running: false,
            buffer: DMABuffer::new(4096),
        }
    }
}

impl SDRDevice for HackRFSDR {
    fn configure(&mut self, config: SDRConfig) -> Result<()> {
        self.config = Some(config);
        Ok(())
    }
    fn start_stream(&mut self) -> Result<()> {
        if self.config.is_none() {
            return Err(Error::ConfigError("HackRF not configured".into()));
        }
        self.running = true;
        Ok(())
    }
    fn stop_stream(&mut self) -> Result<()> {
        self.running = false;
        Ok(())
    }
    fn read_samples(&mut self, buffer: &mut [Complex64]) -> Result<usize> {
        if !self.running {
            return Err(Error::SdrError("HackRF stream not started".into()));
        }
        let n = buffer.len().min(1024);
        buffer[..n].fill(Complex64::new(0.0, 0.0));
        Ok(n)
    }
    fn write_samples(&mut self, samples: &[Complex64]) -> Result<usize> {
        if !self.running {
            return Err(Error::SdrError("HackRF stream not started".into()));
        }
        self.buffer.write_samples(samples);
        Ok(samples.len())
    }
}

pub enum SDRType {
    USRP,
    LimeSDR,
    HackRF,
}

pub fn create_sdr(device_type: SDRType) -> Box<dyn SDRDevice> {
    match device_type {
        SDRType::USRP => Box::new(USRPSDR::new()),
        SDRType::LimeSDR => Box::new(LimeSDR::new()),
        SDRType::HackRF => Box::new(HackRFSDR::new()),
    }
}
