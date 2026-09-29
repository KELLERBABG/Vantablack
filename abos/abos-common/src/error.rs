use thiserror::Error;

/// Unified error type for the ABOS system
#[derive(Error, Debug)]
pub enum Error {
    #[error("SDR hardware error: {0}")]
    SdrError(String),

    #[error("DSP error: {0}")]
    DspError(String),

    #[error("FEC decoding failure: {0}")]
    FecError(String),

    #[error("Protocol error: {0}")]
    ProtocolError(String),

    #[error("Storage error: {0}")]
    StorageError(String),

    #[error("Crypto error: {0}")]
    CryptoError(String),

    #[error("Timeout")]
    Timeout,

    #[error("Synchronization lost")]
    SyncLost,

    #[error("Buffer overflow")]
    BufferOverflow,

    #[error("Invalid configuration: {0}")]
    ConfigError(String),

    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    SerdeError(#[from] bincode::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
