//! ABOS integration test harness.
//!
//! Provides a deterministic, in-memory simulation environment so the full
//! protocol + PHY stack can be exercised without SDR hardware:
//!
//! - [`channel::LoopbackChannel`] — lossy/corrupting/duplicating link that
//!   bundles and I/Q samples pass through.
//! - [`pipeline::Modem`] — the real bit-level TX/RX chain composed from the
//!   workspace's scrambler, LDPC, interleaver, QPSK and OFDM implementations,
//!   producing byte-identical roundtrips on a clean channel.

pub mod channel;
pub mod pipeline;
