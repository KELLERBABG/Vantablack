#[cfg(feature = "vpn")]
pub mod tunnel;
/// Shared test utilities for GhostNet integration tests.
///
/// This module exports:
/// - `virtual_net`: Virtual in-memory transport hub and helpers
///
/// Usage in test files: `mod common; use common::virtual_net::*;`
pub mod virtual_net;
pub mod wire;
