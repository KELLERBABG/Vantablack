/// Shared test utilities for GhostNet integration tests.
///
/// This module exports:
/// - `virtual_net`: Virtual in-memory transport hub and helpers
/// - `nat`: RFC 4787 NAT model, for the Phase 1 NAT-traversal gate
/// - `wire`: wire-format helpers
///
/// Usage in test files: `mod common; use common::virtual_net::*;`
pub mod nat;
#[cfg(feature = "vpn")]
pub mod tunnel;
pub mod virtual_net;
pub mod wire;
