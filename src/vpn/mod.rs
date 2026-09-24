//! VPN daemon module.

pub mod daemon;
#[allow(unused_imports)]
pub use daemon::{init_vpn_mode, vpn_export, VpnMode};

#[cfg(feature = "vpn")]
pub use vantablack::ghost::net::vpn::*;
