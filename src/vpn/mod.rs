//! VPN daemon module.

pub mod daemon;
pub mod userspace;
#[allow(unused_imports)]
pub use daemon::{init_vpn_mode, init_vpn_mode_with_rotator, vpn_export, VpnMode};
#[allow(unused_imports)]
pub use userspace::ZeroAdminTunnel;

#[cfg(feature = "vpn")]
pub use vantablack::ghost::net::vpn::*;
