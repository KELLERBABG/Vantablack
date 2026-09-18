//! Apple Network Extension FFI boundary.
//!
//! The extension owns the entitlement and `NEPacketTunnelFlow`; the Rust core
//! owns packet framing, VPN session state, and lifecycle. The C ABI is kept
//! intentionally small so the signed host target can supply the platform glue
//! without duplicating protocol logic.

use std::ffi::c_void;

#[repr(C)]
pub struct GhostApplePacket {
    pub bytes: *mut u8,
    pub len: usize,
}

unsafe extern "C" {
    fn ggn_vpn_apple_start(user_data: *mut c_void) -> i32;
    fn ggn_vpn_apple_stop(user_data: *mut c_void);
}

/// Start the core from a signed Network Extension host.
///
/// The caller must retain `user_data` until [`stop`] returns. No packet data is
/// accepted through this ABI until the host has authenticated and configured the
/// corresponding `VpnConfig`.
#[cfg(target_os = "macos")]
pub unsafe fn start(user_data: *mut c_void) -> Result<(), i32> {
    let status = ggn_vpn_apple_start(user_data);
    if status == 0 {
        Ok(())
    } else {
        Err(status)
    }
}

#[cfg(target_os = "macos")]
pub unsafe fn stop(user_data: *mut c_void) {
    ggn_vpn_apple_stop(user_data);
}
