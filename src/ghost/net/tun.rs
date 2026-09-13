/// Windows TUN Virtual Network Interface (Admin / Full System VPN)
///
/// This module provides a wintun-based virtual adapter that allows the
/// GhostNet mesh to operate as a full system VPN. When activated, the OS
/// routes all internet traffic through the TUN device, where raw IPv4/IPv6
/// frames are captured, sharded via RS(2,1) erasure coding, and emitted
/// across the mesh to the exit node pool.
///
/// # Architecture
///
/// 1. **wintun.dll** — The official WireGuard® TUN driver for Windows.
///    Download from: https://www.wintun.net/
///    Place `wintun.dll` next to the `vantablack` executable at runtime,
///    or embed it as a resource in the binary.
///
/// 2. **Adapter creation** — On startup, create a virtual adapter named
///    "VantablackMesh" with a "Tunnel" type.
///
/// 3. **Frame capture** — Raw IPv4/IPv6 frames written by the OS kernel
///    to the TUN device are read as byte buffers, fed through
///    `l4_rs::encode()` for erasure coding, and dispatched to the mesh
///    via `send_gtf()`.
///
/// # Usage
/// ```ignore
/// // On Windows with admin privileges:
/// use vantablack::ghost::net::tun::VantablackTun;
///
/// let tun = VantablackTun::new("VantablackMesh", "Tunnel").expect("wintun init failed");
/// let mut frame_buf = vec![0u8; 65536];
/// loop {
///     let n = tun.read(&mut frame_buf).expect("read TUN frame");
///     let frame = &frame_buf[..n];
///     // Encrypt & shard frame across mesh:
///     // l4_rs::encode(frame) -> send_gtf(...) -> exit node pool
/// }
/// ```
///
/// # Feature Gate
/// This module is only compiled on `target_os = "windows"`.
/// On Linux/macOS, the standard TUN/TAP interface (`/dev/net/tun`) would
/// be used instead via a separate implementation.

#[cfg(target_os = "windows")]
mod platform {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use tracing::{info, warn};

    /// Wintun adapter handle — wraps the raw wintun FFI pointer.
    ///
    /// # Safety
    /// Wintun operations involve FFI calls to the wintun.dll driver.
    /// This struct ensures thread-safe access via atomic running flag.
    pub struct TunAdapter {
        /// Whether the adapter is actively capturing.
        running: Arc<AtomicBool>,
        /// Session handle (wintun session for read/write).
        session: Option<Box<dyn TunSession>>,
        /// Adapter name.
        name: String,
    }

    /// Trait abstracting over wintun session operations for testability.
    pub trait TunSession: Send {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize>;
        fn write(&self, buf: &[u8]) -> std::io::Result<usize>;
    }

    impl TunAdapter {
        /// Create a new wintun adapter and start a capture session.
        ///
        /// This requires:
        /// - Administrator privileges on Windows
        /// - `wintun.dll` accessible in the executable's directory or PATH
        ///
        /// Returns an error if wintun cannot be loaded or the adapter
        /// fails to initialize.
        pub fn find_wintun_dll() -> Option<std::path::PathBuf> {
            if let Ok(exe) = std::env::current_exe() {
                if let Some(dir) = exe.parent() {
                    let p = dir.join("wintun.dll");
                    if p.exists() {
                        return Some(p);
                    }
                }
            }
            if let Ok(cwd) = std::env::current_dir() {
                let p = cwd.join("wintun.dll");
                if p.exists() {
                    return Some(p);
                }
            }
            if let Ok(sys_root) = std::env::var("SystemRoot") {
                let p = std::path::PathBuf::from(sys_root)
                    .join("System32")
                    .join("wintun.dll");
                if p.exists() {
                    return Some(p);
                }
            }
            if let Ok(path_var) = std::env::var("PATH") {
                for dir in std::env::split_paths(&path_var) {
                    let p = dir.join("wintun.dll");
                    if p.exists() {
                        return Some(p);
                    }
                }
            }
            None
        }

        pub fn is_wintun_installed() -> bool {
            Self::find_wintun_dll().is_some()
        }

        pub fn new(name: &str, tun_type: &str) -> std::io::Result<Self> {
            info!(
                "Initializing wintun adapter: name={}, type={}",
                name, tun_type
            );

            match Self::find_wintun_dll() {
                Some(dll_path) => {
                    info!("Found wintun.dll at: {}", dll_path.display());
                    #[cfg(feature = "vpn")]
                    {
                        // Attempt real Wintun initialization via WintunTun
                        use crate::ghost::net::vpn::tun::{TunDevice, WintunTun};
                        use std::net::Ipv4Addr;

                        // Default overlay IP 10.66.0.2 / 255.255.255.0 for the TUN adapter interface
                        let addr = Ipv4Addr::new(10, 66, 0, 2);
                        let mask = Ipv4Addr::new(255, 255, 255, 0);

                        match WintunTun::new(name, addr, mask) {
                            Ok(wintun_dev) => {
                                info!("Successfully initialized Wintun adapter '{}'", name);
                                struct WintunDeviceSession(WintunTun);
                                impl TunSession for WintunDeviceSession {
                                    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                                        self.0.read_packet(buf)
                                    }
                                    fn write(&self, buf: &[u8]) -> std::io::Result<usize> {
                                        self.0.write_packet(buf)
                                    }
                                }
                                Ok(Self {
                                    running: Arc::new(AtomicBool::new(true)),
                                    session: Some(Box::new(WintunDeviceSession(wintun_dev))),
                                    name: name.to_string(),
                                })
                            }
                            Err(e) => {
                                warn!("Failed to initialize WintunTun adapter '{}': {}", name, e);
                                Err(e)
                            }
                        }
                    }
                    #[cfg(not(feature = "vpn"))]
                    {
                        warn!("wintun.dll detected but build lacks --features vpn");
                        Err(std::io::Error::new(
                            std::io::ErrorKind::Unsupported,
                            format!("wintun.dll found at {} - compile with --features vpn to enable Wintun adapter driver", dll_path.display()),
                        ))
                    }
                }
                None => {
                    warn!("wintun.dll not found in executable dir, working dir, System32, or PATH");
                    warn!("Place wintun.dll alongside vantablack.exe or in System32 (download: https://www.wintun.net/)");
                    Err(std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        "wintun.dll not found - place wintun.dll next to executable or in System32 to enable full-system TUN VPN mode",
                    ))
                }
            }
        }

        /// Read the next raw IP frame from the TUN device.
        ///
        /// The buffer should be large enough for a full Ethernet MTU (1500)
        /// plus any additional headers. Returns the number of bytes read.
        pub fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if let Some(ref mut session) = self.session {
                session.read(buf)
            } else {
                Err(std::io::Error::new(
                    std::io::ErrorKind::NotConnected,
                    "TUN session not started",
                ))
            }
        }

        /// Write a raw IP frame to the TUN device (inject into OS network stack).
        pub fn write(&self, buf: &[u8]) -> std::io::Result<usize> {
            if let Some(ref session) = self.session {
                session.write(buf)
            } else {
                Err(std::io::Error::new(
                    std::io::ErrorKind::NotConnected,
                    "TUN session not started",
                ))
            }
        }

        /// Check if the adapter is running.
        pub fn is_running(&self) -> bool {
            self.running.load(Ordering::Relaxed)
        }

        /// Shut down the TUN adapter.
        pub fn shutdown(&self) {
            self.running.store(false, Ordering::Relaxed);
            info!("TUN adapter shutdown");
        }

        /// Get the adapter name.
        pub fn name(&self) -> &str {
            &self.name
        }
    }

    impl Drop for TunAdapter {
        fn drop(&mut self) {
            self.shutdown();
        }
    }
}

// ── Cross-platform stubs ─────────────────────────────────────────

/// Re-export the platform-specific TUN adapter.
#[cfg(target_os = "windows")]
pub use platform::TunAdapter;

/// On non-Windows platforms, provide a stub that returns an error
/// explaining that TUN mode is Windows-only for now.
#[cfg(not(target_os = "windows"))]
pub struct TunAdapter;

#[cfg(not(target_os = "windows"))]
impl TunAdapter {
    pub fn new(name: &str, tun_type: &str) -> std::io::Result<Self> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            format!(
                "TUN mode not yet supported on this platform: name={}, type={}",
                name, tun_type
            ),
        ))
    }

    pub fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "TUN mode not supported on this platform",
        ))
    }

    pub fn write(&self, _buf: &[u8]) -> std::io::Result<usize> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "TUN mode not supported on this platform",
        ))
    }

    pub fn is_running(&self) -> bool {
        false
    }

    pub fn shutdown(&self) {}

    pub fn name(&self) -> &str {
        "unsupported"
    }
}
