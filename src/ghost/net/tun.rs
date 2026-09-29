//! Cross-Platform TUN Virtual Network Interface (Full System VPN).
//!
//! Provides virtual network adapter backends (Windows Wintun, Linux /dev/net/tun, macOS utun)
//! enabling GhostNet to operate as an OS-level VPN.

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

// ── Cross-platform stubs & adapters ──────────────────────────────

#[cfg(target_os = "windows")]
pub use platform::TunAdapter;

#[cfg(target_os = "windows")]
pub fn is_wintun_installed() -> bool {
    platform::TunAdapter::is_wintun_installed()
}

#[cfg(target_os = "windows")]
pub fn find_wintun_dll() -> Option<std::path::PathBuf> {
    platform::TunAdapter::find_wintun_dll()
}

// ── Linux: /dev/net/tun kernel driver ─────────────────────────────

#[cfg(target_os = "linux")]
mod linux_platform {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use tracing::info;

    pub trait TunSession: Send {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize>;
        fn write(&self, buf: &[u8]) -> std::io::Result<usize>;
        fn shutdown(&self);
    }

    pub struct TunAdapter {
        running: Arc<AtomicBool>,
        session: Option<Box<dyn TunSession>>,
        name: String,
    }

    impl TunAdapter {
        pub fn find_wintun_dll() -> Option<std::path::PathBuf> {
            None
        }

        pub fn is_wintun_installed() -> bool {
            false
        }

        pub fn new(name: &str, _tun_type: &str) -> std::io::Result<Self> {
            info!("Initializing Linux TUN adapter: /dev/net/tun dev={}", name);
            #[cfg(feature = "vpn")]
            {
                use crate::ghost::net::vpn::tun::{TunDevice, UnixTun};
                let dev = UnixTun::new(name)?;
                struct UnixTunSession(UnixTun);
                impl TunSession for UnixTunSession {
                    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                        self.0.read_packet(buf)
                    }
                    fn write(&self, buf: &[u8]) -> std::io::Result<usize> {
                        self.0.write_packet(buf)
                    }
                    fn shutdown(&self) {
                        self.0.shutdown();
                    }
                }
                Ok(Self {
                    running: Arc::new(AtomicBool::new(true)),
                    session: Some(Box::new(UnixTunSession(dev))),
                    name: name.to_string(),
                })
            }
            #[cfg(not(feature = "vpn"))]
            {
                Err(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    "Compile with --features vpn to enable Linux /dev/net/tun adapter",
                ))
            }
        }

        pub fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if let Some(ref mut session) = self.session {
                session.read(buf)
            } else {
                Err(std::io::Error::new(
                    std::io::ErrorKind::NotConnected,
                    "TUN device closed",
                ))
            }
        }

        pub fn write(&self, buf: &[u8]) -> std::io::Result<usize> {
            if let Some(ref session) = self.session {
                session.write(buf)
            } else {
                Err(std::io::Error::new(
                    std::io::ErrorKind::NotConnected,
                    "TUN device closed",
                ))
            }
        }

        pub fn is_running(&self) -> bool {
            self.running.load(Ordering::Relaxed)
        }

        pub fn shutdown(&self) {
            self.running.store(false, Ordering::Relaxed);
            if let Some(ref session) = self.session {
                session.shutdown();
            }
        }

        pub fn name(&self) -> &str {
            &self.name
        }
    }
}

#[cfg(target_os = "linux")]
pub use linux_platform::TunAdapter;

// ── macOS: utun kernel control socket ──────────────────────────────

#[cfg(target_os = "macos")]
mod macos_platform {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use tracing::info;

    pub trait TunSession: Send {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize>;
        fn write(&self, buf: &[u8]) -> std::io::Result<usize>;
        fn shutdown(&self);
    }

    pub struct TunAdapter {
        running: Arc<AtomicBool>,
        session: Option<Box<dyn TunSession>>,
        name: String,
    }

    impl TunAdapter {
        pub fn find_wintun_dll() -> Option<std::path::PathBuf> {
            None
        }

        pub fn is_wintun_installed() -> bool {
            false
        }

        pub fn new(name: &str, _tun_type: &str) -> std::io::Result<Self> {
            info!("Initializing macOS utun adapter: dev={}", name);
            #[cfg(feature = "vpn")]
            {
                use crate::ghost::net::vpn::tun::{MacOSUtun, TunDevice};
                let dev = MacOSUtun::new(name)?;
                struct MacOSUtunSession(MacOSUtun);
                impl TunSession for MacOSUtunSession {
                    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                        self.0.read_packet(buf)
                    }
                    fn write(&self, buf: &[u8]) -> std::io::Result<usize> {
                        self.0.write_packet(buf)
                    }
                    fn shutdown(&self) {
                        self.0.shutdown();
                    }
                }
                Ok(Self {
                    running: Arc::new(AtomicBool::new(true)),
                    session: Some(Box::new(MacOSUtunSession(dev))),
                    name: name.to_string(),
                })
            }
            #[cfg(not(feature = "vpn"))]
            {
                Err(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    "Compile with --features vpn to enable macOS utun adapter",
                ))
            }
        }

        pub fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if let Some(ref mut session) = self.session {
                session.read(buf)
            } else {
                Err(std::io::Error::new(
                    std::io::ErrorKind::NotConnected,
                    "utun device closed",
                ))
            }
        }

        pub fn write(&self, buf: &[u8]) -> std::io::Result<usize> {
            if let Some(ref session) = self.session {
                session.write(buf)
            } else {
                Err(std::io::Error::new(
                    std::io::ErrorKind::NotConnected,
                    "utun device closed",
                ))
            }
        }

        pub fn is_running(&self) -> bool {
            self.running.load(Ordering::Relaxed)
        }

        pub fn shutdown(&self) {
            self.running.store(false, Ordering::Relaxed);
            if let Some(ref session) = self.session {
                session.shutdown();
            }
        }

        pub fn name(&self) -> &str {
            &self.name
        }
    }
}

#[cfg(target_os = "macos")]
pub use macos_platform::TunAdapter;

#[cfg(all(
    not(target_os = "windows"),
    not(target_os = "linux"),
    not(target_os = "macos")
))]
pub struct TunAdapter;

#[cfg(all(
    not(target_os = "windows"),
    not(target_os = "linux"),
    not(target_os = "macos")
))]
impl TunAdapter {
    pub fn find_wintun_dll() -> Option<std::path::PathBuf> {
        None
    }

    pub fn is_wintun_installed() -> bool {
        false
    }

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

#[cfg(not(target_os = "windows"))]
pub fn is_wintun_installed() -> bool {
    false
}

#[cfg(not(target_os = "windows"))]
pub fn find_wintun_dll() -> Option<std::path::PathBuf> {
    None
}
