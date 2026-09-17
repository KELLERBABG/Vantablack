//! TUN device backends for the VPN client (PROTOTYPE.md M1/M3).
//!
//! - Windows: wintun.dll FFI (official WireGuard driver). Requires
//!   Administrator to create the adapter. DLL located via the same search
//!   order the old stub used (exe dir → cwd → System32 → PATH).
//! - Unix: /dev/net/tun via ioctl TUNSETIFF (Linux); needs CAP_NET_ADMIN.
//!
//! Both implement [`TunDevice`] so the mesh pump (`vpn::client`) is
//! platform-agnostic and testable with a fake backend.

use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// Abstract TUN device: read one IP packet, write one IP packet.
pub trait TunDevice: Send {
    /// Blocking-ish read of the next IP packet from the OS. Returns size.
    fn read_packet(&mut self, buf: &mut [u8]) -> std::io::Result<usize>;
    /// Inject an IP packet into the OS stack.
    fn write_packet(&self, buf: &[u8]) -> std::io::Result<usize>;
    fn mtu(&self) -> u16;
    fn shutdown(&self);
    fn name(&self) -> &str;
}

pub const DEFAULT_MTU: u16 = crate::ghost::net::vpn::TUN_MTU;

// ── Windows: wintun FFI ─────────────────────────────────────────────

#[cfg(windows)]
mod wintun {
    use super::*;
    use std::ffi::{c_void, CString};
    use std::path::PathBuf;

    type Handle = *mut c_void;

    #[link(name = "kernel32")]
    extern "system" {
        fn LoadLibraryA(name: *const i8) -> Handle;
        fn GetProcAddress(lib: Handle, name: *const i8) -> *mut c_void;
        fn FreeLibrary(lib: Handle) -> i32;
    }

    // wintun.dll exports (wintun 0.14) are resolved at runtime via
    // GetProcAddress in WintunTun::new — no import-table linkage, so there is
    // deliberately no extern block here. Signatures (wintun.h):
    //   WintunCreateAdapter(*const u16, *const u16, *const u8, *mut Handle) -> BOOL
    //   WintunDeleteAdapter(Handle) -> BOOL
    //   WintunStartSession(Handle, u32) -> Handle / WintunEndSession(Handle)
    //   WintunGetReadWaitEvent(Handle) -> Handle
    //   WintunReceivePacket(Handle, *mut u32) -> *mut u8 / WintunReleaseReceivePacket(Handle, *mut u8)
    //   WintunSendPacket(Handle, *const u8, u32) -> BOOL
    //   WintunOpenAdapter(*const u16) -> Handle

    pub struct WintunTun {
        lib: Handle,
        adapter: Handle,
        session: Handle,
        name: String,
        running: Arc<AtomicBool>,
    }

    unsafe impl Send for WintunTun {}
    unsafe impl Sync for WintunTun {}

    /// Locate wintun.dll (exe dir → cwd → System32 → PATH).
    pub fn find_dll() -> Option<PathBuf> {
        let mut candidates: Vec<PathBuf> = Vec::new();
        if let Ok(exe) = std::env::current_exe() {
            if let Some(d) = exe.parent() {
                candidates.push(d.join("wintun.dll"));
            }
        }
        if let Ok(cwd) = std::env::current_dir() {
            candidates.push(cwd.join("wintun.dll"));
        }
        if let Ok(sysroot) = std::env::var("SystemRoot") {
            candidates.push(PathBuf::from(sysroot).join("System32").join("wintun.dll"));
        }
        if let Ok(path) = std::env::var("PATH") {
            for dir in std::env::split_paths(&path) {
                candidates.push(dir.join("wintun.dll"));
            }
        }
        candidates.into_iter().find(|p| p.exists())
    }

    impl WintunTun {
        /// Create adapter + start session. Administrator required.
        pub fn new(name: &str, addr: Ipv4Addr, mask: Ipv4Addr) -> std::io::Result<Self> {
            let dll = find_dll().ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "wintun.dll not found — place next to executable (wintun.net)",
                )
            })?;
            let cstr = CString::new(dll.to_string_lossy().as_bytes()).unwrap();
            let lib = unsafe { LoadLibraryA(cstr.as_ptr()) };
            if lib.is_null() {
                return Err(std::io::Error::last_os_error());
            }
            // resolve functions we call through GetProcAddress to avoid
            // import-table requirements on the DLL
            unsafe fn sym(lib: Handle, name: &str) -> std::io::Result<*mut c_void> {
                let c = CString::new(name).unwrap();
                let p = GetProcAddress(lib, c.as_ptr());
                if p.is_null() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        format!("wintun export missing: {name}"),
                    ));
                }
                Ok(p)
            }
            unsafe {
                let create: unsafe extern "system" fn(
                    *const u16,
                    *const u16,
                    *const u8,
                    *mut Handle,
                ) -> i32 = std::mem::transmute(sym(lib, "WintunCreateAdapter")?);
                let start: unsafe extern "system" fn(Handle, u32) -> Handle =
                    std::mem::transmute(sym(lib, "WintunStartSession")?);

                let wname: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
                let wtype: Vec<u16> = "Tunnel".encode_utf16().chain(std::iter::once(0)).collect();
                let mut adapter: Handle = std::ptr::null_mut();
                if create(
                    wname.as_ptr(),
                    wtype.as_ptr(),
                    std::ptr::null(),
                    &mut adapter,
                ) == 0
                    || adapter.is_null()
                {
                    FreeLibrary(lib);
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        "WintunCreateAdapter failed (run as Administrator)",
                    ));
                }
                let session = start(adapter, 0x400_000); // 4 MiB ring
                if session.is_null() {
                    if let Ok(p) = sym(lib, "WintunDeleteAdapter") {
                        let del: unsafe extern "system" fn(Handle) -> i32 = std::mem::transmute(p);
                        del(adapter);
                    }
                    FreeLibrary(lib);
                    return Err(std::io::Error::last_os_error());
                }
                // configure IPv4 via netsh (best-effort; needs admin)
                let _ = std::process::Command::new("netsh")
                    .args([
                        "interface",
                        "ip",
                        "set",
                        "address",
                        &format!("name={name}"),
                        "static",
                        &addr.to_string(),
                        &mask.to_string(),
                    ])
                    .status();
                Ok(Self {
                    lib,
                    adapter,
                    session,
                    name: name.to_string(),
                    running: Arc::new(AtomicBool::new(true)),
                })
            }
        }
    }

    impl TunDevice for WintunTun {
        fn read_packet(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            unsafe {
                let recv: unsafe extern "system" fn(Handle, *mut u32) -> *mut u8 = {
                    let c = CString::new("WintunReceivePacket").unwrap();
                    std::mem::transmute(GetProcAddress(self.lib, c.as_ptr()))
                };
                let release: unsafe extern "system" fn(Handle, *mut u8) = {
                    let c = CString::new("WintunReleaseReceivePacket").unwrap();
                    std::mem::transmute(GetProcAddress(self.lib, c.as_ptr()))
                };
                let mut size: u32 = 0;
                let pkt = recv(self.session, &mut size);
                if pkt.is_null() {
                    // no packet available; brief sleep instead of event wait
                    // (the pump loop handles pacing)
                    std::thread::sleep(std::time::Duration::from_millis(1));
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::WouldBlock,
                        "no packet",
                    ));
                }
                let n = (size as usize).min(buf.len());
                std::ptr::copy_nonoverlapping(pkt, buf.as_mut_ptr(), n);
                release(self.session, pkt);
                Ok(n)
            }
        }

        fn write_packet(&self, buf: &[u8]) -> std::io::Result<usize> {
            unsafe {
                let send: unsafe extern "system" fn(Handle, *const u8, u32) -> i32 = {
                    let c = CString::new("WintunSendPacket").unwrap();
                    std::mem::transmute(GetProcAddress(self.lib, c.as_ptr()))
                };
                if send(self.session, buf.as_ptr(), buf.len() as u32) == 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(buf.len())
            }
        }

        fn mtu(&self) -> u16 {
            DEFAULT_MTU
        }

        fn shutdown(&self) {
            self.running.store(false, Ordering::Relaxed);
        }

        fn name(&self) -> &str {
            &self.name
        }
    }

    impl Drop for WintunTun {
        fn drop(&mut self) {
            unsafe {
                let end: Option<unsafe extern "system" fn(Handle)> = {
                    let c = CString::new("WintunEndSession").unwrap();
                    std::mem::transmute(GetProcAddress(self.lib, c.as_ptr()))
                };
                let del: Option<unsafe extern "system" fn(Handle) -> i32> = {
                    let c = CString::new("WintunDeleteAdapter").unwrap();
                    std::mem::transmute(GetProcAddress(self.lib, c.as_ptr()))
                };
                let close: Option<unsafe extern "system" fn(Handle) -> i32> = {
                    let c = CString::new("FreeLibrary").unwrap();
                    std::mem::transmute(GetProcAddress(self.lib, c.as_ptr()))
                };
                if let Some(end) = end {
                    end(self.session);
                }
                if let Some(del) = del {
                    del(self.adapter);
                }
                if let Some(close) = close {
                    close(self.lib);
                }
            }
        }
    }
}

#[cfg(windows)]
pub use wintun::{find_dll, WintunTun};

// ── Unix: /dev/net/tun ──────────────────────────────────────────────

#[cfg(unix)]
mod unixtun {
    use super::*;
    use std::ffi::CString;

    // ioctl numbers (Linux)
    const TUNSETIFF: u64 = 0x400454ca;
    const IFF_TUN: u16 = 0x0001;
    const IFF_NO_PI: u16 = 0x1000;

    extern "C" {
        fn ioctl(fd: i32, req: u64, ...) -> i32;
        fn open(path: *const std::ffi::c_char, flags: i32) -> i32;
        fn close(fd: i32) -> i32;
    }

    pub struct UnixTun {
        fd: i32,
        name: String,
        running: Arc<AtomicBool>,
    }

    unsafe impl Send for UnixTun {}
    unsafe impl Sync for UnixTun {}

    impl UnixTun {
        pub fn new(name: &str) -> std::io::Result<Self> {
            let path = CString::new("/dev/net/tun").unwrap();
            // O_RDWR = 2
            let fd = unsafe { open(path.as_ptr(), 2) };
            if fd < 0 {
                return Err(std::io::Error::last_os_error());
            }
            let mut ifr = [0u8; 40];
            let bytes = name.as_bytes();
            ifr[..bytes.len()].copy_from_slice(bytes);
            let flags = IFF_TUN | IFF_NO_PI;
            ifr[16] = flags as u8;
            ifr[17] = (flags >> 8) as u8;
            let ret = unsafe { ioctl(fd, TUNSETIFF, ifr.as_mut_ptr()) };
            if ret < 0 {
                unsafe { close(fd) };
                return Err(std::io::Error::last_os_error());
            }
            // best-effort address config
            let _ = std::process::Command::new("ip")
                .args(["addr", "add", "10.66.0.10/24", "dev", name])
                .status();
            let _ = std::process::Command::new("ip")
                .args(["link", "set", "dev", name, "up"])
                .status();
            Ok(Self {
                fd,
                name: name.to_string(),
                running: Arc::new(AtomicBool::new(true)),
            })
        }
    }

    impl TunDevice for UnixTun {
        fn read_packet(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            // read(2)
            unsafe fn read_raw(fd: i32, buf: *mut u8, len: usize) -> isize {
                extern "C" {
                    fn read(fd: i32, buf: *mut c_void, count: usize) -> isize;
                }
                use std::ffi::c_void;
                read(fd, buf as *mut c_void, len)
            }
            let n = unsafe { read_raw(self.fd, buf.as_mut_ptr(), buf.len()) };
            if n < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(n as usize)
        }

        fn write_packet(&self, buf: &[u8]) -> std::io::Result<usize> {
            unsafe fn write_raw(fd: i32, buf: *const u8, len: usize) -> isize {
                extern "C" {
                    fn write(fd: i32, buf: *const c_void, count: usize) -> isize;
                }
                use std::ffi::c_void;
                write(fd, buf as *mut c_void, len)
            }
            let n = unsafe { write_raw(self.fd, buf.as_ptr(), buf.len()) };
            if n < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(n as usize)
        }

        fn mtu(&self) -> u16 {
            DEFAULT_MTU
        }

        fn shutdown(&self) {
            self.running.store(false, Ordering::Relaxed);
        }

        fn name(&self) -> &str {
            &self.name
        }
    }

    impl Drop for UnixTun {
        fn drop(&mut self) {
            unsafe { close(self.fd) };
        }
    }
}

#[cfg(unix)]
pub use unixtun::UnixTun;

// ── Platform TUN + the zero-elevation fake backend ──────────────────

#[cfg(windows)]
pub type RealTun = WintunTun;
#[cfg(unix)]
pub type RealTun = UnixTun;

#[cfg(not(any(windows, unix)))]
compile_error!("VPN client requires windows or unix");

/// The client's TUN device.
///
/// `Real` is the platform device (wintun.dll on Windows, `/dev/net/tun` on
/// Unix) and needs Administrator or CAP_NET_ADMIN. `Fake` is the in-memory
/// [`FakeTun`], selected by `GHOST_VPN_FAKE_TUN`, which lets a full client run
/// with **no privileges and no OS interface** — the vehicle for the two-process
/// loopback self-test that PROTOTYPE.md lists as the outstanding
/// "nothing is wire-proven yet" gate.
pub enum PlatformTun {
    Real(RealTun),
    Fake(FakeTun),
}

impl TunDevice for PlatformTun {
    fn read_packet(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            PlatformTun::Real(t) => t.read_packet(buf),
            PlatformTun::Fake(t) => t.read_packet(buf),
        }
    }
    fn write_packet(&self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            PlatformTun::Real(t) => t.write_packet(buf),
            PlatformTun::Fake(t) => t.write_packet(buf),
        }
    }
    fn mtu(&self) -> u16 {
        match self {
            PlatformTun::Real(t) => t.mtu(),
            PlatformTun::Fake(t) => t.mtu(),
        }
    }
    fn shutdown(&self) {
        match self {
            PlatformTun::Real(t) => t.shutdown(),
            PlatformTun::Fake(t) => t.shutdown(),
        }
    }
    fn name(&self) -> &str {
        match self {
            PlatformTun::Real(t) => t.name(),
            PlatformTun::Fake(t) => t.name(),
        }
    }
}

/// Open the real platform TUN named `name` with address `addr`.
pub fn open_tun(name: &str, addr: Ipv4Addr, mask: Ipv4Addr) -> std::io::Result<PlatformTun> {
    #[cfg(windows)]
    {
        let _ = mask;
        WintunTun::new(name, addr, mask).map(PlatformTun::Real)
    }
    #[cfg(unix)]
    {
        let _ = (addr, mask);
        UnixTun::new(name).map(PlatformTun::Real)
    }
}

/// Open the zero-elevation fake TUN.
///
/// Returns the device for the pump plus a shared handle: cloning a `FakeTun`
/// shares the same queues, so the caller can inject packets the "OS" would have
/// written and observe everything the tunnel writes back.
pub fn open_fake_tun() -> (PlatformTun, FakeTun) {
    let t = FakeTun::new();
    (PlatformTun::Fake(t.clone()), t)
}

// ── Fake backend (tests + GHOST_VPN_FAKE_TUN) ───────────────────────

/// In-memory TUN: reads drain a queue, writes fill another.
#[derive(Clone)]
pub struct FakeTun {
    inbound: Arc<parking_lot::Mutex<std::collections::VecDeque<Vec<u8>>>>,
    outbound: Arc<parking_lot::Mutex<Vec<Vec<u8>>>>,
    name: String,
}

impl FakeTun {
    pub fn new() -> Self {
        Self {
            inbound: Arc::new(parking_lot::Mutex::new(std::collections::VecDeque::new())),
            outbound: Arc::new(parking_lot::Mutex::new(Vec::new())),
            name: "fake0".into(),
        }
    }
    /// Queue a packet the "OS" wrote (next read returns it).
    pub fn push_inbound(&self, pkt: Vec<u8>) {
        self.inbound.lock().push_back(pkt);
    }
    /// Drain everything the mesh pump injected "into the OS".
    pub fn drain_outbound(&self) -> Vec<Vec<u8>> {
        std::mem::take(&mut *self.outbound.lock())
    }
}

impl Default for FakeTun {
    fn default() -> Self {
        Self::new()
    }
}

impl TunDevice for FakeTun {
    fn read_packet(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self.inbound.lock().pop_front() {
            Some(p) => {
                let n = p.len().min(buf.len());
                buf[..n].copy_from_slice(&p[..n]);
                Ok(n)
            }
            None => Err(std::io::Error::new(std::io::ErrorKind::WouldBlock, "empty")),
        }
    }

    fn write_packet(&self, buf: &[u8]) -> std::io::Result<usize> {
        self.outbound.lock().push(buf.to_vec());
        Ok(buf.len())
    }

    fn mtu(&self) -> u16 {
        DEFAULT_MTU
    }

    fn shutdown(&self) {}

    fn name(&self) -> &str {
        &self.name
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fake_tun_roundtrip() {
        let mut t = FakeTun::new();
        t.push_inbound(vec![0x45, 1, 2, 3]);
        let mut buf = [0u8; 64];
        let n = TunDevice::read_packet(&mut t, &mut buf).unwrap();
        assert_eq!(&buf[..n], &[0x45, 1, 2, 3]);
        TunDevice::write_packet(&t, &[9, 9]).unwrap();
        assert_eq!(t.drain_outbound(), vec![vec![9, 9]]);
        assert!(matches!(
            TunDevice::read_packet(&mut t, &mut buf),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock
        ));
    }

    #[cfg(windows)]
    #[test]
    fn wintun_dll_locator_finds_something_or_none() {
        // smoke: the locator must not panic; may find the Tailscale copy
        let _ = find_dll();
    }
}
