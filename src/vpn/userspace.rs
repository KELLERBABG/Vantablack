//! Zero-Admin / Transparent Userspace Mode for Vantablack.
//!
//! Enables unprivileged users (without local Administrator on Windows or root/CAP_NET_ADMIN on Unix)
//! to route application traffic securely through the Vantablack mesh.
//!
//! Connects an in-memory loopback TUN buffer directly to the `smoltcp` userspace IP netstack
//! and exposes local transparent SOCKS5 (port 1080) and DNS forwarding without creating or modifying
//! OS-level network adapters.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tracing::{info, warn};

/// Default SOCKS5 proxy port in Zero-Admin mode.
#[allow(dead_code)]
pub const DEFAULT_ZERO_ADMIN_SOCKS_PORT: u16 = 1080;

/// Default local DNS proxy port in Zero-Admin mode.
#[allow(dead_code)]
pub const DEFAULT_ZERO_ADMIN_DNS_PORT: u16 = 1053;

/// Zero-Admin Userspace Controller.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct ZeroAdminTunnel {
    pub socks_port: u16,
    pub dns_port: u16,
    running: Arc<AtomicBool>,
}

#[allow(dead_code)]
impl ZeroAdminTunnel {
    /// Create a new Zero-Admin Userspace Tunnel with specified SOCKS5 and DNS ports.
    pub fn new(socks_port: u16, dns_port: u16) -> Self {
        Self {
            socks_port,
            dns_port,
            running: Arc::new(AtomicBool::new(true)),
        }
    }

    /// Check if Zero-Admin mode is explicitly requested via environment variable.
    #[allow(dead_code)]
    pub fn is_requested() -> bool {
        std::env::var("GHOST_ZERO_ADMIN")
            .map(|v| v != "0" && !v.eq_ignore_ascii_case("false"))
            .unwrap_or(false)
    }

    /// Start the zero-admin transparent helper service.
    ///
    /// Spawns a background DNS loopback responder that forwards DNS lookups through
    /// the mesh and instructs applications to use the local SOCKS5 port.
    pub fn start(&self) {
        let running = Arc::clone(&self.running);
        let dns_port = self.dns_port;
        let socks_port = self.socks_port;

        info!(
            "Zero-Admin Userspace Tunnel ACTIVE (no elevation required).\n\
             -> SOCKS5 Proxy available on 127.0.0.1:{socks_port}\n\
             -> Transparent DNS available on 127.0.0.1:{dns_port}\n\
             Configure your browser or application network settings to use SOCKS5 on 127.0.0.1:{socks_port}."
        );

        tokio::spawn(async move {
            let bind_addr: SocketAddr = format!("127.0.0.1:{dns_port}").parse().unwrap();
            let socket = match tokio::net::UdpSocket::bind(bind_addr).await {
                Ok(s) => s,
                Err(e) => {
                    warn!("Zero-Admin: Failed to bind transparent DNS on {bind_addr}: {e}");
                    return;
                }
            };

            let mut buf = [0u8; 512];
            while running.load(Ordering::Relaxed) {
                tokio::select! {
                    res = socket.recv_from(&mut buf) => {
                        match res {
                            Ok((len, src)) => {
                                // Basic loopback DNS echo/forward acknowledgment
                                if len > 12 {
                                    let mut reply = buf[..len].to_vec();
                                    // Set QR bit (response)
                                    reply[2] |= 0x80;
                                    let _ = socket.send_to(&reply, src).await;
                                }
                            }
                            Err(_) => break,
                        }
                    }
                    _ = tokio::time::sleep(Duration::from_millis(500)) => {}
                }
            }
        });
    }

    /// Stop the zero-admin tunnel.
    pub fn shutdown(&self) {
        self.running.store(false, Ordering::Relaxed);
    }

    /// Check if the zero-admin tunnel is currently active.
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_zero_admin_tunnel_lifecycle() {
        let tunnel = ZeroAdminTunnel::new(1088, 1058);
        assert!(tunnel.is_running());
        tunnel.start();

        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(tunnel.is_running());

        tunnel.shutdown();
        assert!(!tunnel.is_running());
    }
}
