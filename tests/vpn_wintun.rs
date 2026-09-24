#![cfg(feature = "vpn")]

//! Real Wintun TUN device gate & integration test.
//!
//! Verifies:
//! 1. `is_wintun_installed()` correctly detects the presence or absence of `wintun.dll`.
//! 2. If `wintun.dll` is absent, attempting to initialize real TUN mode fails cleanly
//!    with `ErrorKind::NotFound` and a helpful diagnostic message (no crash/hang).
//! 3. If `wintun.dll` is present:
//!    - With Administrator privileges (e.g. in CI or dedicated host):
//!      creates the real "VantablackTest" adapter, asserts MTU and name, tests
//!      frame injection/write, and cleanly tears it down.
//!    - Without Administrator privileges: returns `ErrorKind::PermissionDenied`
//!      without aborting or corrupting memory.
//! 4. Both `FakeTun` and `WintunTun` satisfy the generic [`TunDevice`] contract.

use std::net::Ipv4Addr;
use vantablack::ghost::net::tun as net_tun;
use vantablack::ghost::net::vpn::tun::{self as vpn_tun, FakeTun, TunDevice};

#[test]
fn test_wintun_detection_consistency() {
    let net_installed = net_tun::is_wintun_installed();
    let vpn_installed = vpn_tun::is_wintun_installed();
    assert_eq!(
        net_installed, vpn_installed,
        "net::tun and vpn::tun must report identical wintun installation status"
    );

    #[cfg(target_os = "windows")]
    {
        let dll_path = net_tun::find_wintun_dll();
        if net_installed {
            assert!(
                dll_path.is_some(),
                "find_wintun_dll must return Some when installed"
            );
            println!(
                "wintun.dll detected on host: {}",
                dll_path.unwrap().display()
            );
        } else {
            assert!(
                dll_path.is_none(),
                "find_wintun_dll must return None when not installed"
            );
            println!("wintun.dll is not present on host (standard non-VPN runner environment)");
        }
    }

    #[cfg(not(target_os = "windows"))]
    {
        assert!(
            !net_installed,
            "wintun is a Windows driver and must return false on non-Windows"
        );
    }
}

#[test]
fn test_wintun_device_or_graceful_gate() {
    #[cfg(target_os = "windows")]
    {
        let installed = net_tun::is_wintun_installed();
        if !installed {
            // Assert that attempting to create without wintun.dll gives NotFound
            let res = net_tun::TunAdapter::new("VantablackTest", "Tunnel");
            let err = match res {
                Err(e) => e,
                Ok(_) => panic!("expected missing wintun.dll to return error"),
            };
            assert_eq!(
                err.kind(),
                std::io::ErrorKind::NotFound,
                "missing wintun.dll must return NotFound error"
            );
            let msg = err.to_string();
            assert!(
                msg.contains("wintun.dll not found") || msg.contains("wintun.net"),
                "error message must guide user to wintun.dll: {msg}"
            );
            println!("PASS: Gracefully gated on missing wintun.dll");
            return;
        }

        // When wintun.dll IS present, attempt real device initialization
        let addr = Ipv4Addr::new(10, 66, 0, 2);
        let mask = Ipv4Addr::new(255, 255, 255, 0);

        match vpn_tun::WintunTun::new("VantablackTest", addr, mask) {
            Ok(tun) => {
                println!("SUCCESS: Initialized real Wintun adapter 'VantablackTest' with Admin privileges");
                assert_eq!(tun.name(), "VantablackTest");
                assert_eq!(tun.mtu(), vantablack::ghost::net::vpn::TUN_MTU);

                // Test injecting a synthetic IPv4 echo request frame
                let mut test_packet = [0u8; 84];
                test_packet[0] = 0x45; // IPv4, IHL = 5
                test_packet[1] = 0x00; // DSCP/ECN
                test_packet[2..4].copy_from_slice(&(84u16.to_be_bytes())); // total length
                test_packet[8] = 64; // TTL
                test_packet[9] = 1; // Protocol: ICMP
                test_packet[12..16].copy_from_slice(&[10, 66, 0, 2]); // src
                test_packet[16..20].copy_from_slice(&[10, 66, 0, 1]); // dst

                let written = tun.write_packet(&test_packet);
                assert!(
                    written.is_ok(),
                    "injecting packet to Wintun adapter succeeded"
                );
                assert_eq!(written.unwrap(), 84);

                // Clean teardown
                tun.shutdown();
                println!("PASS: Real Wintun adapter round-trip and teardown verified cleanly");
            }
            Err(e) => {
                // If not running as Admin, Windows returns PermissionDenied
                if e.kind() == std::io::ErrorKind::PermissionDenied {
                    println!(
                        "PASS: wintun.dll present; correctly received PermissionDenied because test is not elevated: {e}"
                    );
                } else {
                    panic!("Unexpected error initializing WintunTun: {e}");
                }
            }
        }
    }

    #[cfg(not(target_os = "windows"))]
    {
        let res = net_tun::TunAdapter::new("VantablackTest", "Tunnel");
        let err = match res {
            Err(e) => e,
            Ok(_) => panic!("expected non-windows to return error"),
        };
        assert_eq!(err.kind(), std::io::ErrorKind::Unsupported);
    }
}

#[test]
fn test_tun_device_contract_fake_tun() {
    let mut fake = FakeTun::new();
    assert_eq!(fake.mtu(), vantablack::ghost::net::vpn::TUN_MTU);
    assert_eq!(fake.name(), "fake0");

    let payload = vec![0x45, 0x00, 0x00, 0x14, 0x00, 0x01, 0x00, 0x00, 0x40, 0x06];
    fake.push_inbound(payload.clone());

    let mut buf = [0u8; 1500];
    let n = fake.read_packet(&mut buf).expect("read from FakeTun");
    assert_eq!(&buf[..n], &payload[..]);

    let written = fake.write_packet(&payload).expect("write to FakeTun");
    assert_eq!(written, payload.len());
    let drained = fake.drain_outbound();
    assert_eq!(drained.len(), 1);
    assert_eq!(drained[0], payload);

    fake.shutdown();
}
