# Wintun Real-Device Verification Checklist & Runbook

This runbook documents the manual verification procedure for running the **Vantablack VPN Subsystem** using a real Windows Wintun driver adapter (`wintun.dll`), fulfilling the requirement for production VPN assurance.

---

## 📋 Prerequisites

1. **Windows 10 / 11 or Windows Server 2019+** (x86_64 or ARM64).
2. **Administrator Privileges**: Creating virtual network adapters in the Windows kernel requires an elevated command prompt / PowerShell session.
3. **Wintun Driver**:
   - Download the official signed Wintun driver from [wintun.net](https://www.wintun.net/):
     ```powershell
     Invoke-WebRequest -Uri "https://www.wintun.net/builds/wintun-0.14.1.zip" -OutFile "wintun.zip"
     Expand-Archive -Path "wintun.zip" -DestinationPath "wintun-pkg"
     Copy-Item "wintun-pkg\wintun\bin\amd64\wintun.dll" -Destination "."
     ```
   - Place `wintun.dll` in one of:
     - The executable directory (alongside `vantablack.exe` / `ggn.exe`)
     - Working directory
     - `C:\Windows\System32\`
     - Anywhere in the system `%PATH%`

---

## 🔍 Verification Checklist

| Step | Action | Expected Result | Verified? |
|:---:|:---|:---|:---:|
| **1** | Run `vantablack --check-wintun` or check via integration test | `is_wintun_installed()` returns `true` and locates `wintun.dll` path. | [ ] |
| **2** | Launch daemon in an elevated prompt with `--vpn`: <br>`.\target\release\vantablack.exe --vpn --role client` | Daemon starts without driver loading error. Log states: `Found wintun.dll at ...` and `Successfully initialized Wintun adapter 'VantablackMesh'`. | [ ] |
| **3** | In a separate terminal, run `ipconfig /all` | A network adapter named `VantablackMesh` is visible with IPv4 `10.66.0.2` and subnet mask `255.255.255.0`. | [ ] |
| **4** | Send an ICMP echo ping to the gateway: <br>`ping -n 4 10.66.0.1` | Packets are read by the TUN driver session and transmitted across the mesh session. | [ ] |
| **5** | Stop the daemon (Ctrl+C or send SIGINT) | Process exits cleanly. `WintunEndSession` and `WintunDeleteAdapter` execute in `Drop`. `ipconfig` confirms adapter has been completely removed from the OS network stack. | [ ] |

---

## 🧪 Automated Verification in CI

The automated gate in `tests/vpn_wintun.rs` exercises this subsystem:
```powershell
# Run with VPN feature enabled:
cargo test --features vpn --test vpn_wintun -- --nocapture
```

- When `wintun.dll` is present in CI with elevation, the test creates the adapter, tests raw packet injection, verifies MTU = 1420, and releases the ring buffer.
- When `wintun.dll` is absent or unelevated, the test gates cleanly without panics.
