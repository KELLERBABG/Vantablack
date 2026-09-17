# macOS packaging

The Rust daemon builds for `aarch64-apple-darwin` and `x86_64-apple-darwin`.
The default desktop feature uses the native tao/wry shell; the headless binary
is suitable for launchd or a local SOCKS5 service.

```bash
rustup target add aarch64-apple-darwin x86_64-apple-darwin
cargo build --release --target aarch64-apple-darwin
cargo build --release --target x86_64-apple-darwin --no-default-features --bin ggn
```

A repository-side Network Extension target boundary is provided in
`packaging/macos/NetworkExtension/`: `GhostPacketTunnelProvider.swift`, its
`Info.plist`, and the required entitlements. The provider owns only Apple's
lifecycle and packet-flow settings; the Rust core remains entitlement-free and
must be linked through the signed host application's `VpnIngress`/`TunDevice`
bridge. Do not ship the checked-in skeleton as a production VPN until an Xcode
host target supplies that FFI bridge and Apple signs the provisioning profile.

The release gate is therefore split:

* archive and headless SOCKS builds are reproducible in CI;
* the Network Extension is signed and exercised on a macOS host with the
  `com.apple.developer.networking.networkextension` entitlement.
