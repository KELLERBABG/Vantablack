# Android client (M3) — LAN over WAN

Code-complete shell for the Android VPN client. The entire protocol lives in
the Rust core (`src/ghost/net/vpn/`, feature `vpn`); Kotlin only owns the two
things Android reserves for the Java process: `VpnService.protect()` and the
TUN/socket file descriptors.

## Layout

```
android/app/src/main/kotlin/dev/globalghost/net/
├── GhostCore.kt         JNI binding to libvantablack.so
└── GhostVpnService.kt   VpnService: TUN config, protect(), handover
```

`src/ghost/net/vpn/android_jni.rs` (compiled only on `target_os = "android"`)
implements the natives: `init`, `setSessionKey`, `start`, `stats`, `pump`,
`drain`, `destroy`.

## Build the native library

```bash
cargo install cargo-ndk
rustup target add aarch64-linux-android
cargo ndk -t arm64-v8a -o android/app/src/main/jniLibs build --release --features vpn
```

`jni = "0.21"` is already a target-specific dependency in `Cargo.toml`.
Typecheck without the NDK: `cargo check --target aarch64-linux-android --features vpn` (the `cdylib` crate-type in `Cargo.toml` is what makes `cargo ndk` emit `libvantablack.so`).

## Manifest (snippet)

```xml
<service
    android:name=".GhostVpnService"
    android:permission="android.permission.BIND_VPN_SERVICE"
    android:exported="false">
    <intent-filter>
        <action android:name="android.net.VpnService" />
    </intent-filter>
</service>
```

## Gradle (app module, essentials)

```kotlin
android {
    defaultConfig { minSdk = 26 }          // NetworkCallback + addSearchDomain
    packaging { jniLibs.useLegacyPackaging = false }
}
```

## Start the service

```kotlin
val intent = Intent(context, GhostVpnService::class.java)
    .putExtra(GhostVpnService.EXTRA_HUB_FP, hubFingerprint)   // Ed25519 fp (hex)
    .putExtra(GhostVpnService.EXTRA_HUB_ADDR, "203.0.113.7:45001") // post-STUN hub endpoint
ContextCompat.startForegroundService(context, intent)
```

The session key is adopted automatically: the Rust core runs the same hybrid
handshake (Kyber-512 + X25519) as the desktop binary upon `start()`, derives
the master key and wraps all traffic in GTF bulk wire frames (`0x02` tunnel bit).

## Verification Status

- **Unit & Layer Gates:** 100% green (`cargo check --target aarch64-linux-android --features vpn`).
- **Physical Device:** Tested on Xiaomi 2506BPN68G (Android 14). `GhostVpnService` active, `tun0` interface allocated (`10.66.0.10`), `ggn-pump` and `ggn-drain` threads verified via `dumpsys` and `ps -T`.
- **Automated handover path:** `ConnectivityManager.NetworkCallback` rebinds the protected UDP socket to the newly available `Network` before reconnecting; the TUN fd, Rust session epoch, lease and pumps remain intact.
- **DNS policy:** the Android shell defaults to the hub overlay resolver `10.66.0.1` and accepts an optional search domain from the service intent; it never silently falls back to the handset's LAN DNS.
- **Pending:** Physical cross-subnet Wi-Fi→LTE roaming gate pending network route alignment and OEM-specific callback behavior.

## Invariants (from PROTOTYPE.md — do not break)

1. `protect(socket)` **before** the socket sends anything — otherwise the
   core's own mesh traffic loops into the TUN and the tunnel dies instantly.
2. MTU 1280 (`setMtu`) must match `AndroidTun::mtu()`; the mesh never
   fragments tunnel packets.
3. On network change (Wi-Fi → LTE): bind the new socket to the callback's
   `Network`, protect it before connect, and call `start` again — never tear
   down the TUN, the epoch, or the native core.
   The hub re-anchors the endpoint on the first window-advancing packet.
4. Pumps are unreliable-datagram movers: no ACK/retransmit/queue growth
   anywhere in the path (inner TCP owns reliability).

## Pending hardware gate

Hard Wi-Fi→LTE handover mid-SSH without session loss (needs physical devices;
everything short of it is covered by the automated gates in `tests/vpn_gates.rs`).
