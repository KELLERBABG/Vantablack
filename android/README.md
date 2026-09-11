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
handshake as the desktop binary and `setSessionKey` is called on completion
(wire it in your handshake callback; see `ClientState::set_key`).

## Invariants (from PROTOTYPE.md — do not break)

1. `protect(socket)` **before** the socket sends anything — otherwise the
   core's own mesh traffic loops into the TUN and the tunnel dies instantly.
2. MTU 1280 (`setMtu`) must match `AndroidTun::mtu()`; the mesh never
   fragments tunnel packets.
3. On network change (Wi-Fi → LTE): rebuild the protected socket and call
   `start` again — never tear down the TUN, the epoch, or the native core.
   The hub re-anchors the endpoint on the first window-advancing packet.
4. Pumps are unreliable-datagram movers: no ACK/retransmit/queue growth
   anywhere in the path (inner TCP owns reliability).

## Pending hardware gate

Hard Wi-Fi→LTE handover mid-SSH without session loss (needs physical devices;
everything short of it is covered by the automated gates in `tests/vpn_gates.rs`).
