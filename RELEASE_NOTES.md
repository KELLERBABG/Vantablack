# Vantablack 2.1.7 — Threat Shield, Background Updater & Signed Android Releases

Vantablack **v2.1.7** brings **Threat / Malware Shield** to both Desktop and Android, adds non-blocking background updates, and ships Android APKs signed with the official release keystore.

---

### 🛡️ Threat / Malware Shield & Pullback Whitelist (Desktop & Android)
* **Local DNS, SNI & SOCKS5 Enforcement:** Inspects DNS queries (`NXDOMAIN`), DoT/DoQ (`853`), and TLS `ClientHello` SNI directly on the Desktop TUN (`src/daemon/node.rs`), Android VPN (`android_jni.rs`), SOCKS5 proxy, and exit hubs.
* **Android UI & Pullback Controls:** Added the **Threat / Malware Shield** toggle and **Threat Shield Pullback & Whitelist** card to Android (`MainActivity.kt`) alongside the Desktop dashboard (`Settings → General`).
* **Ed25519-Signed Feed Loader & Egress Policy:** Supports signed threat feed snapshots with automatic CIDR expiry pruning, exit egress policy enforcement, and `qel.kellersystems.dev` seeded as a built-in test indicator.

---

### ⬇️ Non-Blocking Background Updater
* **Download on the Side, Install When Ready:** Checking for updates now downloads the new installer/APK in the background on both Desktop and Android instead of forcing an immediate pull and restart.

---

### 🔐 Signed Android Release APKs
* **Official Release Signing:** Android release builds now run `assembleRelease` signed with the Vantablack release keystore so future updates upgrade cleanly in place.
* *(Note: If upgrading from `v2.1.6` or earlier debug-signed APKs, uninstall the old APK once before installing `v2.1.7`.)*
