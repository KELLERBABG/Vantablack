# Vantablack 2.0.1 — Monolith Coal & Connected Liquid Tracks QR Release

Vantablack **v2.0.1** introduces the redesigned **Monolith Coal** experience across Desktop (`.exe` / Linux / macOS) and Android (`.apk`), paired with Vantablack's signature **Connected Liquid Tracks QR** onboarding and a hardened one-tap software updater.

---

### 🌑 Monolith Coal Interface (Desktop & Android)
* **Spotlight Coal Architecture:** Clean, effortless spotlight coal surface (`#232428 -> #141518 -> #0C0D0F`) with warm ivory (`#F4F1EA`) typography and zero technical clutter.
* **Machined Brushed-Steel Center Button:** Tactile circular protection button with warm ivory status indicator light, flanked by **Location** and **Mode** (`Fast`, `Stealth`, `Multi-Hop`).
* **Floating Bottom Pill Dock:** Instant one-click access to location selection, **+ Pair Phone (QR)**, **Devices**, and **Settings**.

---

### 👻 Connected Liquid Tracks QR & Stealth Visor Ghost
* **Custom Vantablack QR Geometry:** Circular finder eyes and fused horizontal liquid pill tracks on a warm ivory card (`#EAE6DC`) with the **Stealth Visor Ghost** center emblem (`#DCFF02` visor glint).
* **Built-In Android Camera Scanner & Deep Links:** Bundles an embedded ZXing camera QR scanner directly inside the Android app (no external scanner app required) plus native system camera deep-link support for `vb://`, `vb-net://`, and `vb-fleet://` URIs.

---

### ⚡ Reliable One-Tap Self-Updater
* **Windows Self-Updater (`ggn.exe`):** Detached background updater waits for the running process to release file locks, runs the Inno Setup upgrade silently, updates portable binaries in place if launched outside `%LOCALAPPDATA%`, and automatically relaunches Vantablack.
* **Android In-App Updater (`v2.0.1`, `versionCode 201`):** Follows cross-host GitHub Release redirects reliably, prefers `vantablack-*-android.apk`, and automatically resumes APK installation upon returning from Android's unknown-sources permission screen.
