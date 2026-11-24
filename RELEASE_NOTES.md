# Vantablack 2.1.8 — Signed Threat Feeds & VpnHub CIDR Blocking

Vantablack **v2.1.8** completes the Threat Shield & Anti-Abuse pipeline across Desktop and Android, removes the `v2.1.7` test seed, and ships signed Android release builds.

---

### 🛡️ Threat Shield & Signed Feed Distribution
* **Automatic HTTPS Feed Download & Caching:** Nodes configured with `GHOST_THREAT_FEED_URL` periodically download Ed25519-signed snapshots over HTTPS, verify against `GHOST_THREAT_FEED_KEY` before installing, and optionally cache verified snapshots to `GHOST_THREAT_FEED_PATH`.
* **VpnHub & Desktop TUN CIDR Blocking:** Enforces Threat Shield IP/CIDR blocks across `VpnHub` outbound TCP/UDP traffic as well as local Desktop TUN and SOCKS5 paths.
* **Clean Production Seed:** Removed the `qel.kellersystems.dev` test indicator from the built-in default shield.

---

### 🔐 Signed Android & Desktop Releases
* **Signed Android Release APK:** Built with `assembleRelease` using the official Vantablack release keystore.
* **Non-Blocking Background Updater:** Downloads updates in the background and installs when ready.
