# Vantablack (GGN) — Technisches Datenblatt & Keynote-Referenz
*Kompakte technische Fakten, Metriken und Argumente für Vortrag, Präsentation & Fachdiskussion.*

---

## 1. Systemübersicht & Stammdaten

| Parameter | Spezifikation / Wert |
|---|---|
| **System** | Vantablack (GGN) / `vantablack` |
| **Architektur-Typ** | Serverloses Post-Quantum Mesh-Overlay-Netzwerk |
| **Programmiersprache** | Rust (Edition 2021, Zero-Unsafe im Transportkern) |
| **Aktuelle Version** | `v0.6.0` (Inventions Track Complete) |
| **Testsuite** | 421 Unit-Tests (100 % Pass), 2 Integrations-Harnesses |
| **Lizenz** | MIT |
| **Offizielles Repository** | `https://github.com/KELLERBABG/Global-Ghost-Net` |
| **Webseite & Docs** | `https://ggn.kellersystems.dev/` |

---

## 2. Die 3 Kern-Axiome (Die Keynote-Botschaft)

1. **Zero-Trust & Zero-Gatekeeper:**  
   Kein Vermittlungsserver, keine Benutzerkonten, kein zentraler Koordinator (im Gegensatz zu Tailscale / Cloudflare). Peers authentifizieren sich rein kryptographisch über öffentliche Schlüssel.
2. **Post-Quantum Shatter-Routing (0-aus-1 Garantie):**  
   Jedes Datenpaket wird via Reed-Solomon RS(2,1) in 3 Bruchstücke (Shards) zerlegt und über getrennte Trägerwege (z. B. Glasfaser, LTE, Tor-Schaltkreise) gesendet.  
   *Metrik:* Ein einzelner abgefangener Shard enthält exakt **0 Bit Information** (Shannon-Entropie > 7,90 Bits/Byte).
3. **Metadaten-Blindheit (DPI-Immunität):**  
   Pakete besitzen keine statischen Protokoll-Header („Magic Bytes“). Jedes Paket ist uniform exakt 576 Bytes lang. Im Leerlauf fließt Poisson-Cover-Traffic. Für Zensoren ist der Datenverkehr von Leitungsrauschen nicht unterscheidbar.

---

## 3. Kryptographischer Stack (Schichten L0 bis L8)

| Schicht | Modul | Algorithmen & Standards | Zweck / Eigenschaft |
|---|---|---|---|
| **L0** | `l0_identity.rs` | Hybrid Ed25519 + ML-DSA-65 (NIST FIPS 204) | Quantensichere Identität; *Burnable Ghost IDs* verhindern Peer-Tracking über Netzwerkgrenzen. |
| **L1** | `l1_kem.rs` | Hybrid X25519 + ML-KEM-768 (NIST FIPS 203) | Gitterbasierter Schlüsseltausch; Elligator-artiger Handshake ohne Header-Signaturen. |
| **L2** | `l2_aead.rs` | ChaCha20-Poly1305 / XChaCha20 | Symmetrische Verschlüsselung mit 64-Bit Monotonic Nonces gegen Replay-Angriffe. |
| **L3** | `l3_shamir.rs` | Shamir Secret Sharing über $GF(256)$ | 3-aus-5 Schwellwert-Kryptographie für dezentrale Gruppen-Autorisierung. |
| **L4** | `l4_rs.rs` | Cauchy Reed-Solomon RS(2,1) über $GF(2^8)$ | Zerlegung in 3 Shards. Beliebige 2 rekonstruieren das Paket ohne Latenzverlust. |
| **L5** | `l5_noise.rs` | GhostMimic (Markov-Modellierung) | Generiert Poisson-verteilten Cover-Traffic ($\text{Exp}(\lambda)$) gegen Verkehrsmusteranalysen. |
| **L6** | `l6_session.rs` | 64-Bit Monotonic Sliding Window | Sitzungs-Zustandsverwaltung und Replay-Schutz bis über die 32-Bit-Grenze hinaus. |
| **L7** | `l7_ldpc.rs` | LDPC (Low-Density Parity-Check) | Adaptive Vorwärtsfehlerkorrektur für extrem verrauschte Kanäle (Funk/Satellit). |
| **L8** | `l8_memsec.rs` | `LockedMemory` + AES-256-XTS im RAM | Verhindert Speicherauslagerung (Swap) und überschreibt Schlüssel beim Löschen mit Nullen. |

---

## 4. Netzwerk- & Routing-Spezifikationen (Ghost Transport Framing v2)

- **Paket-Länge:** Strikt konstant **576 Bytes** (Standard-Privacy-Frame) bzw. 1472 Bytes (Bulk-Ethernet).
- **Protokoll-Overhead:** 0 zusätzliche Latenz bei Ausfall eines Übertragungswegs (Sofortige Rekonstruktion aus den 2 verbleibenden Shards).
- **Sitzungs-Ratchet:** Post-Quantum Double Ratchet pro Paket (`src/ghost/session/ratchet.rs`).
- **RAM-Epochen:** Temporäre Epochenschlüssel verfallen nach $T_{\text{epoch}}$ (z. B. 60 s); Altdaten sind mathematisch unwiderruflich unlesbar (*Forward Secrecy*).
- **Tunnel-Treiber:** `wintun.dll` (Windows Ring-0/Ring-3 TUN Driver) und native `/dev/net/tun` (Linux/macOS) mit integriertem Userspace-NAT und automatischem MSS-Clamping.

---

## 5. Das Inventions-Register (Keynote-Talking-Points)

Für die Bühne: Die wichtigsten Alleinstellungsmerkmale im Überblick:

- **§11 Shatter-Routing:** Shards wandern simultan über heterogene Schnittstellen (WLAN + Mobilfunk + Ethernet).
- **§22 & §33 Dead-Drop Vaults & Self-Eating Storage:**  
  Serverlose Schließfächer, adressiert über SHA-256-Commitments. Der Host speichert blinde Ciphertexts ohne Metadaten. Inaktive Daten zerfallen automatisch über Poisson-Fehlerraten-GC.
- **§27 Spatio-Temporale Erosions-Codes:**  
  Informationen verblassen gewollt über die Zeitachse. Zur Rekonstruktion müssen Schlüssel aus mindestens 2 verschiedenen Zeit-Epochen vorliegen.
- **§29 Windowing the Blackout (DTN):**  
  Automatischer Merkle-Tree Anti-Entropie-Abgleich nach Verbindungsunterbrechungen (Flugmodus, Zensur). Fehlmengen werden in $O(\log N)$ Schritten ohne Neu-Handshake synchronisiert.
- **§45 Anonyme Capability-Wirtschaft:**  
  3-aus-5 Gruppen-Gutscheine autorisieren Bandbreite und Weiterleitung vollkommen identitätsfrei und manipulationssicher gegen Double-Spending.
- **§50 Anti-Fragile Tarpits:**  
  Fehlgeschlagene Handshakes oder Angriffe verdoppeln die Proof-of-Work Rechenaufgabe für den Angreifer. Der Angreifer zahlt exponentiell mit eigener CPU-Zeit.
- **§51 Stego-in-Physics:**  
  Möglichkeit, einen Shard über verdeckte physikalische Kanäle (Ultraschall-FSK, CPU-Wärme-Modulation, LED-Blinken) zu übertragen, während zwei über das Netz laufen.

---

## 6. Verifikations- & Performanz-Nachweise (Zahlen für die Folien)

| Test-Kategorie | Prüfobjekt | Ergebnis / Messwert |
|---|---|---|
| **Bibliotheks-Tests** | `cargo test --features vpn --lib` | **421 Tests bestanden, 0 Fehler** |
| **Red-Team Simulator (§46)** | `tests/redteam_harness.rs` | **100 virtuelle Knoten**, 15 byzantinische Angreifer, 10 % Paketverlust &rarr; **100 % ehrliche Pakete rekonstruiert**, Laufzeit **0,01 s** |
| **Semantischer Fuzzer (§49)** | `tests/semantic_fuzzer.rs` | 4 Eigenschafts-Tests über 1.000+ permutierte Transaktionsfolgen (Dead-Drop, Merkle, Token) &rarr; **0 Invarianten-Verletzungen** |
| **Formaler Beweis (§47)** | `formal/shardsec_space_time.pv` | ProVerif 2.05: Mathematischer Beweis, dass 1 Shard oder 1 Epoche **0 Bit Information** leckt (`RESULT not attacker(secret_payload) is true`) |
| **Code-Formatierung** | `cargo fmt --all --check` | **100 % sauber, 0 Abweichungen** |

---

## 7. Der direkte Vergleich (Slide-Cheat-Sheet)

| Kriterium | Vantablack | WireGuard | Tailscale | Tor Network |
|---|---|---|---|---|
| **Post-Quantum Crypto** | **Hybrid Kyber-768 + Dilithium-65** | Nein (nur Curve25519) | Nein (nur Curve25519) | Nein (Curve25519 / RSA) |
| **Architektur** | **100 % serverloses Mesh (kein Account)** | Manuelle Punkt-zu-Punkt-Konfig | Zentraler Login-Koordinator | 9 Directory Authorities |
| **Datenverlust-Resilienz**| **RS(2,1) Erasure Sharding (0 ms Delay)** | TCP-Retransmit (Verzögerung) | TCP-Retransmit (Verzögerung) | Hohe Latenz, Circuit Stalls |
| **Verkehrsanalyse (DPI)** | **Uniform 576B + Poisson-Cover (Rauschen)**| Feste Paketlängen (erkennbar) | WireGuard-Fingerprints | Obfs4 Pluggable Transports |
| **RAM-Schutz** | **AES-256-XTS + Sofort-Nullung im RAM** | Kernel-Speicher unverschlüsselt | Standard Userspace-RAM | Standard Userspace-RAM |
| **Ausfall-Sync (DTN)** | **Merkle-Tree Reconciliation in $O(\log N)$**| Verbindung bricht ab | Re-Handshake nötig | Neuer 3-Hop Circuit nötig |

---

## 8. Was das Programm zum Laufen zwingend braucht

- **Windows:** `ggn.exe` + `wintun.dll` im selben Verzeichnis (Ring-0 TUN-Treiber).
- **Linux / macOS:** `ggn` / `wan_mesh` (benötigt `CAP_NET_ADMIN` für TUN-Zugriff).
- **Zero External Runtime:** Keine Laufzeitumgebungen, kein Node, kein Python, keine Datenbanken.
