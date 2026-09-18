# Global Ghost Net (GGN) — Technisches Whitepaper
*Ein dezentrales, post-quantensicheres und metadatenfreies Mesh-Overlay-Netzwerk*

**Autor / Maintainer:** KELLERBABG (`contact@kellersystems.dev`)  
**Version:** 0.6.0  
**Datum:** September 2026  
**Status:** Produktionsnah & Vollständig Verifiziert  

---

## Inhaltsverzeichnis
1. [Was ist Global Ghost Net? (Einführung & Motivation)](#1-was-ist-global-ghost-net)
2. [Die Kernmechanismen: Wie funktioniert GGN?](#2-die-kernmechanismen-wie-funktioniert-ggn)
   - 2.1 Das 2-aus-3 Reed-Solomon Erasure Sharding
   - 2.2 Multipath- & Shatter-Routing
   - 2.3 Post-Quantum Hybrid-Kryptographie (NIST FIPS 203 & 204)
   - 2.4 Epochen, Ratchets & Selbstzerstörende Schlüssel
   - 2.5 Metadaten-Blindheit & Uniforme Wire-Frames (GTF v2)
   - 2.6 Serverlose Dead-Drop Speicher & DTN-Ausfall-Synchronisation
   - 2.7 Anti-Fragile Tarpits (Angreifer-Rechenstrafen)
3. [Datei- und Modul-Übersicht: Was macht welche Datei?](#3-datei--und-modul-%C3%BCbersicht)
   - 3.1 Das Herzstück (`src/main.rs`, `src/lib.rs`)
   - 3.2 Die kryptographischen Schichten (`src/ghost/layers/`)
   - 3.3 Netzwerk- & Routing-Module (`src/ghost/net/`)
   - 3.4 Sitzungsverwaltung (`src/ghost/session/`)
   - 3.5 Testbed, Formales Modell & Fuzzing (`deploy/`, `formal/`, `tests/`)
4. [Was braucht das Programm zwingend, um zu funktionieren? (Housekeeping)](#4-lebenswichtige-abh%C3%A4ngigkeiten)
5. [Kompilierung, Tests & Inbetriebnahme](#5-kompilierung-tests--inbetriebnahme)

---

## 1. Was ist Global Ghost Net?

### Die Ausgangslage: Wie das moderne Internet überwacht wird
Herkömmliche Netzwerk- und VPN-Architekturen (wie OpenVPN, IPsec, Tailscale oder Cloudflare WARP) weisen drei grundlegende Schwachstellen auf:

1. **Zentrale Gatekeeper & Konten:** Nahezu alle modernen Mesh-Netzwerke erfordern eine Anmeldung bei einem zentralen Koordinationsdienst (z. B. Tailscale Coordination Server, Google/Microsoft-Logins). Fällt dieser Server aus oder wird er behördlich beschlagnahmt, bricht das gesamte Netzwerk zusammen.
2. **Metadaten- & Verkehrsanalyse (Traffic Analysis):** Selbst wenn Paket-Nutzdaten verschlüsselt sind, sehen Internet-Provider und staatliche Zensoren (mittels *Deep Packet Inspection*, DPI) genau, wer wann mit wem spricht, wie lang die Pakete sind und wie oft kommuniziert wird.
3. **Die Bedrohung durch Quantencomputer (*Harvest Now, Decrypt Later*):** Geheimdienste weltweit schneiden verschlüsselten Datenverkehr bereits heute im großen Stil mit. Sobald in einigen Jahren leistungsfähige Quantencomputer existieren, können klassische Verschlüsselungen (wie RSA oder Elliptic Curves wie Curve25519) rückwirkend entschlüsselt werden.

### Die Lösung: Global Ghost Net (GGN)
Global Ghost Net ist ein von Grund auf in Rust geschriebenes, **vollkommen dezentrales Mesh-Netzwerk**, das ohne Server, ohne Konten, ohne Registrierungen und ohne zentrales Verzeichnis auskommt. 

Zwei Computer (z. B. Ihr Laptop unterwegs und Ihr Heimserver) finden sich automatisch direkt, bauen eine militärisch abgesicherte Verbindung auf und tauschen Daten aus. Dabei ist der Datenverkehr auf der Leitung von zufälligem Rauschen nicht unterscheidbar.

---

## 2. Die Kernmechanismen: Wie funktioniert GGN?

### 2.1 Das 2-aus-3 Reed-Solomon Erasure Sharding
Das absolute Alleinstellungsmerkmal von GGN ist, dass ein Paket niemals als ein einzelner Block über eine einzige Leitung gesendet wird. 

Jede Nachricht wird in **drei mathematische Bruchstücke (Shards)** zerlegt:
- Shard 0 (Daten-Teil 1)
- Shard 1 (Daten-Teil 2)
- Shard 2 (Paritäts-Teil via Reed-Solomon RS(2,1))

**Die mathematische Eigenschaft:**
- Aus **beliebigen 2 der 3 Shards** kann der Empfänger das Originalpaket in Mikrosekunden vollständig und fehlerfrei wiederherstellen.
- Hält ein Angreifer nur **einen einzigen Shard**, so enthält dieser mathematisch **0 Bit Information** über die Originalnachricht (reine Zufallswerte mit maximaler Shannon-Entropie).

### 2.2 Multipath- & Shatter-Routing
Die drei Shards werden über drei **vollständig unabhängige Wege** geschickt:
- Shard 0 über Ihren normalen Internet-Provider (z. B. Glasfaser).
- Shard 1 über mobile Mobilfunkdaten (LTE/5G) oder ein Relay.
- Shard 2 über ein drittes Relay, einen Tor-Schaltkreis oder ein lokales Peer-Gerät.

**Die Sicherheitsgarantie:**
Ein Angreifer oder Geheimdienst, der ein einzelnes Glasfaserkabel oder einen Internet-Knotenpunkt überwacht, sieht nur einen einzigen Shard. Er kann die Daten niemals entschlüsseln. Verliert eine Leitung ein Paket (z. B. durch Funklöcher), kommt die Nachricht dank der anderen beiden Shards trotzdem ohne jegliche Verzögerung beim Empfänger an.

### 2.3 Post-Quantum Hybrid-Kryptographie
GGN setzt nicht auf experimentelle Eigenbauten, sondern kombiniert standardisierte, zukunftssichere Verfahren nach **NIST FIPS 203 / 204**:
- **ML-KEM-768 (Kyber):** Post-Quanten-Gitterbasierter Schlüsselaustausch.
- **ML-DSA-65 (Dilithium):** Post-Quanten-Signaturen für Identitätsnachweise.
- **X25519 & Ed25519:** Bewährte klassische elliptische Kurven als zusätzliche Sicherheitsschicht.

Beide Algorithmen werden miteinander verschmolzen: Selbst wenn eines Tages ein Quantencomputer die elliptische Kurve bricht, hält die Gitterkryptographie den Angreifer auf.

### 2.4 Epochen, Ratchets & Selbstzerstörende Schlüssel
- **Double Ratchet:** Nach jedem einzelnen Paket wird der Verschlüsselungsschlüssel unidirektional weitergedreht. Wurde ein Schlüssel kompromittiert, kann kein früheres Paket entschlüsselt werden (*Forward Secrecy*).
- **Selbstzerstörende Epochen im RAM (`SecureMemGuard`):** Schlüssel existieren ausschließlich im flüchtigen Arbeitsspeicher (RAM) und werden mit AES-256-XTS gegen Kaltstart- und Speicherauszugs-Attacken geschützt. Nach Ablauf der Gültigkeit (z. B. 60 Sekunden) werden die Speicherbereiche sofort mit Nullen überschrieben. Selbst wenn ein Computer physisch beschlagnahmt wird, sind alte Schlüssel physikalisch vernichtet.

### 2.5 Metadaten-Blindheit & Uniforme Wire-Frames (GTF v2)
- **Konstante 576-Byte Pakete:** Jedes Paket im GGN-Netzwerk ist exakt 576 Bytes lang. Ein Chat-Ping, ein Teil einer Website oder ein Video-Frame sehen auf der Leitung auf das Byte genau identisch aus.
- **Poisson-Rauschen (Cover Traffic):** In Leerlaufzeiten generiert der Daemon winzige Fake-Pakete nach einer mathematischen Poisson-Verteilung. Ein Beobachter kann nicht feststellen, ob Sie gerade gigabyteweise Daten übertragen oder ob Ihr Gerät untätig im Raum steht.
- **Keine Protokoll-Header ("Magic Bytes"):** Herkömmliche VPNs haben Identifikatoren wie `OpenVPN` oder `WireGuard` im Header. GGN-Pakete besitzen keinerlei magische Bytes und sehen für DPI-Firewalls wie statistisches weißes Rauschen aus.

### 2.6 Serverlose Dead-Drop Speicher & DTN-Ausfall-Synchronisation
- **Autonome Schließfächer (§22 Dead-Drop):** Shards können auf Zwischenstationen (Vaults) abgelegt werden. Der Host sieht nur einen 576-Byte-Ciphertext-Block und eine SHA-256-Prüfsumme, weiß aber weder, von wem das Paket stammt, noch für wen es ist.
- **Ausfall-Synchronisation (§29 DTN):** Wenn ein Gerät längere Zeit offline war (z. B. Flugmodus, Netzzensur), synchronisieren sich die Peers nach Wiederverbindung mittels Merkle-Bäumen in $O(\log N)$ Schritten, ohne redundante Daten zu übertragen.

### 2.7 Anti-Fragile Tarpits (§50)
Wenn ein Angreifer versucht, GGN durch Handshake-Fluten oder Brute-Force-Angriffe zu stören, greift der Anti-Fragile Tarpit:
- Jeder fehlgeschlagene Versuch verdoppelt die Rechenaufgabe (Proof-of-Work Challenge), die der Absender lösen muss, bevor GGN ihm antwortet.
- Ein ehrlicher Nutzer spürt nichts davon; ein Angreifer wird innerhalb von Sekunden durch astronomische CPU-Kosten lahmgelegt.

---

## 3. Datei- und Modul-Übersicht

Das Projekt ist in eine modulare, streng hierarchische Schichtenarchitektur unterteilt:

```
Global-Ghost-Net/
├── src/
│   ├── main.rs                   # Einstiegspunkt für Daemon, CLI und GUI
│   ├── lib.rs                    # Bibliotheks-Wurzel (Re-Exports)
│   ├── ghost/
│   │   ├── layers/               # L0 bis L8: Kryptographische Kernschichten
│   │   ├── net/                  # Netzwerk-, Transport- und Mesh-Module
│   │   ├── session/              # Ratchet-, Epochen- und Sitzungsverwaltung
│   │   └── ui/                   # Desktop-Steuerfenster & Tray-Icon
├── deploy/                       # Referenz-Container-Testbed (§48)
├── formal/                       # Mathematische ProVerif-Beweise (§47)
├── tests/                        # Integrations-, Fuzzing- & Red-Team-Tests
└── Cargo.toml                    # Projekt-Manifest und Abhängigkeiten
```

### 3.1 Das Herzstück
- **`src/main.rs`:** Enthält die Initialisierung des Daemons, die Konfigurationsverwaltung (`config.env`), das Verbindungsmanagement, den Tray-Icon-Lifecycle und die CLI-Befehle (`ggn status`, `ggn connect`, etc.).
- **`src/lib.rs`:** Verbindet alle Module zu einer einheitlichen Bibliothek (`vantablack`), die auch für Android (JNI) kompiliert werden kann.

### 3.2 Die kryptographischen Schichten (`src/ghost/layers/`)
- **`l0_identity.rs`:** Generierung und Verwaltung von Hybrid-Identitäten (Ed25519 + ML-DSA-65). Unterstützt *Burnable Ghost IDs* (pro Peer abgeleitete, unkorrelierbare Einmalschlüssel).
- **`l1_kem.rs`:** Post-Quanten-Schlüsselaustausch via ML-KEM-768 mit Elligator-artiger Deniability (Handshakes ohne statische Header).
- **`l2_aead.rs`:** Symmetrische Authenticated Encryption mittels ChaCha20-Poly1305 und 64-Bit vorzeichenlosen Nonces.
- **`l3_shamir.rs`:** Shamir Secret Sharing und Schwellwert-Kryptographie (3-aus-5 Gruppen-Governance).
- **`l4_rs.rs`:** Hochoptimierte Galois-Feld $GF(2^8)$ Reed-Solomon(2,1)-Kodierung und Rekonstruktion für Pakete und Compute-Toleranz.
- **`l5_noise.rs`:** GhostMimic: Markov-Modellierung und Poisson-Cover-Traffic-Generierung gegen Verkehrsmusteranalysen.
- **`l6_session.rs`:** Sitzungs-Guards und 64-Bit Replay-Schutzfenster.
- **`l7_ldpc.rs`:** Low-Density Parity-Check Vorwärtsfehlerkorrektur für extrem verrauschte Kanäle.
- **`l8_memsec.rs`:** `LockedMemory` und `SecureMemGuard` — Sperrt Speicherbereiche im physischen RAM (kein Swap auf Festplatte) und überschreibt sie beim Beenden mit Nullen.

### 3.3 Netzwerk- & Routing-Module (`src/ghost/net/`)
- **`pow.rs`:** Proof-of-Work Anti-Abuse Engine und §50 Anti-Fragile Tarpit (dynamische Rechenstrafen gegen DoS-Angreifer).
- **`dead_drop.rs`:** §22 Autonome Blind-Speicher (Tahoe-Style) und §33 Self-Eating Storage (adaptiver Zerfall gekoppelt an die Netzwerkausfallrate).
- **`diffusion.rs`:** §32 Epidemisches Notfall-Flutungs-Routing mit Schleifenunterdrückung (`GHOST_DIFFUSION=1`).
- **`shardsec.rs`:** §1 ShardSec (individuelle Einmalschlüssel pro Shard) und §27 Spatio-Temporale Erosions-Codes (zeitlicher Schlüsselzerfall).
- **`dtn_reconcile.rs`:** §29 Merkle-Tree Anti-Entropie Synchronisation für Verbindungsabbrüche (DTN).
- **`relay.rs`:** 3-Hop Sphinx-Shard Onion-Routing, §45 Anonyme Capability Vouchers und Multi-Circuit Tor Egress.
- **`universal_tunnel.rs`:** §37 Universeller Port-Forwarder (leitet jeden TCP/UDP-Dienst wie RDP, SSH, Web über 576B Shards weiter).
- **`collective_defense.rs`:** §42 Differentiell-private Gefahrenmeldung ohne zentrale Überwachungsinstanz.
- **`energy_currency.rs`:** §31 Energie-Währung basierend auf verifizierten Reed-Solomon Reparatur-Beweisen.
- **`sharded_compute.rs`:** §21/§24/§25 Verteilte Modulausführung über verschiedene autonome Systeme (ASNs) mit Redundanz-Verifikation.
- **`sovereign_cloud.rs`:** §44 Lokale persönliche Cloud mit geografischen Datenhaltungsregeln (z. B. nur EU-Hardware).
- **`stego_physics.rs`:** §51 Physikalischer Shard-Transport über Ultraschall-FSK, Prozessor-Wärmezyklen oder LED-Blinkmuster.
- **`vpn/`:** Integrierter virtueller Netzwerkadapter (Wintun auf Windows, TUN auf Linux/macOS) mit Userspace-NAT und MSS-Clamping.

### 3.4 Sitzungsverwaltung (`src/ghost/session/`)
- **`ratchet.rs`:** Post-Quanten Double-Ratchet Zustandsautomat mit fortlaufender Schlüsselweiterschaltung pro Paket.

### 3.5 Testbed, Formales Modell & Fuzzing
- **`deploy/docker-compose.yml` & `deploy/smoke_test.sh`:** Vollständiges 3-Knoten-Referenznetzwerk (Hub, Relay, Client) für automatisierte Tests.
- **`formal/shardsec_space_time.pv`:** ProVerif-Mathematikmodell, das formal beweist, dass ein Angreifer mit Zugriff auf einen Shard oder eine Epoche mathematisch 0 Bit erfährt.
- **`tests/redteam_harness.rs`:** Deterministischer Simulator mit 100 virtuellen Knoten, 15 bösartigen Angreifern und 10% Paketverlust.
- **`tests/semantic_fuzzer.rs`:** Eigenschaftsbasierter Fuzzer für Zustandsfolgen, Doppel-Ausgaben und Dead-Drop-Zyklen.

---

## 4. Lebenswichtige Abhängigkeiten

### Was MUSS auf einem Zielsystem vorhanden sein?
GGN wurde so konzipiert, dass es als eigenständige, statisch gelinkte Binärdatei läuft:

1. **`ggn.exe` bzw. `vantablack` (Kompilierte Binärdatei):** Enthält die gesamte Logik, Kryptographie und den Netzwerk-Stack.
2. **`wintun.dll` (nur unter Windows):** Der extrem performante TUN-Treiber von WireGuard. Ohne diese DLL kann Windows keinen virtuellen Netzwerkadapter erstellen, um System-IP-Pakete abzufangen.
3. **`config.env` (Optional):** Konfigurationsdatei für Ports und Rollen (wird mit sicheren Standardwerten automatisch im Speicher erzeugt, wenn nicht vorhanden).

### Was wurde bereinigt?
- Temporäre Test-Artefakte und unbenutzte Platzhalter (`placeholder.txt`) wurden vollständig entfernt.
- Es verbleiben keine toten Abhängigkeiten im Baum.

---

## 5. Kompilierung, Tests & Inbetriebnahme

### Schnellanleitung zum Bauen
Da der Pfad auf Windows-Systemen Leerzeichen enthalten kann, wird ein separates Target-Verzeichnis empfohlen:

```powershell
# 1. Zielverzeichnis festlegen (verhindert Linker-Probleme)
$env:CARGO_TARGET_DIR = "C:\ggn-target"

# 2. Vollständige Test-Suite ausführen (über 420 Tests)
cargo test --target-dir C:\ggn-target --features vpn --lib

# 3. 100-Knoten Red-Team Simulator ausführen
cargo test --target-dir C:\ggn-target --test redteam_harness

# 4. Semantischen Protokoll-Fuzzer ausführen
cargo test --target-dir C:\ggn-target --test semantic_fuzzer

# 5. Release-Binärdatei kompilieren
cargo build --release --target-dir C:\ggn-target
```

### Starten als Exit-Node oder Mesh-Client
```bash
# Starten als regulärer Client
./ggn

# Starten als headless Exit-Node (z. B. auf einem Linux-VPS)
NODE_ROLE=exit ./wan_mesh 8000
```

---
*Global Ghost Net: Unüberwachbar, unzerstörbar, dezentral.*
