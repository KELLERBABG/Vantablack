# Vantablack Anti-Abuse Architecture

> **Leitprinzip:** Vantablack schützt normale Nutzer vor Überwachung durch ISPs, Datenbroker und Staaten — **ohne** eine Infrastruktur für Schwarzmärkte („Silk Road“), Botnets, Spam-Relays oder DDoS-Angriffe bereitzustellen. Dabei gilt ein striktes Gebot: **Kein Inhalts-Mitlesen (keine DPI-Backdoor) und keine zentrale Zensur-Instanz.**

---

## §1. Struktureller Schutz gegen Schwarzmärkte (Kein anonymes öffentliches Hosting)

Ein Schwarzmarkt wie *Silk Road* benötigt öffentlich auffindbares, anonymes 1-zu-100.000-Webhosting (Hidden Services). Vantablack verhindert das architektonisch, ohne die Privatsphäre regulärer Clients einzuschränken:

1. **Client-Anonymität statt öffentlicher Hidden Services:**
   - Vantablack anonymisiert ausgehende Client-Verbindungen ins normale Internet (`Guard → Middle → Exit`) sowie **authentifizierte Privat-Meshes** (`ggn fleet`, `ggn party`, `ggn drop`, `ggn expose`).
   - Es gibt bewusst **kein** globales, öffentlich durchsuchbares Verzeichnis anonymer `.vb`-Webserver.
2. **Pflicht-Geheimtoken & Fan-in-Grenzen (`src/ghost/v2/expose.rs`, `src/ghost/v2/vbdns.rs`):**
   - `ggn expose` verlangt zwingend ein vorab geteiltes Geheimtoken (`X-VB-Expose` / Pfad-Token) für genau ein festes Ziel.
   - Ein enges Peer-Fan-in-Limit auf P2P-Diensten verhindert den Aufbau anonymer Massen-Storefronts, während private Server, Dev-Tools und persönliche Kontakte ungestört funktionieren.

---

## §2. Default Exit Egress Policy (`src/ghost/net/egress.rs`)

Ein Exit-Knoten baut im Auftrag fremder Peers Verbindungen auf und darf niemals als offener Proxy für lokale Netze oder Spam missbraucht werden. Standardmäßig blockiert `egress.rs` auf Ebene der **aufgelösten Ziel-IP** (`Policy::resolve`, gegen DNS-Rebinding):

- **TCP/25 (`SMTP`):** Verhindert Spam-Relay-Missbrauch.
- **Loopback (`127.0.0.0/8`, `::1`, `localhost`, `*.localhost`):** Schützt lokale Dienste auf dem Exit-Host.
- **Private Netze (RFC 1918 `10/8`, `172.16/12`, `192.168/16`, IPv6 ULA `fc00::/7`):** Schützt das LAN hinter dem Exit.
- **Link-Local (`169.254.0.0/16`, `fe80::/10`):** Blockiert Cloud-Metadaten-Endpunkte (`169.254.169.254`) gegen SSRF-Credential-Diebstahl — bleibt auch bei `GHOST_EXIT_EGRESS_LAN=1` permanent gesperrt.
- **CGNAT (`100.64.0.0/10`), Unspecified, Multicast und reservierte Bereiche.**

Opt-in-Ausnahmen (`GHOST_EXIT_EGRESS_LAN=1`, `GHOST_EXIT_EGRESS_SMTP=1`, `GHOST_EXIT_EGRESS_ALLOW=host:port`) sind ausschließlich explizit durch den jeweiligen Betreiber freischaltbar.

---

## §3. Local Threat / Malware Shield (`src/ghost/net/threat_shield.rs`)

- Blockiert bekannte Phishing-, Malware- und Botnet-C2-Infrastruktur **lokal** am Exit bzw. SOCKS5-Proxy.
- Keine zentrale Telemetrie: Kein externer Server erfährt, welche Adressen ein Nutzer aufgerufen hat.

---

## §4. Signed Threat-Feed Snapshots (`src/ghost/net/threat_feed.rs`)

- Blocklist-Updates werden als kryptographisch signierte Snapshots verteilt und vor Aktivierung über `l0_identity` verifiziert.
- Kein einzelner Angreifer kann ohne gültige Signatur beliebige legitime Websites in den Filter injizieren.

---

## §5. Anonymes Multi-ASN Strike- & Ausschluss-System (`exp_anonymous_abuse_strikes`)

Um einen wiederholt missbrauchenden Knoten netzwerkweit zu stoppen, **ohne** seine Identität zu de-anonymisieren und **ohne** dem Staat eine Zensurwaffe zu geben, kombiniert das Design vier Schichten:

### 5.1 Blacklistable Anonymous Credentials (`BLAC` / `Nymble` auf Ristretto255)
1. **Unverkettbare Tickets (`src/ghost/v2/btcr.rs`):** Solange ein Client sich normal verhält, sind seine Epochen-Tickets $T_1, T_2, \dots$ kryptographisch unverkettbar.
2. **Objektiver Strike-Beweis:** Bei objektiv messbarem Missbrauch am Exit (Port-Scan, DDoS-Flooding, wiederholter `egress.rs`-Bypass-Versuch, Spam/Botnet-C2 aus `threat_shield.rs`) signiert der Exit einen Strike gegen das verwendete Ticket $T_k$.
3. **Abgestufte Eskalation:**
   - **1–2 Strikes:** Nur lokale Drosselung am betroffenen Exit (Schutz vor Fehlalarmen).
   - **$\ge 3$ unabhängige Strikes aus $\ge 3$ verschiedenen ASNs ($N_{\text{eff}}^{\text{strikes}} \ge 3$):** Das Ticket-Pseudonym wird in die kompakte Epochen-Blacklist aufgenommen.
4. **Zero-Knowledge Non-Membership Proof:**
   $$\pi = \text{ZK}\big\{\text{Ticket-Seed } s \notin \text{Blacklist}_{\text{epoch}}\big\}$$
   - **$\notin$**: „Ist kein Element von …“ — beim nächsten Circuit-Aufbau muss der Client in Zero-Knowledge beweisen, dass sein geheimer Seed nicht zu einem gesperrten Pseudonym gehört, ohne seinen Seed preiszugeben.
   - **Effekt:** Der gesperrte Knoten verliert netzwerkweit den Zugang zu Relays und Exits, ohne dass irgendein Knoten seine reale IP oder frühere ehrliche Sitzungen kennt.

### 5.2 Re-Entry-Kosten gegen `rm identity.key`
- **Sandbox-Start:** Jede frisch erzeugte Identität muss ein `Argon2id` + sequenzielles VDF-Puzzle (`exp_sybil_tax_pow_vdf_ladder`) lösen und beginnt mit streng begrenzter Bandbreite/Verbindungszahl.
- **Reputations- & Pfand-Verlust:** Volle Exit-Kapazität setzt entweder ehrlich aufgebaute anonyme Uptime (`exp_zero_knowledge_reputation`) oder ein anonymes `BTCr`-Arbeits-Pfand voraus — bei einem globalen 3-Strike-Ban gehen beide sofort verloren.
- **Optionales High-Trust-Tier:** Anonyme Hardware-Attestierung (**TPM-DAA** via `src/ghost/net/security/attest.rs`) erlaubt Geräten den Nachweis „echtes, ungesperrtes Gerät“ ohne Identifizierung.

### 5.3 Schutz gegen Missbrauch des Ban-Systems als Zensurwaffe

---

## §6. Sitzungsgebundene Relay-Voucher (`GHOST_RELAY_VOUCHERS`)

Ein Relay, das fremden Transit trägt, darf nicht zum kostenlosen Verstärker werden. `research_hooks::voucher` koppelt jede Weiterleitung an ein Guthaben, das der Absender zuvor vorgelegt hat — und zwar **auf beiden Weiterleitungspfaden**:

- **`BLND!` (Blind-Hop):** der Umschlag wird byte-genau weitergereicht, das Guthaben wird beim Eingang belastet.
- **`RLY!` (Multi-Hop-Onion):** jeder Hop mit `remaining_hops > 0` belastet dasselbe Guthaben. Ein Peer kann also nicht zwischen den beiden Hüllen wechseln, um ein Kontingent doppelt auszugeben — es gibt genau eine Bank pro Peer und Epoche.

### 6.1 Warum der Voucher sitzungsgebunden ist

Ein Voucher ist **kein** eigenständig handelbares Zertifikat. Er wird

1. erst nach erfolgreicher PQ-Authentifizierung über die bestehende Session präsentiert (`GHOST_VOUCHER_`),
2. unter dem Nullifier des Senders verbucht, den nur diese Session benennen kann, und
3. ausschließlich für Weiterleitungen belastet, die **auf derselben Session** eintreffen.

Daraus folgen die drei Eigenschaften, auf die sich die Zählung stützt:

- **Kein Replay über Knoten hinweg:** ein abgefangener Voucher trägt den Nullifier eines *anderen* Peers; ein zweiter Relay würde ihn entweder als bereits eingelöst oder als fremd verwerfen. Transfer zwischen Relays ist damit wertlos, ohne dass eine globale Nullifier-Datenbank nötig wäre.
- **Kein Replay über IP-Wechsel:** die Belastung hängt am Fingerprint der authentifizierten Session, nicht an der Quell-IP. Ein NAT-Rebind oder ein Pfadwechsel ändert das Guthaben nicht und erzeugt auch kein neues.
- **Kein anonymer Gratis-Transit:** ohne vorgelegten Voucher verweigert das Relay die Weiterleitung, sobald `GHOST_RELAY_VOUCHERS=1` gesetzt ist. Die Prüfung ist ein reiner Zählervergleich, kein Inhaltsblick — die Null-Kenntnis-Eigenschaft des Relays bleibt unberührt.

### 6.2 Kosten und Grenzen

Jeder Voucher wird mit einem Proof-of-Work über `epoch ‖ preimage` gemünzt (8 führende Nullbits) und deckt ein festes Kontingent pro Epoche. Das ist bewusst *billig genug für ehrliche Knoten und teuer genug gegen Massenmünzung* — es ersetzt keine Reputation, sondern verhindert, dass ein einzelner Peer unbegrenzt fremden Transit verbraucht.

Die Gate ist standardmäßig **aus**: ein Relay, das ohne Wissen seiner Peers plötzlich Gebühren erhebt, würde deren Verkehr schwarzlochieren. Erst `GHOST_RELAY_VOUCHERS=1` aktiviert die Belastung, und dann gilt sie symmetrisch für `BLND!` und `RLY!`.

> **Telemetrie:** `/api/status` meldet unter `research.voucher` `admitted`, `denied`, `blind_bytes` und `onion_bytes` — getrennt gezählt, gemeinsam gedeckelt.
- **Kein Single-Exit-Ban:** Ein einzelner (z. B. staatlich kontrollierter) Exit kann einen Nutzer nur lokal ablehnen, niemals global sperren ($N_{\text{eff}}^{\text{strikes}} \ge 3$ über disjunkte ASNs zwingend erforderlich).
- **Strenge Objektivität:** Strikes gelten ausschließlich für lokal verifizierbare Protokoll-/Netzwerk-Angriffe (§2–§3), niemals für politische Inhalte.
- **Epochen-Verjährung:** Blacklist-Einträge verfallen automatisch nach festen Epochen (analog `Chrono-Erosion`), damit Sperrlisten kompakt bleiben und dauerhafte Fehl-Ausschlüsse verhindert werden.
