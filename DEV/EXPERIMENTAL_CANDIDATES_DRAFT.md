# Experimental Candidates — Epistemic Mesh OS Master Draft

> **Grundbasis:** Vantablack als **Epistemic Mesh Operating System** (*Proof-Carrying Adversarial Communication & Sovereignty Substrate*) — Sicherheit wird nicht behauptet, sondern aus **Informationstheorie, Typ-System, Kryptographie, Topologie und Physik** abgeleitet.  
> **Status:** Reine Sammel- und Denkdatei in `DEV/`. Nichts hiervon ist im Produktivcode verdrahtet. Jede Idee durchläuft später den **Sanity Check** (Angreifermodell, Komplexität, ehrliche Grenze, Machbarkeit), bevor sie ein `exp_*`-Flag oder `research`-Modul wird.  
> **Didaktik-Regel:** Unter jeder Formel wird jedes Symbol (inkl. $\sum$, $\prod$, $\bigcap$, $\lor$, $\forall$, Indizes) im Klartext erklärt.

---

# Domäne I — Zeit, Kausalität & Kryptographische Sterblichkeit

## 1. `exp_deadman_cascade` — Kryptographischer Totmannschalter (Duales Gegenstück zu `Chrono-Erosion`)
- **Umgedrehtes Axiom:** `Chrono-Erosion` (`src/ghost/v2/erosion.rs`) löst nur eine Richtung der Zeit (*„Nach Zeit $T$ vergisst das Netz für immer“*). Das exakte duale Gegenstück fehlt: *„Wenn ich nach Frist $\Delta T$ nicht mehr widersprechen kann, wird ein verschlüsseltes Dokument ohne zentrale Instanz unaufhaltsam lesbar.“*
- **Konstruktion:**
  - Ein verschlüsseltes Bundle $C = \text{AEAD}(K_{\text{msg}}, M)$ ruht über `src/ghost/net/dead_drop.rs` im Mesh.
  - **Variante A (Threshold-Komitee):** Ein $(t, n)$-Komitee hält Shares eines Zukunfts-Schlüssels $k_{\tau}$. Solange der Autor periodisch einen blinden Lebens-Puls über `src/ghost/net/metabolic.rs` einreicht, schiebt er die Freigabe-Epoche $\tau \to \tau + 1$ weiter, ohne seine Identität oder den Inhalt zu offenbaren. Bleibt der Puls aus, gibt das Komitee nach $\tau$ den Schlüssel frei.
  - **Variante B (Trustless VDF):** Der Schlüssel wird mit einer *Verifiable Delay Function* (sequenziell nicht parallelisierbare Berechnung $y = g^{2^T} \bmod N$) versiegelt:
    $$K_{\text{release}} = H\!\left(g^{2^T} \bmod N\right), \qquad t_{\text{unlock}} \ge \frac{T}{f_{\max}}$$
    - **$T$**: Anzahl streng sequenzieller Quadrierungen (lässt sich nicht durch 10.000 GPUs beschleunigen).
    - **$f_{\max}$**: Schnellste physikalisch erreichbare Einzelkern-Taktrate für modulare Quadrierung.
    - **$t_{\text{unlock}}$**: Garantierte Mindestzeit bis zur Freigabe, sobald der Autor aufhört, das Puzzle in eine frische Instanz umzupacken.
- **Andockpunkte im Code:** `src/ghost/v2/erosion.rs`, `src/ghost/net/dead_drop.rs`, `src/ghost/net/metabolic.rs`.
- **Ehrliche Grenze:** Schützt nicht, wenn ein Angreifer *alle* gespeicherten `dead_drop`-Kopien vor Ablauf löscht (Kombination mit `exp_diffusion` / `mesh_archive` nötig). Bei Variante B droht bei Hardware-Sprüngen (ASICs für Squaring) eine verkürzte reale Wartezeit $t_{\text{unlock}}$.
- **Machbarkeit:** **Ja** | **Verifikation:** ProVerif (symmetrisch zu `formal/chrono_erosion.pv`) + VDF-Benchmark.

---

## 2. `exp_ambient_entanglement` — Blockchain-freie Kausal-Verflechtung (Umgebungs-Zeitzeugen)
- **Umgedrehtes Axiom:** Um zu beweisen, dass ein Dokument, Log oder Zustand sicher vor Zeitpunkt $T$ existierte und nicht rückwirkend umgeschrieben wurde, scheint man bisher eine globale Blockchain oder eine zentrale Zeitstempel-Behörde (*TSA*) zu brauchen.
- **Konstruktion:**
  - Ein Knoten berechnet ein blindes Commitment seines lokalen Zustands:
    $$c_t = H(\text{salt}_t \parallel \text{root}_t)$$
    - **$\text{salt}_t$**: Frischer 256-Bit-Zufallswert (verhindert Wörterbuchangriffe auf bekannte Dokumente).
    - **$\parallel$**: Byte-Verkettung.
    - **$\text{root}_t$**: Merkle-Wurzel der zu bezeugenden Daten.
  - Während regulärer Handshakes (`braid_identity.rs`) und DTN-Abgleiche (`dtn_reconcile.rs`) wird $c_t$ in die nächsten Übergangs-Hashes zufälliger fremder Peers mitverflochten. Da diese Peers unabhängig weiterwachsen, entsteht ein dichter gerichteter azyklischer Kausal-Graph (DAG).
- **Andockpunkte im Code:** `src/ghost/net/braid_identity.rs`, `src/ghost/net/dtn_reconcile.rs`, `src/ghost/net/entropy_beacon.rs`.
- **Ehrliche Grenze:** Liefert **probabilistische** kausale Verankerung (hängt von Mesh-Dichte und Churn ab), keine globale Totalordnung wie eine PoW-Blockchain.
- **Machbarkeit:** **Ja** | **Verifikation:** ProVerif (Non-Equivocation-Queries analog `formal/braid_identity.pv`).

---

## 3. `exp_causal_time_capsule` — Kollektiv-bedingte Zukunfts-Entschlüsselung (Event-Locked Keys)
- **Umgedrehtes Axiom:** Klassische Verschlüsselung kennt nur zwei Bedingungen für Entschlüsselung: *„Du hast den Schlüssel“* oder *„Zeit $T$ ist vergangen“*. Sie kennt keine **netzwerk-epistemische Bedingung** (*„Öffne erst, wenn das Mesh einen bestimmten kollektiven Zustand erreicht oder beweist“*).
- **Konstruktion:**
  - Ein Sender verschlüsselt eine Notfall-Anweisung (z. B. Backup-Bridge-Adressen oder Notfall-Koordination) unter einem deterministisch abgeleiteten Epochen-/Ereignis-Key eines $(t, n)$-Threshold-Beacons:
    $$K_{\text{event}} = H\!\left(\sigma_{\text{threshold}}(\text{event\_id})\right)$$
    - **$\sigma_{\text{threshold}}(\text{event\_id})$**: Eindeutige Schwellenwert-Signatur (BLS oder Ristretto255-Threshold-VOPRF), die nur entsteht, wenn mindestens $t$ unabhängige Knoten das Ereignis `event_id` (z. B. *„Sheaf-Kohomologie meldet regionale Partition $> 6\text{ h}$“*) signieren.
  - Erst wenn das Ereignis tatsächlich eintritt, existiert $\sigma_{\text{threshold}}$ im Netz — und alle vorbereiteten Zeitkapseln öffnen sich synchron ohne weitere Interaktion des Senders.
- **Andockpunkte im Code:** `src/ghost/net/entropy_beacon.rs`, `src/ghost/net/sheaf.rs`, `src/ghost/v2/erosion.rs`.
- **Ehrliche Grenze:** Erfordert ein korrektes Schwellenwert-Quorum ($< t$ kolludierende Knoten können die Kapsel nicht vorzeitig öffnen); anfällig, falls die Ereignis-Definition selbst zweideutig ist.
- **Machbarkeit:** **Ja** | **Verifikation:** ProVerif (Secrecy vor Quorum-Event, Reachability danach).

---

## 4. `exp_retroactive_amnesia_ratchet` — Selektive Vergangenheits-Chirurgie (Puncturable Forward Secrecy)
- **Umgedrehtes Axiom:** Ein klassischer Ratchet (`ratchet.rs`) schützt nur *grobe Epochen* oder zwingt zum Löschen der gesamten Kette. Bei asynchroner Out-of-Order-Zustellung über Mixnets/DTN muss ein Knoten Schlüssel für noch fehlende Pakete vorhalten — in diesem Fenster sind auch bereits empfangene Pakete derselben Epoche noch angreifbar.
- **Konstruktion:**
  - Ersetze den flachen Epochenschlüssel innerhalb einer Ratchet-Epoche durch eine **GGM-Baum-basierte Puncturable PRF** über den Sequenznummern-Raum $[0, 2^{20})$:
    $$K_i = \text{PPRF}(K_{\text{epoch}}, i), \qquad K'_{\text{epoch}} = \text{Puncture}(K_{\text{epoch}}, i)$$
    - **$\text{PPRF}$**: Baum-basierte pseudozufällige Funktion (Tiefe $20$ = nur 20 SHA-256/BLAKE3-Schritte pro Paket!).
    - **$\text{Puncture}(K, i)$**: Löscht exakt den Blatt-Pfad zu Paket $i$ und ersetzt ihn durch die minimalen Geschwister-Knoten im Binärbaum (höchstens $20 \times 32\text{ B} = 640\text{ B}$ Zustand pro Lücke) + sofortiges `zeroize` via `l8_memsec.rs`.
  - **Effekt:** Sobald Paket $i$ entschlüsselt wurde, existiert kein kryptographisches Material mehr für $i$, **obwohl** verspätete Pakete $i-3$ oder $i+7$ derselben Epoche noch sauber entschlüsselbar bleiben!
- **Andockpunkte im Code:** `src/ghost/session/ratchet.rs`, `src/ghost/layers/l8_memsec.rs`, `src/ghost/layers/l6_session.rs`.
- **Ehrliche Grenze:** Bei tausenden dauerhaft verlorenen Lücken wächst die Liste der offenen Baum-Knoten (muss nach `SessionGuard`-Fenstergröße $W = 128$ hart geprunt werden).
- **Machbarkeit:** **Ja** (sehr sauber in reinem Rust + BLAKE3) | **Verifikation:** ProVerif (`session_ratchet.pv`-Erweiterung).

---

## 5. `exp_chronological_firewall` — Kausalitäts-Monotonie gegen Epochen-Rückspulung
- **Umgedrehtes Axiom:** Ein isolierter Knoten (z. B. hinter einem Eclipse-Angreifer oder nach langem Offline-Sein) akzeptiert signierte Kontroll-Nachrichten (Revocations, Peer-Deskriptoren, Threat-Feeds), deren Zeitstempel scheinbar plausibel sind — solange die lokale Uhr manipuliert oder verzögert wurde.
- **Konstruktion:**
  - Verknüpfe jede Kontroll-Nachricht mit einer **kausalen Vektor-Monotonie** aus `braid_identity`-Höhen und `entropy_beacon`-Epochen:
    $$\forall e_{\text{neu}}:\; \text{epoch}(e_{\text{neu}}) \ge \max_{p \in \mathcal{N}} \text{epoch}_p - \Delta_{\max} \;\land\; \text{CausalParent}(e_{\text{neu}}) \not\prec \text{Revoked}$$
    - **$\forall$**: Gilt für jede neu empfangene Kontroll-Nachricht $e_{\text{neu}}$.
    - **$\max_{p \in \mathcal{N}}$**: Höchste bisher beobachtete Epoche über alle verifizierten Nachbarn $\mathcal{N}$.
    - **$\not\prec$**: Darf kausal nicht von einem bereits widerrufenen Zweig abstammen.
  - Ein Knoten darf kausal niemals „rückwärts“ laufen — selbst wenn sein lokales OS-NTP manipuliert wird.
- **Andockpunkte im Code:** `src/ghost/net/braid_identity.rs`, `src/ghost/net/threat_feed.rs`, `src/ghost/net/entropy_beacon.rs`.
- **Ehrliche Grenze:** Bei komplettem Kaltstart ohne Vorwissen braucht der Knoten einmalig mindestens $k$ ehrliche Peer-Beacons als Kausal-Anker.
- **Machbarkeit:** **Ja** | **Verifikation:** Unit-/Property-Tests + ProVerif.

---

# Domäne II — Zwang, Abstreitbarkeit & Forensische Immunisierung

## 6. `exp_witness_amnesia` — Nicht-übertragbare Beweise (Designated-Verifier `X-Ray`)
- **Umgedrehtes Axiom:** Klassische Signaturen beweisen Echtheit — aber verwandeln jedes gespeicherte `X-Ray`-Transcript, jede Relay-Quittung und jedes Peer-Echo bei Beschlagnahmung in einen **von Dritten verifizierbaren Beweis gegen den Absender**.
- **Konstruktion:**
  - Ersetze klassische Ed25519-Signaturen für interne Session-/Echo-Zeugnisse durch **Non-Interactive Designated-Verifier Signatures (DVS)** als 2-Parteien-OR-Sigma-Beweis über Ristretto255:
    $$\pi = \text{NIZK}\Big\{\big(pk_A = sk_A \cdot G\big) \;\lor\; \big(pk_B = sk_B \cdot G\big)\Big\}(m)$$
    - **$\lor$**: Logisches ODER — der Beweis zeigt nur, dass der Ersteller *entweder* Alices Geheimnis $sk_A$ *oder* Bobs Geheimnis $sk_B$ kennt.
    - **$G$**: Generatorpunkt der Ristretto255-Gruppe (bereits in `src/ghost/v2/btcr.rs` vorhanden).
  - **Effekt:** Bob weiß im Moment des Empfangs, dass *er* $\pi$ nicht erstellt hat $\implies$ es stammt sicher von Alice. Beschlagnahmt ein Dritter Bobs Gerät, kann Bob jedes beliebige Transcript mit $sk_B$ ununterscheidbar fälschen $\implies$ **0 Bit Beweiswert gegen Alice**.
- **Andockpunkte im Code:** `src/ghost/layers/l0_identity.rs`, `src/ghost/v2/xray.rs`, `src/ghost/v2/btcr.rs`.
- **Ehrliche Grenze:** Schützt vor nachträglicher Weitergabe an Dritte (*Non-Transferability*), nicht vor Echtzeit-Kollusion eines korrupten Bob mit einem Live-Beobachter.
- **Machbarkeit:** **Ja** | **Verifikation:** ProVerif (Observational Equivalence zwischen echtem Alice-Beweis und Bob-Simulator).

---

## 7. `exp_blind_social_vault` — Blinde Soziale Wiederherstellung ohne Seed-Phrase & ohne wissende Wächter
- **Umgedrehtes Axiom:** Bisheriges Schlüssel-Backup zwingt zur Wahl zwischen Papier-Seed (physisch stehlbar), Cloud (zentral) oder Freunden per Shamir (sozial erpressbar, weil sie wissen, wessen Key sie halten).
- **Konstruktion:**
  - Spalte den Master-Recovery-Key per $(k, n)$-Shamir (`l3_shamir.rs`) in $n$ Shares und versiegle jeden Share als unverkettbaren `dead_drop`-Slot bei einem Wächter-Peer, der **nicht weiß, wem der Share gehört**.
  - Ein Abruf-Versuch startet eine obligatorische **Quarantäne-Phase** ($T_{\text{quar}} = 48\text{ h}$). Sendet das echte Gerät während $T_{\text{quar}}$ einen signierten `braid_identity`-Veto-Puls, wird der Recovery-Abruf lautlos vernichtet und als Diebstahlversuch markiert.
- **Andockpunkte im Code:** `src/ghost/layers/l3_shamir.rs`, `src/ghost/net/dead_drop.rs`, `src/ghost/net/braid_identity.rs`.
- **Ehrliche Grenze:** Sind nach einem echten Totalverlust weniger als $k$ Wächter-Peers erreichbar, ist der Schlüssel permanent verloren (klassisches Availability-vs.-Security-Dilemma).
- **Machbarkeit:** **Ja** | **Verifikation:** ProVerif (Diebstahl-Abbruch innerhalb $T_{\text{quar}}$ vs. erfolgreiches Recovery nach Verlust).

---

## 8. `exp_duress_honeygraph` — Synthetisches Zwang-Paralleluniversum (Plausible Active Decoy)
- **Umgedrehtes Axiom:** Ein Duress-PIN, der einfach alle Daten löscht (`Wipe`), verrät dem Forensiker sofort: *„Hier wurde unter Zwang gelöscht!“* — ein völlig leeres, fabrikneues Vantablack auf einem seit Monaten genutzten Gerät ist selbst ein Verdachtsmoment.
- **Konstruktion:**
  - Kopple `Vanta-Subliminal Tail` (`l2_aead.rs`) an eine dauerhaft im Hintergrund mitlaufende **Decoy-Persona**:
    - Die äußere Schicht (`K_decoy`) tauscht automatisch harmlose, realistische Hintergrund-Aktionen aus (z. B. öffentliche `mesh_archive`-Mirrors, normale `.vb`-Statuspings, glaubwürdige lokale Logs und `X-Ray`-Metriken).
    - Bei Eingabe der **Duress-PIN** nullt `l8_memsec.rs` sofort `K_true` + alle echten Epochen-Zustände und öffnet nahtlos die gewachsene, zeitlich konsistente Decoy-Oberfläche.
- **Andockpunkte im Code:** `src/ghost/layers/l2_aead.rs`, `src/ghost/layers/l8_memsec.rs`, `src/ghost/net/consumer.rs`, `src/webview.rs`.
- **Ehrliche Grenze:** Wenn ein Gegner bereits vorher komplettes Device-Imaging zu zwei Zeitpunkten vergleichen kann (*Multi-Snapshot Rubber-Hose Forensics*), muss auch das Speicher-Layout im Flash konstant groß (Fixed-Size Encrypted Container) bleiben, damit sich die belegte Blockzahl nicht ändert.
- **Machbarkeit:** **Ja** | **Verifikation:** Forensische Diff-Tests auf Fixed-Size-Containern.

---

## 9. `exp_volatile_ephemeral_execution` — Zero-Disk Ephemeral State Machine (Wear-Leveling-Immun)
- **Umgedrehtes Axiom:** Normale Software schreibt Schlüssel, Caches und SQLite/JSON-Zustände auf SSD/Flash. Auf modernen SSDs kann selbst `fsync` + Überschreiben alte Blöcke im Controller-Wear-Leveling über Monate zurücklassen.
- **Konstruktion:**
  - Ein strikter `--amnesic`-Laufzeitmodus, der **exakt 0 Bytes** auf das Dateisystem schreibt:
    - Sämtlicher State (`IdentityKeypair`, `SessionGuard`, `Ratchet`, `DTN-Cache`, `X-Ray`-Ledger) lebt ausschließlich in gesperrten, per AES-XTS verschlüsselten RAM-Arenen (`l8_memsec.rs` + `VirtualLock`/`mlock`).
    - Beim Stromausfall oder Prozess-Ende existieren physisch null Spuren auf dem Datenträger.
- **Andockpunkte im Code:** `src/ghost/layers/l8_memsec.rs`, `src/daemon/node.rs`, `src/cli.rs`.
- **Ehrliche Grenze:** Verliert bewusst persistente `Braid`-Historie (muss beim Neustart als frische Ephemeral-Identität starten) und schützt nicht gegen laufenden Live-DMA-Angriff ohne IOMMU.
- **Machbarkeit:** **Ja** | **Verifikation:** OS-Syscall-Audit (`strace`/ETW: garantiert `0` Write-Syscalls auf Nicht-Socket-Deskriptoren).

---

## 10. `exp_canary_poison_key` — Selbstverratende Zwangsschlüssel (Stiller Mesh-Alarm)
- **Umgedrehtes Axiom:** Wenn ein Gerät beschlagnahmt und unter Zwang entsperrt wird, merken die übrigen Peers im Mesh nichts davon — sie senden weiter sensible Daten an den kompromittierten Endpunkt.
- **Konstruktion:**
  - Die Duress-PIN entsperrt die harmlose Decoy-Ebene **und** leitet einen speziellen `K_canary`-Seed ab.
  - Beim nächsten regulären Handshake oder `RACS`-Cover-Paket bettet der Knoten im `Vanta-Subliminal Tail` ein authentifiziertes 16-Byte-Notfall-Tag ein, das **nur** für vertraute Fleet-Peers (`fleet.rs`) erkennbar ist:
    $$\text{Tag}_{\text{canary}} = \text{BLAKE3}_{\text{keyed}}(K_{\text{fleet\_alarm}}, \text{epoch} \parallel \text{nonce})$$
    - **$\text{BLAKE3}_{\text{keyed}}$**: Schneller kryptographischer MAC unter dem gemeinsamen Fleet-Notfallschlüssel $K_{\text{fleet\_alarm}}$.
  - Empfangen Fleet-Peers $\text{Tag}_{\text{canary}}$, isolieren sie das Gerät still aus allen geheimen Gruppen/Quoren und schicken ihm ab sofort nur noch harmlosen Decoy-Traffic — der Beschlagnahmer sieht keine abrupte Verbindungsabbrüche!
- **Andockpunkte im Code:** `src/ghost/v2/fleet.rs`, `src/ghost/layers/l2_aead.rs`, `src/daemon/auth.rs`.
- **Ehrliche Grenze:** Wirkt nur, sobald das beschlagnahmte Gerät noch einmal ins Netz geht (nicht im permanenten Faraday-Käfig — dafür greift `metabolic.rs`).
- **Machbarkeit:** **Ja** | **Verifikation:** ProVerif (Ununterscheidbarkeit von $\text{Tag}_{\text{canary}}$ gegenüber Zufalls-Tail für Dritte).

---

# Domäne III — Aktive Traffic-Physik, Timing & Anti-Korrelation

## 11. `exp_watermark_counterphase` — Aktive Gegen-Korrelation gegen Timing-Wasserzeichen
- **Umgedrehtes Axiom:** Anonymitätsnetze verhalten sich fast immer passiv-defensiv: Ein aktiver Zensor moduliert künstliche Verzögerungswellen (Timing-Watermarks) in einen Eingangs-Stream, um denselben Rhythmus am Exit wiederzuerkennen — und das Netz hofft bloß auf genug Rauschen.
- **Konstruktion:**
  - Ein leichter Online-Korrelator über die letzten $L$ Paketabstände $\Delta t_0, \dots, \Delta t_{L-1}$ schätzt dominierende Modulationsfrequenzen $\hat{\omega}$ via diskreter Autokorrelation:
    $$R(\tau) = \frac{1}{L - \tau} \sum_{k=0}^{L - 1 - \tau} (\Delta t_k - \bar{\Delta t})(\Delta t_{k+\tau} - \bar{\Delta t})$$
    - **$\sum_{k=0}^{L-1-\tau}$**: Addiere alle Produkte aus zentrierter Verzögerung zum Schritt $k$ und Schritt $k + \tau$ (misst, ob sich ein Muster alle $\tau$ Pakete wiederholt).
    - **$\bar{\Delta t}$**: Durchschnittlicher Paketabstand im Fenster.
  - Statt den Pfad abrupt abzubrechen (was dem Angreifer verrät, dass sein Watermark entdeckt wurde), spiegelt `racs.rs` dieselbe Frequenz $\hat{\omega}$ mit zufälligen Phasen $\phi_m \stackrel{\$}{\leftarrow} [0, 2\pi)$ in $M$ unabhängige Cover-Streams. Die Korrelations-Trefferschärfe des Angreifers bricht um Faktor $\frac{1}{\sqrt{M}}$ zusammen (*False-Positive-Vergiftung*).
- **Andockpunkte im Code:** `src/ghost/v2/racs.rs`, `src/ghost/v2/chronos.rs`, `src/ghost/net/sheaf.rs`.
- **Ehrliche Grenze:** Wirkt hervorragend gegen periodische / spektrale Wasserzeichen; bei breitbandigen, pseudozufälligen PN-Code-Wasserzeichen (z. B. *RAINBOW*) mit minimaler Amplitude greift es schlechter als hartes Renewal-Slot-Shaping (`Shaped-RACS`).
- **Machbarkeit:** **Ja** | **Verifikation:** Stochastische Monte-Carlo-Simulation gegen aktive Watermark-Detektoren.

---

## 12. `exp_relativistic_fog` — Metrisch konsistente Fata Morgana (Anti-Triangulation)
- **Umgedrehtes Axiom:** `LightCone-Proof` (`sovereign_cloud.rs`) nutzt Lichtgeschwindigkeit + RTT, um Standorte zu **beweisen**. Ein Angreifer nutzt exakt dieselbe Physik (RTT-Triangulation), um versteckte Server zu **orten** — und naive konstante Verzögerungen fliegen auf, weil sie die Dreiecksungleichung verletzen.
- **Konstruktion:**
  - Wähle eine virtuelle Schein-Position $x_{\text{fake}}$ auf der Erdkugel $S^2$ (weiter entfernt von allen beobachtenden Peers als die echte Position $x_{\text{real}}$).
  - Für jeden Peer $p_i$ ergänzt `chronos.rs` exakt so viel Pufferzeit, dass die beobachtete RTT einer echten Glasfaser-Distanz zu $x_{\text{fake}}$ entspricht:
    $$\Delta \text{RTT}_i = \max\!\left(0,\; \frac{2 \cdot d_{\text{geo}}(p_i, x_{\text{fake}})}{v_{\text{fiber}}} - \text{RTT}_{i,\text{real}}\right)$$
    - **$d_{\text{geo}}(p_i, x_{\text{fake}})$**: Geodätische Oberflächen-Distanz (Haversine-Formel) zwischen Peer $p_i$ und Schein-Ort $x_{\text{fake}}$.
    - **$v_{\text{fiber}} \approx 204\text{ km/ms}$**: Ausbreitungsgeschwindigkeit von Licht in Glasfaser.
    - **$\max(0, \dots)$**: Verzögerung kann physikalisch niemals negativ sein (man kann Pakete nur verlangsamen, nie beschleunigen).
- **Andockpunkte im Code:** `src/ghost/v2/chronos.rs`, `src/ghost/net/sovereign_cloud.rs`, `src/ghost/net/relay.rs`.
- **Ehrliche Grenze:** Kann dich physikalisch niemals *näher* erscheinen lassen, als die echte Lichtlaufzeit erlaubt, und erhöht spürbar die Latenz.
- **Machbarkeit:** **Ja** | **Verifikation:** Geometrische Triangulations-Tests aus 10+ globalen Beobachterpunkten.

---

## 13. `exp_biological_mimicry_racs` — Empirische Markov-Traffic-Mimikry
- **Umgedrehtes Axiom:** Starres Constant-Rate-Padding (ein Paket exakt alle 50 ms) verhindert zwar Aktivitäts-Leaks, aber **die perfekt konstante Rate selbst ist ein unverwechselbarer Fingerabdruck** für DPI-Systeme (kein echtes menschliches Protokoll taktet stundenlang wie ein Metronom).
- **Konstruktion:**
  - Ersetze den einfachen ON/OFF-Timer in `racs.rs` durch eine **eingemessene Hidden-Markov-Übergangsmatrix** $P_{\text{target}}$ eines legitimen Massen-Trägers (z. B. echter WebRTC-Sprach-/Videocall über `srtp.rs` oder HTTP/3-Streaming über `masque.rs`).
  - Die Slots $t_i$ werden strikt unabhängig vom echten Nutzer-Input $X$ aus $P_{\text{target}}$ gesampelt ($S \perp X$), sodass gleichzeitig gilt:
    $$I(O; X) \le \epsilon_{\text{AEAD}} \quad \land \quad D_{\text{KL}}\!\left(P_{\text{Vantablack}} \,\|\, P_{\text{WebRTC}}\right) \approx 0$$
    - **$I(O; X)$**: Transinformation zwischen beobachtbarem Traffic $O$ und echter Nutzeraktivität $X$ (bleibt nahe 0).
    - **$D_{\text{KL}}(\dots)$**: Kullback-Leibler-Divergenz zwischen dem Vantablack-Strom und einem echten WebRTC-Anruf.
- **Andockpunkte im Code:** `src/ghost/v2/racs.rs`, `src/daemon/srtp.rs`, `src/ghost/v2/masque.rs`.
- **Ehrliche Grenze:** Wenn der gewählte Ziel-Träger selbst unüblich im lokalen Netz ist (z. B. 14 Stunden durchgehender Videoanruf um 3 Uhr nachts), fällt das Langzeit-Profil trotzdem auf — daher Profil-Wechsel nach Tageszeit/Kontext nötig.
- **Machbarkeit:** **Ja** | **Verifikation:** Klassifikator-Tests (Random Forest / CNN Traffic-Classifier gegen echte WebRTC-PCAPs).

---

## 14. `exp_asymmetric_split_horizon` — Physisch getrennter Uplink/Downlink
- **Umgedrehtes Axiom:** Selbst bei 3-Hop-Onion-Routing sieht dein lokaler ISP (oder dein Guard-Knoten) **sowohl** deinen ausgehenden Request **als auch** die zurückkehrende Antwort auf derselben Leitung — und kann daraus Request-Response-Muster korrelieren.
- **Konstruktion:**
  - Nutzt `hpeb.rs` + SURB-Rückrouten (`relay.rs`) asymmetrisch:
    - **Uplink (Senden):** Läuft ausschließlich über Pfad A (z. B. Wi-Fi / ISP 1 $\to$ Guard A) inklusive vorverschlüsselter Rückroute (*SURB*), die auf Pfad B zeigt.
    - **Downlink (Empfangen):** Läuft ausschließlich über Pfad B (z. B. 5G-Mobilfunk / ISP 2 $\to$ Guard B).
  - Kein einzelner ISP und kein einzelner Guard sieht jemals ein geschlossenes Frage-Antwort-Paar!
- **Andockpunkte im Code:** `src/ghost/v2/hpeb.rs`, `src/daemon/bonding.rs`, `src/ghost/net/relay.rs`.
- **Ehrliche Grenze:** Erfordert mindestens zwei physisch unabhängige Zugangsnetze (z. B. DSL + 5G); schützt nicht gegen einen globalen Gegner, der beide ISPs gleichzeitig anzapft.
- **Machbarkeit:** **Ja** | **Verifikation:** ProVerif (erweiterte `ghost_circuit_unlinkability.pv` mit getrennten Ein-/Ausgangskanälen).

---

## 15. `exp_stochastic_mtu_chameleon` — Epochen-weises Frame-Größen-Morphing
- **Umgedrehtes Axiom:** Jedes `GTFv2`-Paket ist exakt `576 B` groß. Das verhindert zwar interne Längenanalyse — aber **tausende exakt 576 Byte große UDP-Pakete in Folge sind selbst ein DPI-Erkennungsmerkmal** für Vantablack!
- **Konstruktion:**
  - Beide Peers leiten aus ihrem gemeinsamen Epochenschlüssel via PRF pro Epoche (oder pro Paket-Slot unabhängig vom Inhalt!) eine Ziel-Größenverteilung $L_k \sim \mathcal{D}_{\text{carrier}}$ ab (z. B. realistische QUIC-/HTTP3-/RTP-Paketgrößen zwischen `128 B` und `1280 B`), indem das `AAD-Tail` dynamisch skaliert oder Chunks auf die gesampelte Zielgröße gepolstert werden:
    $$L_k = \text{Sample}\!\left(\mathcal{D}_{\text{carrier}},\; \text{PRF}(K_{\text{shape}}, k)\right), \qquad L_k \perp M_k$$
    - **$\perp$**: Stochastisch unabhängig — die Paketlänge $L_k$ hängt *niemals* von der echten Nachrichtenlänge $M_k$ ab, sondern ausschließlich vom geheimen Shaping-Seed.
- **Andockpunkte im Code:** `src/ghost/net/mod.rs`, `src/daemon/framing.rs`, `src/ghost/net/coalesce.rs`.
- **Ehrliche Grenze:** Bricht die fixe `576 B`-Annahme im Parser (erfordert explizites Längen-Framing innerhalb des verschlüsselten Headers) und kann bei kleinen gesampelten Slots zu höherem Fragmentierungs-Overhead führen.
- **Machbarkeit:** **Vielleicht** (erfordert saubere Anpassung von `framing.rs` + `coalesce.rs`) | **Verifikation:** Statistische Chi-Quadrat-/KS-Tests gegen echte QUIC-Verteilungen.

---

## 16. `exp_congestion_decoupling` — Seitenkanal-freie Überlastkontrolle
- **Umgedrehtes Axiom:** Normale Congestion Control (`cc.rs` / TCP) reduziert sofort die Senderate, sobald irgendwo am Ende des Tunnels ein Paket verloren geht. Ein Angreifer am Zielserver kann also künstlich Pakete droppen und am anderen Ende der Welt beobachten, **wessen** Leitung sofort langsamer wird (*Congestion-Side-Channel-Angriff*).
- **Konstruktion:**
  - Strenge **zweistufige Entkopplung** zwischen äußerer Link-Überlastkontrolle (zwischen Client und Guard) und innerem Circuit-Durchsatz:
    - Die äußere Leitung hält ihr `Shaped-RACS`-Profil unabhängig vom inneren Verlust konstant (fehlende Nutzpakete werden lokal durch `576 B`-Dummys aufgefüllt).
    - Innerer Paketverlust steuert nicht die äußere Taktrate, sondern ausschließlich die lokale **RS-Redundanzrate** (`l4_rs.rs`) und interne Puffer-Backpressure.
- **Andockpunkte im Code:** `src/ghost/net/cc.rs`, `src/ghost/v2/racs.rs`, `src/ghost/layers/l4_rs.rs`.
- **Ehrliche Grenze:** Reduziert den maximalen Spitzendurchsatz im Vergleich zu ungefiltertem TCP/QUIC und erhöht lokale Puffer-Latenz bei anhaltender Überlastung am Exit.
- **Machbarkeit:** **Ja** | **Verifikation:** Cross-Flow-Korrelationstests bei künstlichem 20%-Drop am Exit.

---

# Domäne IV — Topologie, Routing & Anti-Zensur-Geometrie

## 17. `exp_sheaf_hodge_autopilot` — Selbstheilendes Hodge-Routing um Zensur-Horizonte
- **Umgedrehtes Axiom:** `sheaf.rs` erkennt topologische Zensur- und Eclipse-Blasen ($[\delta] \neq 0 \in H^1$) bisher nur als Diagnose-Alarm im Dashboard — der Router leitet Pakete aber erst um, wenn der Nutzer manuell eingreift oder harte Timeouts feuern.
- **Konstruktion:**
  - Speise die **Hodge-Wirbelenergie** jeder Kante $e = (u, v)$ aus `Theorem 15` direkt als dynamische Strafkosten in die Pfadwahl (`routing.rs` / `relay.rs`):
    $$\text{Cost}(e) = \text{RTT}(e) \cdot \left(1 + \beta \cdot \|(\mathrm{d}_1^* \psi + h)_e\|^2\right)$$
    - **$(\mathrm{d}_1^* \psi + h)_e$**: Nicht-wegtransformierbarer Wirbel-/Harmonischer Anteil der Kante $e$ (hoch genau dort, wo eine Kante eine Zensur- oder MitM-Grenze kreuzt).
    - **$\beta > 0$**: Empfindlichkeitsfaktor für die Umleitung.
  - Das gesamte Mesh „fließt“ wie Wasser automatisch um kompromittierte BGP-Zonen und MitM-Inseln herum, ohne jemals eine zentrale Blockliste zu brauchen.
- **Andockpunkte im Code:** `src/ghost/net/sheaf.rs`, `src/ghost/net/routing.rs`, `src/ghost/net/relay.rs`.
- **Ehrliche Grenze:** Braucht kalibrierte Schwellenwerte für $\beta$, damit normale Internet-Jitter-Spitzen keine Routing-Oszillationen (*Route Flapping*) auslösen.
- **Machbarkeit:** **Vielleicht** (erbt Kalibrierungs-Bedarf von `sheaf.rs`) | **Verifikation:** Netz-Simulator (`scale_mesh.rs`) mit injizierten Eclipse-Inseln.

---

## 18. `exp_censorship_probe_labyrinth` — Zustandsloses Active-Probing-Tarpit
- **Umgedrehtes Axiom:** Wenn eine staatliche Firewall (`GFW`) einen verdächtigen Server aktiv abtastet (*Active Probing*), reagieren klassische Server binär: gültiger Handshake $\to$ Tunnel, ungültiger Handshake $\to$ Reset oder starrer Weiterleitungs-Proxy. Genau dieser Übergang lässt sich zeitlich oder per Replay-Probe fingerabdrucken.
- **Konstruktion:**
  - Erweitere `front.rs` (`REALITY TLS 1.3`) um einen **zustandslosen PRF-Antwort-Generator**:
    - Unautorisierte oder wiederholte Active-Probes werden nicht abgebrochen, sondern deterministisch über `Borrowed-Origin-Splice` mit konsistenten, verlangsamten HTTP/3- und TLS-1.3-Antworten bedient — ohne serverseitigen Speicher zu verbrauchen (immun gegen Tarpit-RAM-DoS).
- **Andockpunkte im Code:** `src/ghost/v2/front.rs`, `src/daemon/reality_front.rs`, `src/ghost/net/pow.rs`.
- **Ehrliche Grenze:** Wenn der echte Origin-Server seine TLS-Cipher-Suites oder ALPN-Reihenfolge ändert, muss der Splice dynamisch mitziehen, sonst entsteht eine Fingerprinting-Differenz.
- **Machbarkeit:** **Ja** | **Verifikation:** Automatisierte Active-Probe-Suite gegen `reality_front.rs`.

---

## 19. `exp_balkanized_bridge_ferry` — Opportunistische BLE / Wi-Fi-Direct DTN-Fähren
- **Umgedrehtes Axiom:** Fällt in einer Stadt das Internet + Mobilfunk komplett aus, sind Internet-Knoten isoliert, solange kein Kurzwellen-Funkgerät (`ABOS`) danebensteht.
- **Konstruktion:**
  - Fügt eine lokale Nahbereichs-Stufe in die `Continuum Ladder` (`continuum.rs`) ein: Smartphones tauschen beim Vorbeigehen (Bus, Bahn, Café) per **BLE / Wi-Fi-Aware** verschlüsselte, blinde `576 B`-DTN-Bundles aus (`dtn_reconcile.rs`), bis ein Gerät wieder eine Funkzelle, WLAN oder `ABOS`-Station erreicht.
  - Dank `ShardSec` + `Chrono-Erosion` weiß das tragende Smartphone weder, *was* es transportiert, noch *für wen* — und vergessene Bundles sterben automatisch nach $\tau_{\text{die}}$.
- **Andockpunkte im Code:** `src/ghost/v2/continuum.rs`, `src/ghost/net/dtn_reconcile.rs`, `src/ghost/net/vpn/android_jni.rs`, `src/ghost/net/vpn/apple.rs`.
- **Ehrliche Grenze:** Batterie-Verbrauch durch BLE-Scanning und OS-Hintergrund-Restriktionen (insbesondere iOS) begrenzen die Reichweite und Datenrate auf kleine Text-/Key-/Proof-Bundles.
- **Machbarkeit:** **Vielleicht** (Protokoll einfach, Mobile-OS-Background-APIs hakelig) | **Verifikation:** DTN-Delay-Simulation.

---

## 20. `exp_adversarial_asn_antigravity` — Unterseekabel- & IXP-bewusstes $N_{\text{eff}}$
- **Umgedrehtes Axiom:** Zwei verschiedene ASNs (z. B. zwei Cloud-Provider in Frankfurt) erfüllen zwar `ASN_guard != ASN_exit`, laufen aber physisch oft über **denselben Internet Exchange (DE-CIX)** oder **dasselbe Transatlantik-Unterseekabel** — ein einzelner Tap sieht beide Enden!
- **Konstruktion:**
  - Verfeinere die Domänen-Partition in `Theorem 04` (`regime.rs` / `xray.rs`) von bloßen ASN-Nummern auf **physische Korridor-Äquivalenzklassen** (IXP + Unterseekabel-Landepunkt + Jurisdiktion) über eine kompakte, lokal aktualisierbare Topologie-Karte:
    $$N_{\text{eff}}^{\text{phy}} = \left(\sum_{c=1}^{M_{\text{corridor}}} w_c^2\right)^{-1} \le N_{\text{eff}}^{\text{ASN}}$$
    - **$w_c$**: Gebündelter Bandbreitenanteil aller Relays, die über denselben physischen Korridor $c$ (z. B. gleiches Unterseekabel) laufen.
- **Andockpunkte im Code:** `src/ghost/v2/regime.rs`, `src/ghost/v2/xray.rs`, `src/ghost/net/sovereign_cloud.rs`.
- **Ehrliche Grenze:** Echte BGP-/Kabel-Pfade ändern sich dynamisch und sind nicht immer öffentlich vollständig kartiert (daher konservative Schätzung statt perfekter Gewissheit).
- **Machbarkeit:** **Ja** | **Verifikation:** Unit-Tests auf synthetischen AS-/IXP-Graphen.

---

## 21. `exp_ephemeral_dark_rendezvous` — Einmalige Quantensichere Dead-Drop-Treffpunkte
- **Umgedrehtes Axiom:** Wiederverwendete Rendezvous-Slots (`rendezvous.rs`) erlauben es einem globalen Beobachter, über Tage hinweg zu erkennen, dass zwei Peers immer wieder denselben Mailbox-Slot abfragen (*Social-Graph-Korrelation*).
- **Konstruktion:**
  - Zwei bereits bekannte Peers leiten für **jede einzelne Nachricht** $k$ aus ihrem gemeinsamen geheimen Rendezvous-Seed $S_{AB}$ und dem öffentlichen Epochen-Beacon $B_e$ einen einmaligen, nie wieder benutzten Slot-Index ab:
    $$\text{slot}_{k} = \text{BLAKE3}\big(\text{"VB-ONE-SHOT-RDV"} \parallel S_{AB} \parallel B_e \parallel k\big)$$
  - Kein Slot wird je zweimal gelesen oder beschrieben — selbst wenn der Mailbox-Knoten 100 % kompromittiert ist, sieht er nur unzusammenhängendes Rauschen.
- **Andockpunkte im Code:** `src/ghost/net/rendezvous.rs`, `src/ghost/net/entropy_beacon.rs`, `src/ghost/net/dead_drop.rs`.
- **Ehrliche Grenze:** Bei langem Offline-Sein muss der Empfänger mehrere verpasste Epochen $B_e$ nach-scannen (linearer Scan-Aufwand in der Anzahl verpasster Epochen).
- **Machbarkeit:** **Ja** | **Verifikation:** ProVerif (Slot-Unlinkability über aufeinanderfolgende Nachrichten).

---

## 22. `exp_censor_induced_mutation` — Evolutionäre Carrier-Selektion (Adversarial Bandits)
- **Umgedrehtes Axiom:** Statische Fallback-Listen („probiere erst UDP, dann QUIC, dann MASQUE, dann REALITY“) sind für Zensoren trivial vorhersagbar — sie blockieren einfach die ersten zwei Stufen und zwingen alle Nutzer in ein einziges Muster.
- **Konstruktion:**
  - Modelliert die Wahl des Transport-Carriers (`UDP`, `QUIC`, `MASQUE`, `REALITY`, `SRTP`, `ABOS-HF`) als **Adversarial Multi-Armed Bandit (EXP3-Algorithmus)**, gespeist aus lokalen Verbindungserfolgen und `collective_defense`-Signalen:
    $$p_i(t) = (1 - \gamma) \frac{w_i(t)}{\sum_{j=1}^{K} w_j(t)} + \frac{\gamma}{K}$$
    - **$p_i(t)$**: Wahrscheinlichkeit, in Runde $t$ Carrier $i$ zu wählen.
    - **$w_i(t)$**: Exponentiell angepasstes Erfolgsgewicht von Carrier $i$.
    - **$\gamma \in (0, 1)$**: Explorationsrate (damit das Netz blockierte Wege periodisch wieder prüft und nie vorhersagbar wird).
  - Jeder Block durch einen Zensor verändert sofort die Gewichte und lässt das Mesh stochastisch in funktionierende Nischen mutieren.
- **Andockpunkte im Code:** `src/ghost/net/carrier.rs`, `src/ghost/net/fallback.rs`, `src/ghost/net/collective_defense.rs`.
- **Ehrliche Grenze:** Während der Lernphase nach einer plötzlichen neuen Zensur-Regel gehen einige Probe-Verbindungen verloren (Regret-Schranke $O(\sqrt{K T \ln K})$).
- **Machbarkeit:** **Ja** | **Verifikation:** Simulation gegen dynamisch wechselnde Zensur-Filter.

---

# Domäne V — Kryptographische Primitive, Gruppen & Anonyme Ökonomie

## 23. `exp_zero_knowledge_reputation` — Anonyme Qualitäts- & Uptime-Beweise ohne Historie
- **Umgedrehtes Axiom:** Reputation und Anonymität gelten klassisch als unvereinbar: Entweder ein Relay trägt über Monate dieselbe statische ID (verfolgbar!), oder es rotiert seine ID (dann weiß niemand, ob es zuverlässig ist).
- **Konstruktion:**
  - In jeder Epoche, in der ein Relay verifiziert weiterleitet, erhält es ein blind signiertes Uptime-Token aus dem `btcr.rs`-VOPRF-Mechanismus.
  - Beim Eintritt in eine neue Epoche mit **frischer, unverkettbarer Epochen-ID** beweist das Relay über einen kompakten Sigma-/Bulletproof-Summenbeweis:
    $$\exists \{u_1, \dots, u_k\} \text{ gültige Epochen-Tokens mit } k \ge 95 \text{ aus den letzten } 100 \text{ Epochen}$$
    - **$\exists$**: „Es existieren …“ — der Verifier sieht **nicht**, welche alten Epochen-IDs dahinterstecken, sondern nur die mathematische Wahrheit von $k \ge 95$.
- **Andockpunkte im Code:** `src/ghost/v2/btcr.rs`, `src/ghost/net/relay.rs`, `src/ghost/v2/regime.rs`.
- **Ehrliche Grenze:** Schützt nicht gegen ein „Schläfer-Relay“, das sich 95 Epochen lang ehrlich verhält und erst in Epoche 96 angreift — erhöht aber die Kosten für Sybil-Relay-Farmen drastisch.
- **Machbarkeit:** **Ja** | **Verifikation:** ProVerif (Unlinkability zwischen alter und neuer Epochen-ID).

---

## 24. `exp_oblivious_dns_pir` — Private Information Retrieval für `.vb`-Namen & Peer-Deskriptoren
- **Umgedrehtes Axiom:** Selbst wenn `.vb`-Namen lokal oder über eine DHT (`vbdns.rs` / `discovery.rs`) aufgelöst werden, erfährt der antwortende Knoten, **nach welchem Ziel-Namen** ein Nutzer gesucht hat — Metadaten-Leak auf der allerersten Schicht!
- **Konstruktion:**
  - **2-Server-XOR-PIR** über zwei nicht-kolludierende Mesh-Directory-Peers (aus disjunkten ASNs):
    - Die Datenbank der $N$ `.vb`-Einträge sei ein Vektor $\mathbf{D} = (D_1, \dots, D_N)$.
    - Um Eintrag $i$ geheim abzurufen, zieht der Client einen zufälligen Bitvektor $\mathbf{q}_1 \stackrel{\$}{\leftarrow} \{0, 1\}^N$ und bildet $\mathbf{q}_2 = \mathbf{q}_1 \oplus \mathbf{e}_i$ (exakt Bit $i$ geflippt).
    - Server 1 antwortet $a_1 = \bigoplus_{j : q_{1,j}=1} D_j$, Server 2 antwortet $a_2 = \bigoplus_{j : q_{2,j}=1} D_j$.
    - Der Client berechnet $a_1 \oplus a_2 = D_i$ — jeder einzelne Server sieht ausschließlich gleichverteiltes Bit-Rauschen (**0 Bit** Information über $i$).
- **Andockpunkte im Code:** `src/ghost/v2/vbdns.rs`, `src/ghost/net/discovery.rs`.
- **Ehrliche Grenze:** 2-Server-PIR bricht, wenn *beide* abgefragten Server kolludieren (deshalb strikte ASN-/Light-Cone-Disjunktheit nötig); bei sehr großen Tabellen ($N > 10^6$) wächst der Query-Vektor auf $\sim 125\text{ KB}$ (ab dort Wechsel auf Lattice-Single-Server-PIR sinnvoll).
- **Machbarkeit:** **Ja** (für Tabellen bis ~100.000 `.vb`-Einträge extrem schnell in Rust) | **Verifikation:** Informationstheoretische Äquivalenz ($I(i; \mathbf{q}_1) = 0$).

---

## 25. `exp_threshold_exit_signing` — Verteilte Ausgangs-Souveränität (Multi-Exit ohne Einzelpunkt-Einsicht)
- **Umgedrehtes Axiom:** Im klassischen 3-Hop-Onion-Netz (`relay.rs`) schützt zwar der Pfad deine IP — aber der **Exit-Knoten** sieht bei unverschlüsselten Zielen oder Metadaten allein das gesamte Ausgangs-Ziel und kann allein blockieren oder protokollieren.
- **Konstruktion:**
  - Für kritische API-/Signatur-/Auth-Aktionen (z. B. Veröffentlichung eines Whistleblower-Bundles oder mTLS-Client-Auth) halten $n$ disjunkte Exit-Knoten $(t, n)$-Threshold-Shares einer ephemeren Ed25519/FROST-Identität.
  - Erst $t$ unabhängige Exits erzeugen gemeinsam eine einzige gültige Standard-Signatur $\sigma$, ohne dass ein einzelner Exit je den Gesamtschlüssel besitzt oder allein handeln kann.
- **Andockpunkte im Code:** `src/ghost/net/relay.rs`, `src/ghost/layers/l0_identity.rs`, `src/ghost/layers/l3_shamir.rs`.
- **Ehrliche Grenze:** Gilt für signierte/authentifizierte Ziel-Aktionen und TLS-Client-Handshakes — allgemeiner unverschlüsselter HTTP-Klartext am Zielserver bleibt systembedingt am letzten TCP-Proxy sichtbar.
- **Machbarkeit:** **Vielleicht** (FROST-Threshold-Schnorr auf Ristretto255/Ed25519 ist gut spezifiziert, braucht aber 2 Kommunikationsrunden) | **Verifikation:** ProVerif + FROST-Testvektoren.

---

## 26. `exp_fungible_proof_of_relay` — Verifizierbare Weiterleitung gegen „Black-Hole-Relays“
- **Umgedrehtes Axiom:** In anonymen Credit-Systemen (`btcr.rs`) kann ein faules oder bösartiges Relay das Paket entgegennehmen, sein Blind-Credit einstreichen und das Paket einfach still wegwerfen (*Silent Packet Dropping*).
- **Konstruktion:**
  - Ein `BTCr v2`-Spend-Token wird beim Hop $i$ erst **bedingt** freigeschaltet (*Hash-Time-Locked Micro-Receipt*):
    $$\text{Unlock}_i \iff H(r_{i+1}) = h_i$$
    - **$h_i$**: Hash-Commitment, das der Absender im verschlüsselten Header für Hop $i$ hinterlegt.
    - **$r_{i+1}$**: Kurzes 16-Byte-Geheimnis, das erst Hop $i+1$ nach erfolgreichem Empfang und AEAD-Prüfung an Hop $i$ zurückgibt.
  - Nur wenn Hop $i$ das Paket wirklich korrekt an Hop $i+1$ geliefert hat, erhält er $r_{i+1}$ und kann sein `BTCr`-Guthaben einlösen — ohne dass irgendein Hop den Nutzinhalt sieht!
- **Andockpunkte im Code:** `src/ghost/v2/btcr.rs`, `src/ghost/net/relay.rs`, `src/ghost/net/bandwidth_voucher.rs`.
- **Ehrliche Grenze:** Ein korrupter Hop $i+1$ könnte das Paket empfangen und trotzdem $r_{i+1}$ zurückhalten (*Griefing*), verliert dadurch aber selbst seine eigene Weiterleitungs-Belohnung $r_{i+2}$.
- **Machbarkeit:** **Ja** | **Verifikation:** ProVerif (`btcr_v2.pv`-Erweiterung).

---

## 27. `exp_post_quantum_group_mls` — Asynchrone Post-Quanten-Gruppen-Ratchets (TreeKEM + ML-KEM)
- **Umgedrehtes Axiom:** Pairwise-Ratchets (`ratchet.rs`) skalieren in Gruppen mit $G$ Mitgliedern (z. B. `ggn party`, `ggn fleet`, Team-Kanäle) quadratisch ($O(G)$ Verschlüsselungen pro Nachricht / $O(G^2)$ beim Schlüsselwechsel).
- **Konstruktion:**
  - Organisiere Gruppenmitglieder als Blätter eines balancierten Binärbaums (**PQ-TreeKEM**, angelehnt an RFC 9420 MLS, aber direkt auf Vantablacks `X25519 + ML-KEM-768`-Layer `l1_kem.rs`):
    $$\text{Update-Kosten}(G) = O(\log_2 G), \qquad K_{\text{root}} = \text{HKDF}(\dots)$$
    - **$\log_2 G$**: Bei einer Gruppe mit $G = 64$ Geräten genügen nur **6** statt 64 hybride KEM-Kapselungen für volle Post-Compromise Security der gesamten Gruppe.
- **Andockpunkte im Code:** `src/ghost/layers/l1_kem.rs`, `src/ghost/session/ratchet.rs`, `src/ghost/v2/fleet.rs`, `src/ghost/v2/party.rs`.
- **Ehrliche Grenze:** Bei gleichzeitigen Gruppen-Updates (Forks) ohne zentralen Delivery-Server braucht es einen deterministischen Tie-Break (z. B. über `braid_identity`-Kausalhöhe).
- **Machbarkeit:** **Ja** | **Verifikation:** ProVerif (Gruppen-FS & Gruppen-PCS).

---

## 28. `exp_homomorphic_telemetry_sketch` — Ende-zu-Ende-verschlüsselte Netzgesundheit
- **Umgedrehtes Axiom:** Um globale Netzprobleme (Massen-Zensur, kaputte Carrier, DDoS-Wellen) zu messen, sammeln normale Systeme Klartext-Telemetrie — oder müssen in `collective_defense.rs` stark verrauschen, um einzelne Nutzer zu schützen.
- **Konstruktion:**
  - Jeder Knoten kodiert seine lokalen Störungsmeldungen in einen kompakten **Count-Min-Sketch** und addiert eine paarweise aufgehobene Maske (*Secure Aggregation* über Ristretto255-Skalare):
    $$\tilde{v}_i = v_i + \sum_{j \neq i} \text{sign}(i, j) \cdot \text{PRF}(K_{ij}, \text{epoch}) \pmod \ell$$
    - **$\text{sign}(i, j) \in \{+1, -1\}$**: Plus für $i < j$, Minus für $i > j$ — summiert man über alle Knoten $i$, heben sich **alle Masken exakt zu 0 auf**, sodass $\sum_i \tilde{v}_i = \sum_i v_i$ die exakte Summe liefert, ohne dass irgendjemand ein einzelnes $v_i$ sieht!
- **Andockpunkte im Code:** `src/ghost/net/collective_defense.rs`, `src/ghost/v2/btcr.rs`, `src/ghost/v2/xray.rs`.
- **Ehrliche Grenze:** Fällt ein Knoten mitten in der Aggregationsrunde aus, fehlen seine Gegen-Masken (lösbar über 1 Runde Shamir-Masken-Recovery, aber erhöht Protokoll-Komplexität).
- **Machbarkeit:** **Vielleicht** (Dropout-Handling ist der knifflige Teil) | **Verifikation:** ProVerif / algebraische Summen-Tests.

---

# Domäne VI — Typ-System-Epistemologie & Formale Laufzeit-Verifikation

## 29. `exp_proof_carrying_config` — Boot-Time Policy-Widerspruchs-Checker
- **Umgedrehtes Axiom:** Komplexe Sicherheits-Tools erlauben gefährliche Konfigurations-Kombinationen (z. B. *„Regime = `vantablack`“* + *„Split-Tunneling = lokal erlauben“* + *„DNS-Fallback = OS-Resolver“*), die im Stillen alle Garantien aushebeln.
- **Konstruktion:**
  - Modelliert alle Regimes (`regime.rs`), Carrier und `exp_*`-Flags als boolesches Constraint-System $\Phi(\text{config})$ beim Daemon-Start:
    $$\text{StartErlaubt} \iff \text{SAT}\!\left(\Phi_{\text{regime}} \land \Phi_{\text{flags}} \land \neg \Phi_{\text{leak}}\right)$$
    - **$\text{SAT}(\dots)$**: Erfüllbarkeitsprüfung — existiert ein Konflikt zwischen versprochener Sicherheitsstufe und aktiviertem Flag, **verweigert der Daemon den Start mit exakter Begründung** (oder verlangt ein explizites `--ack-downgrade`).
- **Andockpunkte im Code:** `src/ghost/v2/regime.rs`, `src/daemon/experimental.rs`, `src/cli.rs`, `src/socks.rs`.
- **Ehrliche Grenze:** Prüft nur Konfigurations-Widersprüche innerhalb von Vantablack, keine OS-Firewall-Fehlkonfigurationen außerhalb des Prozesses.
- **Machbarkeit:** **Ja** (sehr geringer Code-Aufwand, riesiger Sicherheitsgewinn!) | **Verifikation:** Exhaustive Unit-Tests über alle Flag-Kombinationen.

---

## 30. `exp_differential_build_attestation` — Reproducible-Binary Quorum Witness
- **Umgedrehtes Axiom:** Selbst perfekt verifizierter Open-Source-Code nützt nichts, wenn ein kompromittierter Build-Server oder ein infizierter Download ein manipuliertes Binary verteilt — Peers verbinden sich ahnungslos mit gebackdoorten Relays.
- **Konstruktion:**
  - Beim Handshake tauscht jeder Knoten den kryptographischen Messwert seines laufenden Binaries plus des kompilierten `formal/attestations.json`-Roots aus (optional Hardware-signiert via `attest.rs`):
    $$H_{\text{node}} = \text{SHA256}(\text{binary\_digest} \parallel \text{proverif\_attest\_root})$$
  - `xray.rs` vergleicht $H_{\text{node}}$ gegen die von $k$ unabhängigen Reproducible-Build-Signierern bestätigten Release-Hashes und warnt sofort bei unbekannten oder abweichenden Relay-Builds.
- **Andockpunkte im Code:** `build.rs`, `src/ghost/net/security/attest.rs`, `src/ghost/v2/xray.rs`, `src/ghost/layers/l9_infra.rs`.
- **Ehrliche Grenze:** Ein rein in Software laufender, kompromittierter Gegner kann seinen eigenen `binary_digest` lügen — harte Beweiskraft entsteht erst in Kombination mit `hardware-tpm` Remote Attestation (deshalb ehrliche Unterscheidung wie in `sovereign_cloud.rs`).
- **Machbarkeit:** **Ja** (Software-Audit) / **Schwer** (erzwungene Remote-TPM-Attestierung) | **Verifikation:** Reproducible-Build-CI-Check.

---

## 31. `exp_adversarial_chaos_selftest` — Eingebauter kontinuierlicher Red-Team-Agent
- **Umgedrehtes Axiom:** Unit-Tests laufen nur beim Entwickler vor dem Release. Sobald ein Knoten monatelang im Feld läuft, merkt niemand, ob ein OS-Update, ein kaputter Treiber oder eine fehlerhafte Regel den Replay-Guard, Zeroize oder AAD-Check still ausgehebelt hat.
- **Konstruktion:**
  - Ein isolierter Hintergrund-Task im Daemon feuert periodisch (z. B. stündlich) harmlose, lokal synthetisierte **Angriffspakete gegen den eigenen echten RX-Pfad**:
    1. Ein 1-Bit-manipuliertes `576 B`-GTFv2-Frame (muss am Poly1305-Tag droppen),
    2. Eine wiederholte Sequenznummer (muss an `SessionGuardU64` scheitern),
    3. Ein abgelaufener `LightConeProof` (muss auf `Unknown` fallen).
  - Bestehen alle Injektionen den *Expected-Reject*-Test, emittiert der RX-Pfad einen frischen `WireWitness<SelfAudit>` ins `X-Ray`-Ledger; schlägt eine Prüfung fehl, löst sofort der Circuit-Breaker aus!
- **Andockpunkte im Code:** `src/daemon/ingress.rs`, `src/ghost/v2/xray.rs`, `src/ghost/layers/l6_session.rs`.
- **Ehrliche Grenze:** Findet nur Regressionen im eigenen Codepfad, keine unbekannten Zero-Days außerhalb der definierten Test-Vektoren.
- **Machbarkeit:** **Ja** | **Verifikation:** Deterministische Fault-Injection-Tests.

---

## 32. `exp_taint_tracked_secrets` — Typ-erzwungener Informationsfluss für Geheimnisse
- **Umgedrehtes Axiom:** In normalem Code ist ein Schlüssel bloß ein `[u8; 32]`. Ein einziges versehentliches `tracing::debug!("{:?}", key)` oder `serde::Serialize` in einer API-Antwort reicht für einen katastrophalen Key-Leak.
- **Konstruktion:**
  - Symmetrisch zu `WireWitness<P>` (`Theorem 11`) wird jeder sensible Byte-Block in einen linearen Newtype `TaintedSecret<S, const N: usize>` gekapselt:
    - Implementiert bewusst **weder** `Debug`, `Display`, `Serialize`, `Copy`, `Clone` noch `Deref<Target=[u8]>`.
    - Zugriff auf die rohen Bytes ist **nur** über eine geschlossene Closure `expose_in_crypto(|bytes| ...)` innerhalb von `crate::ghost::layers` erlaubt; beim `Drop` wird zwangsweise `zeroize` via `l8_memsec.rs` ausgeführt.
  - Ein versehentliches Loggen oder Senden eines Geheimnisses wird zum **Compile-Time-Fehler**.
- **Andockpunkte im Code:** `src/ghost/layers/l8_memsec.rs`, `src/ghost/layers/l0_identity.rs`, `src/ghost/layers/l1_kem.rs`, `src/ghost/session/ratchet.rs`.
- **Ehrliche Grenze:** Gilt in Safe Rust; `unsafe`-Blöcke (z. B. FFI zu `wintun.dll` oder Hardware-Treibern) müssen manuell auditiert werden.
- **Machbarkeit:** **Ja** (Zero-Cost-Abstraction in Rust!) | **Verifikation:** `trybuild` Compile-Fail-Tests (beweist, dass Logging/Serialize von Secrets nicht kompiliert).

---

## 33. `exp_epistemic_downgrade_circuit_breaker` — Automatisierter Fail-Closed Schutzschalter
- **Umgedrehtes Axiom:** Selbst wenn `xray.rs` ehrlich `Unknown` oder `Violated` anzeigt (z. B. $N_{\text{eff}}$ stürzt unter 200 ab oder `sheaf.rs` meldet eine Eclipse-Blase), bemerkt ein Mensch das rote Symbol im Dashboard oft erst Minuten später — bis dahin sind längst sensible Daten abgeflossen.
- **Konstruktion:**
  - Bindet den ausgehenden Datenpfad (`coalesce.rs` / `socks.rs` / `vpn_client.rs`) direkt an einen atomaren Epistemic-State-Lock aus `xray.rs`:
    $$\text{AllowTx}(p) \iff \forall I \in \mathcal{I}_{\text{regime}}:\; \text{State}(I) = \text{Verified}$$
    - **$\forall I \in \mathcal{I}_{\text{regime}}$**: Für jede einzelne Pflicht-Invariante $I$ des aktiven Regimes (z. B. frischer 3-Hop-Witness, $N_{\text{eff}} \ge 200$, `clock_consistent`).
  - Sobald ein Beweis abläuft oder verletzt wird, **friert der Socket echte Nutzdaten atomar ein** (nur `RACS`-Cover-Traffic läuft weiter, damit selbst der Freeze von außen nicht sichtbar ist!).
- **Andockpunkte im Code:** `src/ghost/v2/xray.rs`, `src/ghost/net/coalesce.rs`, `src/socks.rs`, `src/ghost/net/vpn/client.rs`.
- **Ehrliche Grenze:** Bevorzugt strikt Sicherheit vor Verfügbarkeit — bei instabilen Netzen mit häufig ablaufenden Witnesses pausiert der Datenfluss spürbar.
- **Machbarkeit:** **Ja** | **Verifikation:** Integrationstest mit künstlichem Witness-Ablauf (garantiert 0 abfließende Bytes nach TTL).

---

# Domäne VII — Physik, HF/ABOS & Post-Infrastruktur-Überleben

## 34. `exp_ionospheric_doppler_beacon` — Passives Natur-Clocking ohne GPS & NTP
- **Umgedrehtes Axiom:** Im Internet-Blackout oder unter GPS-Spoofing verliert ein Off-Grid-Knoten seine zuverlässige Uhrzeit — dadurch brechen zeitabhängige Protokolle wie `Chrono-Erosion`, `Rendezvous-Slots`, `Metabolic`-Halbwertszeiten und `SessionGuard`-Timeouts.
- **Konstruktion:**
  - Nutzt `abos-hal` + `abos-dsp` + `abos-iono`, um passiv (ohne selbst einen einzigen Funk-Impuls abzustrahlen!) mehrere unkorrelierte Lang-/Kurzwellen-Zeitzeichensender (DCF77, WWV, WWVH, CHU) gleichzeitig auszuwerten und über Median-Konsens gegen lokales Spoofing zu härten:
    $$\hat{t}_{\text{UTC}} = \text{Median}_{s \in \mathcal{S}}\!\left(t_s^{\text{rx}} - \frac{d_{\text{sky}}(s)}{c}\right)$$
    - **$t_s^{\text{rx}}$**: Lokal gemessene Ankunftszeit des Senders $s$.
    - **$d_{\text{sky}}(s) / c$**: Aus der F2-Schicht-Höhe (`abos-iono/src/fo_f2.rs`) geschätzte Laufzeitkorrektur.
  - Ein lokaler Angreifer kann zwar GPS (schwaches Satellitensignal) leicht spoofen, aber kaum gleichzeitig mehrere europa-/weltweite Lang- und Kurzwellen-Träger samt realer Ionosphären-Doppler-Signatur.
- **Andockpunkte im Code:** `abos/abos-iono/src/fo_f2.rs`, `abos/abos-dsp/`, `src/ghost/net/rendezvous.rs`, `src/ghost/v2/erosion.rs`.
- **Ehrliche Grenze:** Erfordert ein angeschlossenes SDR/HF-Empfangsmodul (`abos-hal`); Genauigkeit liegt im Millisekundenbereich (reicht für Epochen/Slots/TTL, nicht für Nanosekunden-Sync).
- **Machbarkeit:** **Schwer** (braucht reale SDR-Hardware) | **Verifikation:** Offline-IQ-Capture-Testvektoren in `abos-tests`.

---

## 35. `exp_acoustic_ultrasonic_pairing` — Physischer Out-of-Band Nahbereichs-Handshake
- **Umgedrehtes Axiom:** Das schwerste Problem jeder Ende-zu-Ende-Kryptographie bleibt der **erste Kontakt (TOFU — Trust on First Use)**: Woher weißt du beim allerersten Verbinden, dass ein `L0`-Public-Key wirklich der Person vor dir gehört und nicht einem MitM?
- **Konstruktion:**
  - Zwei physisch anwesende Geräte verifizieren ihren gemeinsamen `L0`-Fingerprint + `L1`-Handshake-Transcript $T$ über einen **unhörbaren 18–20 kHz Ultraschall-Chirp** (Mikrofon/Lautsprecher, OFDM-Symbole aus `abos-dsp` wiederverwendet!) oder eine animierte QR-Fontäne:
    $$\text{SAS} = \text{Trunc}_{64}\!\left(\text{BLAKE3}(\text{"VB-OOB-PAIR"} \parallel pk_A \parallel pk_B \parallel T)\right)$$
    - **$\text{Trunc}_{64}$**: Die ersten 64 Bit des Hashes (genügt bei interaktivem Nahbereichs-Abgleich für $2^{-64}$ Fälschungswahrscheinlichkeit).
  - Beseitigt das MitM-Risiko beim Erstkontakt komplett, ohne Internet und ohne vertrauenswürdige Server.
- **Andockpunkte im Code:** `src/ghost/layers/l0_identity.rs`, `src/ghost/layers/l1_kem.rs`, `abos/abos-dsp/src/ofdm.rs`, `src/ghost/v2/fleet.rs`.
- **Ehrliche Grenze:** Mikrofon-/Lautsprecher-Frequenzgänge variieren stark je nach Smartphone/Laptop (oft harte Tiefpassfilter bei 16–18 kHz); QR-Code-Fallback bleibt für volle Zuverlässigkeit nötig.
- **Machbarkeit:** **Ja** | **Verifikation:** Audio-Loopback-Test + ProVerif (authentifiziertes Out-of-Band-Channel-Modell).

---

## 36. `exp_solar_battery_adaptive_crypto` — Energie-gekoppelte Sicherheits-Pareto-Steuerung
- **Umgedrehtes Axiom:** Feste Sicherheits-Profile (`vantablack`-Regime mit Dauer-Cover-Traffic und voller LDPC-Dekodierung) saugen Off-Grid- oder Solar-Relay-Knoten in Stunden leer — und ein ausgeschalteter Knoten hat **0 % Anonymität und 0 % Verfügbarkeit**.
- **Konstruktion:**
  - Der Knoten misst Batteriestand $E_{\text{bat}} \in [0, 1]$ und Ladeleistung und passt kontinuierlich die **Betriebs-Pareto-Front** an:
    - Verlängert kontrolliert das `Shaped-RACS`-OFF-Fenster $T_{\text{off}}$ (damit Mobilfunk-Modems in `RRC_IDLE` schlafen),
    - skaliert `abos-fec` LDPC-Iterationen und `HPEB`-Redundanz dynamisch,
    - **und** meldet jede abgesenkte Sicherheitsmarge brutal ehrlich als explizite Metrik ins `X-Ray`-Ledger (`Degraded-Power`, niemals stilles grünes `Verified`!).
- **Andockpunkte im Code:** `src/ghost/v2/racs.rs`, `src/ghost/v2/xray.rs`, `abos/abos-fec/src/ldpc.rs`, `src/ghost/v2/hpeb.rs`.
- **Ehrliche Grenze:** Längere OFF-Fenster erhöhen nach dem `Shaped-RACS`-Tradeoff-Gesetz (`Invention 4`) unvermeidlich die Worst-Case-Paketlatenz $T_{\text{off}}$.
- **Machbarkeit:** **Ja** | **Verifikation:** Energie-/Latenz-Simulationskurven.

---

## 37. `exp_opportunistic_multipath_acoustic_rf` — Cross-Medium-Polysemie (Orthogonale Physik-Dimensionen)
- **Umgedrehtes Axiom:** `Causal Polysemy` (`polysemy.rs`) über `Wi-Fi + 5G + Starlink` nutzt zwar drei Provider — aber alle drei laufen über **IP-Infrastruktur**, die ein Staat per zentraler Internet-Abschaltung gleichzeitig kappen kann.
- **Konstruktion:**
  - Verteilte Polysemie-Shards über **physikalisch orthogonale Transportmedien**:
    - Pfad 1: Glasfaser/WAN (`UDP`/`MASQUE`),
    - Pfad 2: Ionosphärische Steilstrahlung (`ABOS-NVIS`, 2–10 MHz),
    - Pfad 3: Lokale Nahbereichs-Fähre (`BLE`/Wi-Fi-Direct aus #19).
  - Nach `Theorem 12` (`Causal Polysemy`) kollabiert das System bei einem Internet-Blackout automatisch auf die authentifizierte `{ABOS-HF, BLE}`-Notfallrealität, während die Internet-Realität 0 Bit Spur hinterlässt.
- **Andockpunkte im Code:** `src/ghost/net/polysemy.rs`, `src/ghost/net/sdr_bridge.rs`, `src/ghost/v2/continuum.rs`.
- **Ehrliche Grenze:** Durchsatz der kombinierten Notfall-Realität wird durch den langsamsten beteiligten Pfad (`ABOS-NVIS`: wenige hundert Bit/s) begrenzt — sinnvoll nur für hochkritische Befehle, Keys und Kurznachrichten.
- **Machbarkeit:** **Vielleicht** (erbt SDR-Hardware-Bedarf für Pfad 2) | **Verifikation:** `formal/causal_polysemy.pv` + Multi-Medium-Simulator.

---

## 38. `exp_meteor_burst_ephemeral_sync` — Meteor-Scatter-Kurzburst-Synchronisation
- **Umgedrehtes Axiom:** Wenn eine Region komplett vom Internet abgetrennt ist **und** die F2-Ionosphäre durch Sonnenstürme oder Störsender gestört wird, scheint Fernkommunikation über 800–2000 km unmöglich.
- **Konstruktion:**
  - Aktiviert `abos/abos-iono/src/meteor.rs` gezielt für **ultrakurze, hochkritische Vantablack-Kontroll-Pakete** (`400 B` `Braid`-Clone-Suicide-Proofs, `64 B` `Entropy-Beacon`-Roots, `Deadman`-Lebenspulse):
    - Millisekunden-lange ionisierte Spuren von Mikrometeoriten in 85–115 km Höhe reflektieren VHF-Bursts extrem gerichtet (schmaler Fußabdruck $\implies$ von Natur aus extrem schwer abhörbar/peilbar!).
    - Der Sender wartet passiv auf einen kurzen Reflexions-Ping und feuert sofort ein einziges LDPC-codiertes `576 B`-GTFv2-Frame durch das 0,5-Sekunden-Fenster.
- **Andockpunkte im Code:** `abos/abos-iono/src/meteor.rs`, `abos/abos-phy/src/burst.rs`, `src/ghost/net/braid_identity.rs`.
- **Ehrliche Grenze:** Benötigt VHF-SDR + Richtantenne; sehr unregelmäßige Burst-Intervalle (Sekunden bis Minuten zwischen brauchbaren Meteorspuren).
- **Machbarkeit:** **Schwer** (reale VHF-SDR-Hardware erforderlich) | **Verifikation:** `abos-tests` Kanalmodell für stochastische Burst-Fenster.

---

# Domäne VIII — Verteilte Souveräne Berechnung & Kollektive Intelligenz

## 39. `exp_verifiable_blind_micro_agents` — Private Mesh-Orakel für Bedrohungs-Klassifikation
- **Umgedrehtes Axiom:** Ein lokaler Malware-/Phishing-Schutz (`threat_shield.rs`) hat bisher nur zwei Optionen: entweder veraltete statische Blocklisten (`threat_feed.rs`) oder Cloud-Abfragen (die der Cloud deinen gesamten Browserverlauf verraten!).
- **Konstruktion:**
  - Nutzt `LC-Vantablack` (`sharded_compute.rs` + `lagrange.rs`, `Theorem 10`) für kleine, **polynomiell gebundene Klassifikationsmodelle** ($d \le 2$, z. B. quadratische Feature-Bewertung für Phishing-Domains oder Anomalie-Scoring):
    - Der Client zerlegt seinen Feature-Vektor $X$ mit Zufallsmaske $Z$ in $N \ge d(K+T-1)+1+S+2A$ Lagrange-Shares und fragt $N = 5$ unabhängige Worker in disjunkten ASNs ab.
    - Kein einzelner Worker sieht die abgefragte URL ($T$-Privacy), 1 Worker darf offline sein ($S = 1$) und 1 Worker darf aktiv lügen ($A = 1$).
- **Andockpunkte im Code:** `src/ghost/net/sharded_compute.rs`, `src/ghost/net/sharded_compute/lagrange.rs`, `src/ghost/net/threat_shield.rs`.
- **Ehrliche Grenze:** Funktioniert schnell und exakt nur für kleine lineare/quadratische Modelle ($d \le 2$), nicht für riesige Deep-Learning-Modelle.
- **Machbarkeit:** **Ja** (genau der realistische Sweet-Spot für `LC-Vantablack`!) | **Verifikation:** Unit-Tests mit injizierten byzantinischen Workern in `lagrange.rs`.

---

## 40. `exp_oblivious_psi_contact_discovery` — Private Set Intersection (PSI) für Kontakte
- **Umgedrehtes Axiom:** Neue Nutzer stehen vor einem leeren Mesh („Wer meiner Freunde nutzt Vantablack?“). Klassische Messenger laden dafür dein ganzes Adressbuch auf einen zentralen Server — ein massives soziales Metadaten-Leak.
- **Konstruktion:**
  - **Ristretto255-DH-OPRF-PSI** zwischen zwei Peers (oder gegen einen anonymen Directory-Shard ohne Adressbuch-Klartext):
    - Alice blendet jeden ihrer Kontakt-Hashes $c_i$ mit geheimem Skalar $a$: $A_i = a \cdot H_{\mathbb{G}}(c_i)$.
    - Bob multipliziert mit seinem Skalar $b$: $AB_i = b \cdot A_i = (ab) \cdot H_{\mathbb{G}}(c_i)$, und schickt seine eigenen $B_j = b \cdot H_{\mathbb{G}}(c'_j)$.
    - Alice berechnet $a \cdot B_j = (ab) \cdot H_{\mathbb{G}}(c'_j)$ und findet exakt die Schnittmenge $A \cap B$:
      $$x \in A \cap B \iff (ab) \cdot H_{\mathbb{G}}(x) \in \{AB_i\} \cap \{a \cdot B_j\}$$
    - **Keiner erfährt auch nur einen einzigen Nicht-Kontakt des anderen!**
- **Andockpunkte im Code:** `src/ghost/v2/btcr.rs` (Ristretto255-Infrastruktur), `src/ghost/net/discovery.rs`, `src/ghost/v2/vbdns.rs`.
- **Ehrliche Grenze:** Schützt nicht gegen einen Angreifer, der gezielt Millionen zufälliger Telefonnummern in sein eigenes Set steckt (*Rate-Limiting* via `pow.rs` / `btcr.rs` nötig).
- **Machbarkeit:** **Ja** (Ristretto255 liegt bereits im Crate!) | **Verifikation:** ProVerif (Unkenntnis über Nicht-Schnittmenge).

---

## 41. `exp_self_healing_erasure_swarm` — Autonome Proof-of-Retrievability Reparatur-Schwärme
- **Umgedrehtes Axiom:** Dezentrale Archive (`mesh_archive.rs`, `dead_drop.rs`) sterben langsam aus (*Bit Rot / Peer Churn*): Verschwinden über Monate genug Knoten mit Shards, fällt die Anzahl unter $k$ und die Daten sind unwiederbringlich weg — obwohl vorher niemand etwas gemerkt hat.
- **Konstruktion:**
  - Periodischer **blinder Audit-Loop**: Ein Zufalls-Wächter schickt eine kurze Challenge $r$ an die Halter der $n$ Shards eines Root-Hashes; jeder Halter antwortet mit einem kompakten Hash-Beweis `BLAKE3(r || shard_i)` (beweist Live-Besitz ohne Übertragung des ganzen Shards).
  - Sinkt die Zahl antwortender Halter unter einen Warn-Schwellenwert $k_{\text{warn}}$ (mit $k < k_{\text{warn}} < n$), sammeln beliebige $k$ überlebende Knoten kurzzeitig ihre verschlüsselten Shards, regenerieren den verlorenen Paritäts-Shard über `l4_rs.rs` und schieben ihn auf einen frischen Peer in einem neuen ASN — belohnt über `energy_currency.rs` / `btcr.rs`.
- **Andockpunkte im Code:** `src/ghost/net/mesh_archive.rs`, `src/ghost/net/dead_drop.rs`, `src/ghost/layers/l4_rs.rs`, `src/ghost/net/energy_currency.rs`.
- **Ehrliche Grenze:** Ein Knoten, der eine Datei nur als „Dead-Drop“ temporär speichern soll, muss explizit von Auto-Repair ausgeschlossen werden (sonst kämpft Auto-Repair gegen `Chrono-Erosion`!).
- **Machbarkeit:** **Ja** | **Verifikation:** Churn-Simulation über 10.000 Epochen.

---

## 42. `exp_epistemic_consensus_lite` — Konflikt-bewusster Partial-Order-Konsens ohne Blockchain
- **Umgedrehtes Axiom:** Viele dezentrale Systeme glauben, sie müssten für globale Ereignisse (z. B. globale `Threat-Feed`-Updates oder Notfall-Revocations) entweder eine zentrale Autorität oder eine riesige Blockchain (PoW/PoS) einführen — und lügen bei einer Netz-Partition über angebliche „Finalität“.
- **Konstruktion:**
  - Kombiniert **Bracha Reliable Broadcast** ($N \ge 3f + 1$ über $N_{\text{eff}}$-gewichtete Domänen) mit der **Epistemic Sheaf Cohomology** (`sheaf.rs`):
    - Existiert ein eindeutiges Quorum ohne topologische Zyklen-Widersprüche ($[\delta] = 0 \in H^1$), wird der Zustand als `Consensus::Verified` akzeptiert.
    - Erkennt das Netz eine Partition oder widersprüchliche Sichten ($[\delta] \neq 0$), friert es Updates **ehrlich im Zustand `Consensus::Partitioned`** ein (sichtbar in `xray.rs`), statt zwei getrennte „Wahrheiten“ vorzutäuschen.
- **Andockpunkte im Code:** `src/ghost/net/sheaf.rs`, `src/ghost/net/threat_feed.rs`, `src/ghost/v2/xray.rs`, `src/ghost/net/braid_identity.rs`.
- **Ehrliche Grenze:** Nach dem **CAP-/FLP-Theorem** gibt es bei asynchroner Netz-Partition niemals gleichzeitig Liveness und Safety — dieses Modul wählt bewusst **Safety + Ehrlichkeit** (`Partitioned` statt falscher Konvergenz).
- **Machbarkeit:** **Ja** | **Verifikation:** Jepsen-ähnliche Partition-Tests in `scale_mesh.rs`.

---

# Domäne IX — Spieltheorie, Anreiz-Mechanik & Selbstverteidigende Ökonomie

## 43. `exp_harberger_relay_slotting` — Konvexe Konzentrations-Steuer zur $N_{\text{eff}}$-Maximierung
- **Umgedrehtes Axiom:** In offenen Relay-Netzen belohnen lineare Vergütungen („pro weitergeleitetem GB“) große Rechenzentren — genau das zerstört aber die effektive Diversität $N_{\text{eff}}$ (`Theorem 04`) und treibt das Netz in die Zentralisierung.
- **Konstruktion:**
  - Die effektive Vergütungs- und Auswahlrate einer Domäne $i$ mit Bandbreitenanteil $w_i$ wird konvex gedämpft, sobald ihr Gewicht das Gleichgewicht $1/m$ übersteigt:
    $$R_i(w_i) = \frac{w_i}{1 + \lambda_{\text{conc}} \cdot w_i^2}$$
    - **$w_i$**: Anteil der Domäne/ASN $i$ an der Gesamt-Bandbreite.
    - **$\lambda_{\text{conc}} > 0$**: Konzentrations-Strafparameter — ein Monopolist verdient pro zusätzlichem Relay immer weniger, während kleine, neue ASNs maximal belohnt werden.
- **Andockpunkte im Code:** `src/ghost/v2/btcr.rs`, `src/ghost/v2/regime.rs`, `src/ghost/net/relay.rs`.
- **Ehrliche Grenze:** Ohne `LightCone-Proof` oder ASN-/RPKI-Prüfung könnte ein Großbetreiber seine Relays auf viele kleine Billig-VPS-Hoster aufteilen, um die Kurve zu umgehen.
- **Machbarkeit:** **Ja** | **Verifikation:** Spieltheoretische Gleichgewichts-Simulation über $N_{\text{eff}}$.

---

## 44. `exp_mutually_assured_reputation_stake` — Verdecktes Krypto-Pfand gegen Equivocation
- **Umgedrehtes Axiom:** Slashing (Strafverlust bei Betrug) scheint bisher an öffentliche Blockchain-Konten gebunden zu sein — was aber die Anonymität der Betreiber zerstört.
- **Konstruktion:**
  - Ein Relay hinterlegt vor Teilnahme an sensitiven Komitees ein unverkettbares, per `BTCr`-Bucket quantisiertes Arbeits-/Credit-Pfand gebunden an seine Epochen-`Braid`-Spitze.
  - Emittiert das Relay widersprüchliche Nachrichten (z. B. `Braid`-Equivocation oder nachgewiesenes `Proof-of-Relay`-Dropping), erlaubt der `400 B`-Betrugsbeweis jedem Finder, den gebundenen Pfand-Nullifier kryptographisch zu verbrennen (und ggf. eine Finder-Prämie zu ziehen).
- **Andockpunkte im Code:** `src/ghost/net/braid_identity.rs`, `src/ghost/v2/btcr.rs`, `src/ghost/net/energy_currency.rs`.
- **Ehrliche Grenze:** Wirkt nur für *kryptographisch beweisbares* Fehlverhalten (Equivocation, ungültige Proofs), nicht für rein passives Schweigen/Offline-Gehen.
- **Machbarkeit:** **Vielleicht** (sauberes Nullifier-Design nötig) | **Verifikation:** ProVerif (No-False-Slashing Query wie in `formal/braid_identity.pv`).

---

## 45. `exp_altruistic_cover_barter` — Kooperatives Cover-Traffic-Tauschen (Desktop-Patenschaft für Handys)
- **Umgedrehtes Axiom:** Echter `Shaped-RACS`-Cover-Traffic ist auf akkubetriebenen Smartphones teuer — daher schalten mobile Nutzer ihn oft ab und werden genau dadurch korrelierbar.
- **Konstruktion:**
  - Ein heimischer Desktop-Knoten (`boomerang.rs`) und ein mobiles Gerät schließen einen asymmetrischen `BTCr v2`-Tauschvertrag: Der Desktop übernimmt ressourcenintensives Relay-/Cover-Forwarding im Mesh, während das Mobilgerät die verdienten Credits nutzt, um hochfrequentes Guard-Mixing und kurze Aufwach-Bursts zu priorisieren.
- **Andockpunkte im Code:** `src/ghost/v2/boomerang.rs`, `src/ghost/v2/btcr.rs`, `src/ghost/v2/racs.rs`.
- **Ehrliche Grenze:** Kann die letzte Funkstrecke zwischen Handy und Mobilfunkmast physikalisch nicht vom Cover-Zwang befreien (senkt aber die Gesamt-CPU-/Relay-Last des Handys drastisch).
- **Machbarkeit:** **Ja** | **Verifikation:** Batterie-/Bandbreiten-Budget-Simulation.

---

## 46. `exp_sybil_tax_pow_vdf_ladder` — Memory-Hard + Zeit-Sequenzielle Sybil-Leiter
- **Umgedrehtes Axiom:** Reines `SHA-256`-Proof-of-Work (`pow.rs`) lässt sich von einem staatlichen Angreifer mit ASICs oder 10.000 GPUs millionenfach parallelisieren — in Sekunden überschwemmt er das Mesh mit Sybils.
- **Konstruktion:**
  - Ersetze das einfache `SHA-256`-Puzzle beim Eintritt neuer unauthentifizierter Knoten durch eine zweistufige Kombination aus **Memory-Hard `Argon2id`** (gegen ASICs/GPUs) **und** einer streng sequenziellen **VDF-Kette** (gegen Parallelisierung):
    $$T_{\text{entry}}(k) = T_{\text{Argon2}}(M_{\text{RAM}}) + T_{\text{VDF}}(2^{d_0 + k})$$
    - **$M_{\text{RAM}}$**: Mindestens benötigter Arbeitsspeicher pro Identitäts-Versuch.
    - **$2^{d_0 + k}$**: Exponentiell wachsende sequenzielle Rechenzeit pro zusätzlichem Identitäts-Request $k$ aus derselben Subnetz-/Präfix-Klasse.
- **Andockpunkte im Code:** `src/ghost/net/pow.rs`, `src/daemon/auth.rs`, `src/ghost/net/discovery.rs`.
- **Ehrliche Grenze:** Verlangsamt auch für ehrliche Nutzer den allerersten Kaltstart um einige Sekunden (einmalig pro neuer Identität).
- **Machbarkeit:** **Ja** | **Verifikation:** Benchmark CPU vs. Multi-Core-Angreifer.

---

## 47. `exp_incentivized_censorship_bounty` — Selbstfinanzierendes Globales Zensur-Radar
- **Umgedrehtes Axiom:** Zensur-Messung (wie OONI) hängt bisher von Freiwilligen und zentralen Spenden ab; im Ernstfall melden zu wenige Knoten zu spät.
- **Konstruktion:**
  - Knoten, die als Erste eine kryptographisch belegte `Sheaf`-$H^1$-Zensur-Anomalie (`sheaf.rs`) oder einen systematischen Carrier-Block (`collective_defense.rs`) über `CDEF`-Reports melden und durch $k \ge 3$ unabhängige Peers bestätigt bekommen, erhalten automatisch ein blindes `BTCr v2`-Guthaben für eigene Prioritäts-Bandbreite.
- **Andockpunkte im Code:** `src/ghost/net/collective_defense.rs`, `src/ghost/net/sheaf.rs`, `src/ghost/v2/btcr.rs`.
- **Ehrliche Grenze:** Muss gegen „Fake-Zensur-Meldungen“ abgesichert werden (deshalb erst Auszahlung ab Bestätigung durch $k \ge 3$ disjunkte ASNs!).
- **Machbarkeit:** **Vielleicht** | **Verifikation:** Spieltheoretischer Sybil-Griefing-Test.

---

## 48. `exp_coalition_breaking_split_reward` — Anti-Kollusions-Gefangenendilemma für Komitees
- **Umgedrehtes Axiom:** Schwellenwert-Verfahren (`Chrono-Erosion`, `Threshold-Exit`, `Entropy-Beacon`) vertrauen darauf, dass weniger als $t$ Mitglieder zusammenarbeiten. Was, wenn ein Angreifer $t$ Mitglieder heimlich besticht?
- **Konstruktion:**
  - Jedes Komitee-Mitglied hinterlegt ein anonymes Pfand (#44). Ein geheimes Whistleblower-Protokoll erlaubt es **jedem einzelnen** bestochenen Mitglied, anonym einen ZK-Beweis einzureichen, dass ein anderes Mitglied seinen privaten Share $s_j$ geteilt hat (Nachweis der Kenntnis von $s_j$ ohne Preisgabe der eigenen Identität) — und dafür sofort die gesamte Pfand-Summe der Verschwörer zu kassieren.
  - **Spieltheoretisches Resultat:** Jede Kollusion ab $t \ge 2$ wird zum instabilen Gefangenendilemma (*Dominante Strategie: Verrat vor den anderen!*).
- **Andockpunkte im Code:** `src/ghost/v2/erosion.rs`, `src/ghost/layers/l3_shamir.rs`, `src/ghost/v2/btcr.rs`.
- **Ehrliche Grenze:** Hilft gegen Bestechung unabhängiger Betreiber — hilft **nicht**, wenn alle $t$ Knoten derselben einzigen Organisation gehören (Sybil-Komitee).
- **Machbarkeit:** **Vielleicht** | **Verifikation:** Spieltheoretischer Nash-Gleichgewichts-Nachweis + ProVerif.

---

## 49. `exp_elastic_exit_marketplace` — Quantisierte Zweitpreis-Kapazitätsauktion
- **Umgedrehtes Axiom:** Bei Überlastung eines Exits führt „First-Come, First-Served“ zu Paketverlust für alle — klassische dynamische Preise dagegen zerstören nach `Theorem 03` (`BTCr Quantization`) die Anonymität durch eindeutige Beträge.
- **Konstruktion:**
  - Exits bieten Überlast-Priorität ausschließlich in den **3 quantisierten `BTCr v2`-Stufen** (`1 / 16 / 256 MiB`) per blinder Zweitpreis-Clearing-Stufe an: Jeder Nutzer in derselben Stufe zahlt dasselbe Einheits-Token — maximale Effizienz bei exakt erhaltener Bucket-Anonymität $\log_2 k(d, \tau)$.
- **Andockpunkte im Code:** `src/ghost/v2/btcr.rs`, `src/ghost/net/egress.rs`, `src/ghost/net/relay.rs`.
- **Ehrliche Grenze:** Grobkörnige 3-Stufen-Quantisierung ist weniger fein als kontinuierliche Preise (bewusster Privacy-Trade-off nach `Theorem 03`).
- **Machbarkeit:** **Ja** | **Verifikation:** `Theorem 03`-Konformitätsprüfung.

---

# Domäne X — Semantik, Mensch-Maschine-Epistemik & Post-Silicon-Grenzen

## 50. `exp_semantic_noise_injection` — Anwendungsschicht-Kontext-Entkopplung
- **Umgedrehtes Axiom:** Selbst wenn IP, Timing und Paketgröße zu 100 % geschützt sind, verrät der **Inhalt** einer HTTP-/Such-/LLM-Anfrage am Zielserver (Themenmuster, Schreibstil, Abfragezeitpunkt) oft sofort die Identität des Nutzers.
- **Konstruktion:**
  - Ein opt-in Anwendungsschicht-Proxy vor `socks.rs` / `expose.rs` mischt auf unkritischen Lese-Endpunkten zeitlich entkoppelte, thematisch benachbarte Decoy-Abfragen aus einer lokalen Wörterbuch-/Corpus-Verteilung bei, um Profil-Schärfe am Zielserver abzuflachen:
    $$H(\text{Nutzerprofil} \mid \text{Echt} \cup \text{Decoy}) \gg H(\text{Nutzerprofil} \mid \text{Echt})$$
- **Andockpunkte im Code:** `src/socks.rs`, `src/ghost/v2/expose.rs`, `src/ghost/net/adblock.rs`.
- **Ehrliche Grenze:** Darf **niemals** auf zustandsverändernde Endpunkte (`POST`/`DELETE`/Logins) angewendet werden und ist gegen sehr fortgeschrittene semantische LLMs nur eine Abschwächung, keine mathematische 0-Bit-Garantie.
- **Machbarkeit:** **Vielleicht** (schwer, wirklich natürlich wirkende Decoys ohne eigenes Muster zu erzeugen) | **Verifikation:** Stilometrie-/Klassifikator-Benchmark.

---

## 51. `exp_epistemic_ui_friction` — Kognitive Sicherheits-Reibung gegen „Alert Fatigue“
- **Umgedrehtes Axiom:** Die stärkste Kryptographie der Welt scheitert in 0,5 Sekunden, wenn ein müder Mensch ein rotes Zertifikats-Warnfenster reflexartig mit „Fortfahren“ wegklickt.
- **Konstruktion:**
  - Verknüpft kritische Zustandswechsel im `X-Ray`-Ledger (z. B. Key-Wechsel eines bekannten Kontakts, `Sheaf`-Anomalie, Absturz von `Verified` auf `Violated`) in `webview.rs` mit **adaptiver kognitiver Reibung**:
    - Kein einfacher „Weiter“-Button, sondern eine gezielte, kurze Bestätigung der konkreten Konsequenz (z. B. Eintippen des 4-Zeichen-SAS-Präfixes oder explizite Wahl des Downgrade-Regimes).
- **Andockpunkte im Code:** `src/webview.rs`, `src/ghost/v2/xray.rs`, `src/ghost/net/consumer.rs`.
- **Ehrliche Grenze:** Reines Human-Factors-Design — schützt vor versehentlichem Durchklicken, nicht vor bewusst ignorierenden Nutzern.
- **Machbarkeit:** **Ja** | **Verifikation:** UI-State-Machine-Tests.

---

## 52. `exp_plausible_identity_mitosis` — Kontrollierte Identitäts-Zellteilung (Unverkettbare Personas)
- **Umgedrehtes Axiom:** Ein einziges Gerät hat klassisch genau **eine** `identity.key` (`l0_identity.rs`). Wer denselben Vantablack-Client für Arbeit, Privates und Aktivismus nutzt, riskiert Identitäts-Korrelation zwischen Kontexten.
- **Konstruktion:**
  - Ein Offline-Master-Root (`fleet.rs`) erzeugt über gehärtete Domain-Separation (`HKDF("VB-MITOSIS" || persona_id)`) mehrere **vollständig isolierte Sub-Identitäten** auf demselben Gerät — jede mit eigener `Braid`-Kette, eigener `Ratchet`-Epoche, eigenem `SessionGuard` und eigenen Guard-Relays, sodass kein Netzwerk-Beobachter zwei Personas desselben Geräts verknüpfen kann.
- **Andockpunkte im Code:** `src/ghost/layers/l0_identity.rs`, `src/ghost/v2/fleet.rs`, `src/daemon/node.rs`.
- **Ehrliche Grenze:** Wenn beide Personas gleichzeitig exakt zur selben Millisekunde über denselben lokalen ISP ohne `Shaped-RACS` funken, verrät das gemeinsame Netzwerk-Interface die Ko-Lokalität (daher nur stark zusammen mit `racs.rs`!).
- **Machbarkeit:** **Ja** | **Verifikation:** ProVerif (Persona-Unlinkability).

---

## 53. `exp_hardware_rng_entropy_mixer` — Multi-Quellen-Entropie-Extraktor gegen CPU-Backdoors
- **Umgedrehtes Axiom:** Fast jede Krypto-Software vertraut blind einem einzigen Zufallsgenerator (`OsRng` / CPU-`RDRAND`). Ist der Hardware-RNG kompromittiert (z. B. manipulierte Mikrocode-Instruktion) oder der OS-Pool beim Booten schwach, fallen alle `ML-KEM`- und `Ed25519`-Keys.
- **Konstruktion:**
  - Kombiniert **fünf physikalisch/systemisch unabhängige Entropiequellen** durch einen kryptographischen BLAKE3-/HKDF-Extraktor:
    $$E_{\text{seed}} = \text{BLAKE3}\big(E_{\text{OsRng}} \parallel E_{\text{CPU-Jitter}} \parallel E_{\text{Net-Arrival-ns}} \parallel E_{\text{ABOS-RF}} \parallel E_{\text{QEL}}\big)$$
    - Solange **mindestens eine** dieser Quellen echte Min-Entropie $H_\infty \ge 256\text{ Bit}$ liefert, ist $E_{\text{seed}}$ (analog zum *Leftover Hash Lemma* und `Theorem 09`) ununterscheidbar von idealem Zufall!
- **Andockpunkte im Code:** `src/ghost/layers/l0_identity.rs`, `src/ghost/layers/l1_kem.rs`, `src/ghost/layers/l10_qel.rs`.
- **Ehrliche Grenze:** Reine Software-Jitter-Schätzung auf stark virtualisierten VMs kann geringe echte Entropie haben — daher bleibt `OsRng` Pflicht-Basis, niemals Ersatz.
- **Machbarkeit:** **Ja** (sehr sauber, winziger Code, hoher Schutz gegen Supply-Chain-/CPU-Backdoors) | **Verifikation:** NIST SP 800-90B Entropie-Tests.

---

## 54. `exp_silent_mesh_bios_recovery` — Auditierbarer `no_std` Minimal-Überlebenskern
- **Umgedrehtes Axiom:** Ein großes Desktop-Binary mit WebView, HTTP-Server und OS-Treibern hat Millionen Zeilen Abhängigkeiten — fällt ein Betriebssystem durch Malware oder Zensur-Sperren aus, bricht die Kommunikation ab.
- **Konstruktion:**
  - Extrahiert einen winzigen, `no_std`-fähigen kryptographischen Überlebenskern (`l0` + `l1` + `l2` + `l4` + `abos-protocol`) ohne Allocator-Zwang und ohne UI, der direkt auf eingebetteter Hardware (ESP32/RP2350/Router-Flash) oder einem Live-USB-Rettungssystem läuft und Notfall-Shards über serielle Konsole oder SDR absetzt.
- **Andockpunkte im Code:** `src/ghost/layers/l4_rs.rs` (bereits Zero-Allocation!), `src/ghost/layers/l2_aead.rs`, `abos/abos-protocol/`.
- **Ehrliche Grenze:** Erfordert strikte `#![no_std]`-Pflege für die Kern-Krypto-Crates und verzichtet bewusst auf Komfort-Layer (`webview`, `socks`, `masque`).
- **Machbarkeit:** **Vielleicht** (Krypto-Crate-Refactoring auf `no_std` erfordert Disziplin) | **Verifikation:** Cross-Compile-Target (`thumbv7em-none-eabihf` / `riscv32imac`).

---

## 55. `exp_counterfactual_audit_replay` — Lokaler „Was-wäre-wenn“-Angriffs-Simulator
- **Umgedrehtes Axiom:** Nutzer erfahren erst *nach* einem echten Angriff, ob ihr Routing-Verhalten, ihre Online-Zeiten oder ihre Guard-Wahl verwundbar waren.
- **Konstruktion:**
  - Ein lokaler, rein in-memory arbeitender Audit-Simulator im `X-Ray`-Subsystem spielt anonymisierte Zeit-/ASN-Spuren der eigenen Sitzung gegen verschiedene virtuelle Angreifer-Profile durch (Passiver ISP, kompromittiertes Cloud-ASN, aktiver Timing-Korrelator) und berechnet eine konkrete, ehrliche **Empirische Korrelations-Obergrenze** $\hat{P}_{\text{corr}}$ direkt für die eigenen Nutzungsgewohnheiten.
- **Andockpunkte im Code:** `src/ghost/v2/xray.rs`, `src/ghost/v2/regime.rs`, `src/bin/scale_mesh.rs`.
- **Ehrliche Grenze:** Ein Simulator ist immer nur so stark wie seine einprogrammierten Angreifermodelle — darf niemals als „100 % unknackbar“-Garantie dargestellt werden.
- **Machbarkeit:** **Ja** | **Verifikation:** Reproduzierbare Szenario-Suites.

---

## 56. `exp_cognitive_sidechannel_keystroke_pad` — Tastenanschlag-Timing-Glättung für interaktive Tunnel
- **Umgedrehtes Axiom:** Selbst durch einen perfekten `576 B`-Tunnel lecken interaktive SSH- oder Terminal-Sitzungen (`universal_tunnel.rs` / `expose.rs`) getippte Passwörter und Kommandos über die Millisekunden-Abstände zwischen einzelnen menschlichen Tastendrücken (*Inter-Keystroke Timing Side-Channel*)!
- **Konstruktion:**
  - Erkennt der Tunnel interaktive Low-Bandwidth-TCP-Streams (z. B. SSH/Terminal), puffert er ausgehende Einzelzeichen lokal und gibt sie ausschließlich auf dem **input-unabhängigen `Shaped-RACS`-Gitter** als gleichförmige `576 B`-Frames frei — jeder menschliche Tipp-Rhythmus wird vollständig ausgelöscht ($I(\text{Tipp-Rhythmus}; O) = 0$).
- **Andockpunkte im Code:** `src/ghost/net/universal_tunnel.rs`, `src/ghost/v2/racs.rs`, `src/daemon/tunnel.rs`.
- **Ehrliche Grenze:** Fügt spürbare Tipp-Latenz von bis zu einem Slot-Intervall (z. B. `40–80 ms`) hinzu — bewusst nur für sensible interaktive Sessions (`vantablack`-Regime) aktivierbar.
- **Machbarkeit:** **Ja** (winziger Code, behebt einen der berühmtesten realen SSH/Tor-Seitenkanäle!) | **Verifikation:** Timing-Entropie-Test auf realen SSH-Keystroke-Traces.

---

## 57. `exp_anonymous_abuse_strikes` — Multi-ASN Anonymes Blacklisting (`BLAC` / `Nymble`)
- **Umgedrehtes Axiom:** Klassische Anonymitätsnetze kennen beim Missbrauch (DDoS, Spam, Port-Scans, Botnets) nur zwei kaputte Extreme: entweder totale Hilflosigkeit (jeder Angreifer zieht endlos weiter) oder De-Anonymisierung durch Logging.
- **Konstruktion:**
  - Baut auf den Ristretto255-Tickets aus `src/ghost/v2/btcr.rs` und der Anti-Abuse-Spezifikation in `docs/anti_abuse.md` (§5) auf:
    - Objektive Verstöße gegen `egress.rs` / `threat_shield.rs` erzeugen signierte Strike-Tokens.
    - Erst ab $k \ge 3$ unabhängigen Strikes aus **$\ge 3$ verschiedenen ASNs** ($N_{\text{eff}}^{\text{strikes}} \ge 3$) landet das Ticket-Pseudonym auf der zeitlich verfallenden Epochen-Blacklist.
    - Jeder Client beweist beim Circuit-Aufbau in Zero-Knowledge Nicht-Mitgliedschaft:
      $$\pi = \text{ZK}\big\{\text{Ticket-Seed } s \notin \text{Blacklist}_{\text{epoch}}\big\}$$
    - Kombiniert mit Sandbox-Eintritt (`#46 pow_vdf_ladder`) + Pfand-Verlust (`#44`) gegen triviales `rm identity.key`.
- **Andockpunkte im Code:** `src/ghost/v2/btcr.rs`, `src/ghost/net/egress.rs`, `src/ghost/net/threat_shield.rs`, `src/ghost/net/security/attest.rs`, `docs/anti_abuse.md`.
- **Ehrliche Grenze:** Verlangt strenge Objektivität der Strike-Gründe und Multi-ASN-Quorum ($N_{\text{eff}} \ge 3$), damit ein einzelner bösartiger Exit das System nicht als Zensurwaffe gegen ehrliche Nutzer missbrauchen kann; ohne Re-Entry-Kosten (#46) könnte ein Angreifer nach dem Ban neue Identitäten farmen.
- **Machbarkeit:** **Ja** (Ristretto255-Gruppe bereits vorhanden) | **Verifikation:** ProVerif (Unlinkability ehrlicher Nutzer + erzwungener Ausschluss nach 3 Strikes).

---

# Master-Synthese: Synergien & Multiplikator-Kombinationen

Einzelne Flags sind stark — aber die echten Paradigmenwechsel entstehen, wenn **mehrere Ideen zusammenspielen**:
1. **Vollständige Zwang-Immunität:** `Vanta-Subliminal Tail` + `#8 exp_duress_honeygraph` + `#10 exp_canary_poison_key` + `#6 exp_witness_amnesia` + `#9 exp_volatile_ephemeral_execution` $\implies$ Der Beschlagnahmer sieht ein glaubwürdiges, genutztes System mit 0 Disk-Spuren, findet 0 Bit über echte Kontakte, und der Rest des Meshes schließt das Gerät still aus.
2. **Beherrschung beider Zeit-Pfeile:** `Chrono-Erosion` (Vergessen) + `#1 exp_deadman_cascade` (Totmannschalter) + `#4 exp_retroactive_amnesia_ratchet` (paket-genaue Chirurgie) + `#5 exp_chronological_firewall` (keine Epochen-Rückspulung).
3. **Wahrheit ohne Vertrauens-Kredit:** `WireWitness<P>` + `#29 exp_proof_carrying_config` + `#31 exp_adversarial_chaos_selftest` + `#32 exp_taint_tracked_secrets` + `#33 exp_epistemic_downgrade_circuit_breaker` + `#51 exp_epistemic_ui_friction` $\implies$ End-to-End Compile-Time, Runtime & Human-Factors Fail-Closed Epistemik.
4. **Selbstverteidigendes Ökosystem:** `#43 exp_harberger_relay_slotting` + `#46 exp_sybil_tax_pow_vdf_ladder` + `#26 exp_fungible_proof_of_relay` + `#48 exp_coalition_breaking_split_reward` $\implies$ Ökonomische & spieltheoretische Immunität gegen Monopole, Sybils und Komitee-Bestechung.
5. **Post-Infrastruktur-Überleben:** `ABOS-NVIS` + `#19 exp_balkanized_bridge_ferry` + `#34 exp_ionospheric_doppler_beacon` + `#38 exp_meteor_burst_ephemeral_sync` + `#54 exp_silent_mesh_bios_recovery` $\implies$ Ein Kommunikationssubstrat, das selbst ohne Internet, Mobilfunk, GPS und Desktop-OS weiterlebt.

---

# Master Sanity-Check Matrix (Alle 57 Kandidaten)

| # | Flag | Domäne | Machbarkeit | Aufwand | Empfehlung für 1. Welle | Status |
|---|---|---|---|---|---|---|
| 1 | `exp_deadman_cascade` | I — Zeit | **Ja** | Mittel | Hoch (duale Zeit-Architektur) | `[ ]` |
| 2 | `exp_ambient_entanglement` | I — Zeit | **Ja** | Niedrig | Hoch (nutzt `braid` direkt) | `[ ]` |
| 3 | `exp_causal_time_capsule` | I — Zeit | **Ja** | Mittel | Mittel | `[ ]` |
| 4 | `exp_retroactive_amnesia_ratchet` | I — Zeit | **Ja** | Niedrig | **Sehr hoch** (GGM-PPRF in BLAKE3) | `[ ]` |
| 5 | `exp_chronological_firewall` | I — Zeit | **Ja** | Niedrig | Hoch | `[ ]` |
| 6 | `exp_witness_amnesia` | II — Zwang | **Ja** | Niedrig | **Sehr hoch** (Ristretto255 DVS) | `[ ]` |
| 7 | `exp_blind_social_vault` | II — Zwang | **Ja** | Mittel | **Sehr hoch** (löst Backup-Problem) | `[ ]` |
| 8 | `exp_duress_honeygraph` | II — Zwang | **Ja** | Mittel | Hoch | `[ ]` |
| 9 | `exp_volatile_ephemeral_execution` | II — Zwang | **Ja** | Niedrig | **Sehr hoch** (`--amnesic` RAM-only) | `[ ]` |
| 10 | `exp_canary_poison_key` | II — Zwang | **Ja** | Niedrig | Hoch (stiller Fleet-Alarm) | `[ ]` |
| 11 | `exp_watermark_counterphase` | III — Traffic | **Ja** | Mittel | Mittel–Hoch | `[ ]` |
| 12 | `exp_relativistic_fog` | III — Traffic | **Ja** | Niedrig | **Sehr hoch** (saubere Metrik in `chronos`) | `[ ]` |
| 13 | `exp_biological_mimicry_racs` | III — Traffic | **Ja** | Mittel | Hoch (DPI-Tarnung) | `[ ]` |
| 14 | `exp_asymmetric_split_horizon` | III — Traffic | **Ja** | Mittel | Hoch (Up/Down über getrennte ISPs) | `[ ]` |
| 15 | `exp_stochastic_mtu_chameleon` | III — Traffic | **Vielleicht** | Hoch | Später (bricht fixes `576 B`-Framing) | `[ ]` |
| 16 | `exp_congestion_decoupling` | III — Traffic | **Ja** | Mittel | Hoch (stoppt CC-Seitenkanal) | `[ ]` |
| 17 | `exp_sheaf_hodge_autopilot` | IV — Topologie | **Vielleicht** | Mittel | Später (braucht `sheaf`-Kalibrierung) | `[ ]` |
| 18 | `exp_censorship_probe_labyrinth` | IV — Topologie | **Ja** | Niedrig | Hoch (härtet `front.rs`) | `[ ]` |
| 19 | `exp_balkanized_bridge_ferry` | IV — Topologie | **Vielleicht** | Hoch | Später (Mobile-OS BLE-Limits) | `[ ]` |
| 20 | `exp_adversarial_asn_antigravity` | IV — Topologie | **Ja** | Niedrig | Hoch (schärft $N_{\text{eff}}$) | `[ ]` |
| 21 | `exp_ephemeral_dark_rendezvous` | IV — Topologie | **Ja** | Niedrig | **Sehr hoch** (One-Shot-Slots) | `[ ]` |
| 22 | `exp_censor_induced_mutation` | IV — Topologie | **Ja** | Niedrig | Hoch (EXP3 Carrier-Bandit) | `[ ]` |
| 23 | `exp_zero_knowledge_reputation` | V — Krypto | **Ja** | Mittel | Mittel–Hoch | `[ ]` |
| 24 | `exp_oblivious_dns_pir` | V — Krypto | **Ja** | Niedrig | **Sehr hoch** (2-Server-XOR-PIR für `.vb`) | `[ ]` |
| 25 | `exp_threshold_exit_signing` | V — Krypto | **Vielleicht** | Hoch | Später (FROST 2-Runden-Komplexität) | `[ ]` |
| 26 | `exp_fungible_proof_of_relay` | V — Krypto | **Ja** | Mittel | Hoch (stoppt Black-Hole-Relays) | `[ ]` |
| 27 | `exp_post_quantum_group_mls` | V — Krypto | **Ja** | Hoch | Hoch (für `fleet`/`party` Gruppen) | `[ ]` |
| 28 | `exp_homomorphic_telemetry_sketch` | V — Krypto | **Vielleicht** | Hoch | Später (Dropout-Recovery) | `[ ]` |
| 29 | `exp_proof_carrying_config` | VI — Epistemik | **Ja** | Niedrig | **Sehr hoch** (sofortiger Praxiswert) | `[ ]` |
| 30 | `exp_differential_build_attestation` | VI — Epistemik | **Ja / Schwer** | Mittel | Mittel (erst voll stark mit TPM) | `[ ]` |
| 31 | `exp_adversarial_chaos_selftest` | VI — Epistemik | **Ja** | Niedrig | **Sehr hoch** (Live-Red-Team-Witness) | `[ ]` |
| 32 | `exp_taint_tracked_secrets` | VI — Epistemik | **Ja** | Niedrig | **Sehr hoch** (Zero-Cost Compile-Guard) | `[ ]` |
| 33 | `exp_epistemic_downgrade_circuit_breaker` | VI — Epistemik | **Ja** | Niedrig | **Sehr hoch** (Fail-Closed Kill-Switch) | `[ ]` |
| 34 | `exp_ionospheric_doppler_beacon` | VII — Physik | **Schwer** | Hoch | Später (SDR-Hardware) | `[ ]` |
| 35 | `exp_acoustic_ultrasonic_pairing` | VII — Physik | **Ja** | Mittel | Hoch (löst TOFU physisch) | `[ ]` |
| 36 | `exp_solar_battery_adaptive_crypto` | VII — Physik | **Ja** | Niedrig | Mittel–Hoch | `[ ]` |
| 37 | `exp_opportunistic_multipath_acoustic_rf` | VII — Physik | **Vielleicht** | Hoch | Später (braucht ABOS-Hardware) | `[ ]` |
| 38 | `exp_meteor_burst_ephemeral_sync` | VII — Physik | **Schwer** | Hoch | Später (VHF-SDR-Hardware) | `[ ]` |
| 39 | `exp_verifiable_blind_micro_agents` | VIII — Compute | **Ja** | Mittel | Hoch (bester Case für `LC-Vantablack`) | `[ ]` |
| 40 | `exp_oblivious_psi_contact_discovery` | VIII — Compute | **Ja** | Niedrig | **Sehr hoch** (privates Onboarding) | `[ ]` |
| 41 | `exp_self_healing_erasure_swarm` | VIII — Compute | **Ja** | Mittel | Mittel–Hoch (für `mesh_archive`) | `[ ]` |
| 42 | `exp_epistemic_consensus_lite` | VIII — Compute | **Ja** | Mittel | Mittel–Hoch | `[ ]` |
| 43 | `exp_harberger_relay_slotting` | IX — Spieltheorie | **Ja** | Niedrig | Hoch ($N_{\text{eff}}$-Anreiz) | `[ ]` |
| 44 | `exp_mutually_assured_reputation_stake` | IX — Spieltheorie | **Vielleicht** | Mittel | Mittel | `[ ]` |
| 45 | `exp_altruistic_cover_barter` | IX — Spieltheorie | **Ja** | Niedrig | Hoch (Handy-Entlastung) | `[ ]` |
| 46 | `exp_sybil_tax_pow_vdf_ladder` | IX — Spieltheorie | **Ja** | Niedrig | **Sehr hoch** (härtet `pow.rs`) | `[ ]` |
| 47 | `exp_incentivized_censorship_bounty` | IX — Spieltheorie | **Vielleicht** | Mittel | Mittel | `[ ]` |
| 48 | `exp_coalition_breaking_split_reward` | IX — Spieltheorie | **Vielleicht** | Mittel | Mittel–Hoch (Komitee-Schutz) | `[ ]` |
| 49 | `exp_elastic_exit_marketplace` | IX — Spieltheorie | **Ja** | Niedrig | Mittel | `[ ]` |
| 50 | `exp_semantic_noise_injection` | X — Semantik/OS | **Vielleicht** | Mittel | Später (schwere Kalibrierung) | `[ ]` |
| 51 | `exp_epistemic_ui_friction` | X — Semantik/OS | **Ja** | Niedrig | **Sehr hoch** (gegen Alert Fatigue) | `[ ]` |
| 52 | `exp_plausible_identity_mitosis` | X — Semantik/OS | **Ja** | Niedrig | **Sehr hoch** (Multi-Persona) | `[ ]` |
| 53 | `exp_hardware_rng_entropy_mixer` | X — Semantik/OS | **Ja** | Niedrig | **Sehr hoch** (gegen CPU-Backdoors) | `[ ]` |
| 54 | `exp_silent_mesh_bios_recovery` | X — Semantik/OS | **Vielleicht** | Hoch | Später (`no_std`-Core) | `[ ]` |
| 55 | `exp_counterfactual_audit_replay` | X — Semantik/OS | **Ja** | Mittel | Hoch (persönlicher Angriffs-Sim) | `[ ]` |
| 56 | `exp_cognitive_sidechannel_keystroke_pad` | X — Semantik/OS | **Ja** | Niedrig | **Sehr hoch** (SSH-Timing-Fix) | `[ ]` |
| 57 | `exp_anonymous_abuse_strikes` | IX — Anti-Abuse | **Ja** | Mittel | **Sehr hoch** (`BLAC` Multi-ASN-Sperre) | `[ ]` |
