# Tactical Transports: Atmospheric Skywave (HF/SDR)
## Autonomous Out-of-Band Physical Fallback Carrier & DTN Reconciliation

> **Maturity Status:** *Experimental / Physical Layer Specification & In-Memory DSP Engine*  
> **Feature Flag:** `--features sdr`  
> **External Subsystem:** [`KELLERBABG/ABOS`](https://github.com/KELLERBABG/ABOS)

---

## 1. Architectural Motivation

Vantablack is designed from first principles to survive hostile environments—ranging from targeted ISP DNS poisoning and Deep Packet Inspection (DPI) to coordinated terrestrial fiber cuts and complete national internet shutdowns.

Under catastrophic circumstances where standard IP routing, cellular data towers (5G/LTE), and satellite downlinks are disabled or electronically jammed, all conventional VPN and mesh protocols collapse. 

To guarantee unjammable survival, Vantablack implements an out-of-band **Physical Skywave Fallback Carrier** powered by **Atmospheric Broadcast OS (ABOS)**.

```
┌────────────────────────────────────────────────────────┐
│               THE REACHABILITY LADDER                  │
│                                                        │
│  [Priority 0] Direct P2P (UDP Hole Punching / ICE)     │
│       │                                                │
│       ▼ (NAT failure / direct port blocked)            │
│  [Priority 1] Mesh Multi-Hop Relay (RLY! Onion Router) │
│       │                                                │
│       ▼ (Local ISP throttling / egress censorship)     │
│  [Priority 2] Blinded TURN Relay Pool                  │
│       │                                                │
│       ▼ (Total WAN / Terrestrial Internet Blackout)    │
│  [Priority 3] Atmospheric Skywave (NVIS HF Radio)      │
└────────────────────────────────────────────────────────┘
```

---

## 2. Atmospheric Propagation Physics

The Skywave fallback operates on High Frequency (HF) bands between **2 MHz and 10 MHz** utilizing **Near Vertical Incidence Skywave (NVIS)**:

```
                  +--------------------------------+
                  |  Ionosphere (F2 Layer Plasma)  |
                  +--------------------------------+
                             ^          \
      Transmitted RF        /            \   Reflected RF
      Burst (2-10 MHz)     /              \  Burst (0-500 km radius)
                          /                v
                  +-------------+    +-------------+
                  | Vantablack  |    | Vantablack  |
                  | Node A (TX) |    | Node B (RX) |
                  +-------------+    +-------------+
                  ///////////////////////////////////
                     Mountains, Valleys, Jammed WAN
```

### Key Physical Guarantees:
1. **Zero Intermediate Servers:** Radiation reflects directly off ionized atmospheric plasma layers (D, E, F1, F2). Because the atmosphere itself serves as the passive reflector, `is_relayed()` evaluates to `false`. There are no cloud intermediaries, proxy servers, or telecom operators in the signal path.
2. **Terrain Immunity:** Standard VHF/UHF tactical radios require direct line-of-sight. NVIS signals radiate almost vertically (70°–90°), bouncing back downwards into valleys, urban centers, and across mountainous terrain within a 0–500 km radius without line-of-sight dead zones.
3. **Low Probability of Intercept / Detection (LPI/LPD):** Packets are spread across frequencies using Direct Sequence Spread Spectrum (DSSS) and pseudo-random frequency hopping (FHSS), submerging the signal beneath the atmospheric thermal noise floor (SNR < 0 dB).

---

## 3. Software Architecture & Cross-Layer Bridge

To maintain zero overhead and high performance for standard WAN deployments, the Skywave carrier is completely decoupled into an opt-in cargo feature:

```toml
# Cargo.toml
[dependencies]
abos = { git = "https://github.com/KELLERBABG/ABOS.git", optional = true }

[features]
sdr = ["dep:abos"]
```

### The SDR Bridge Adapter (`src/ghost/net/sdr_bridge.rs`)
The bridge translates high-level Vantablack datagrams into raw baseband RF bursts:

1. **Ingress Serialization:** Outbound 576-byte Ghost Transport Frames (GTF) are extracted from the packet ring buffer.
2. **FEC Encoding:** Frames pass through Low-Density Parity-Check (LDPC) coding and matrix interleaving to tolerate burst atmospheric static and lightning noise.
3. **Modulation:** Complex I/Q baseband samples are synthesized via Orthogonal Frequency Division Multiplexing (OFDM) or Direct Sequence Spread Spectrum (DSSS).
4. **RF Dispatch:** Modulated bursts are pushed to the hardware transceiver queue.

---

## 4. Delay-Tolerant Networking (DTN) & Phoenix Windows

High-frequency radio channels are inherently intermittent. Ionospheric density shifts diurnal cycles, geomagnetic storms produce absorption blackouts, and solar flares degrade high frequencies.

Vantablack bridges this physical reality using **Delay-Tolerant Networking (DTN)**:

* **Bundle Serialization:** During complete disconnection, outgoing states (Merkle tree heads, cryptographic capability vouchers, and peer heartbeat vectors) are buffered into durable `DtnBundle` structures on disk.
* **Phoenix Windows:** When an ionospheric opening or transient meteor trail (meteor scatter ionization) is detected, the carrier opens an opportunistic "Phoenix Window", flushing prioritized DTN bundles in micro-burst transmissions before the ionospheric channel closes.

---

## 5. Telemetry & Observability

When compiled with `--features sdr`, operators can inspect live skywave status through both the CLI and local REST API:

### CLI Command
```bash
ggn sdr-status
```
**Output:**
```text
=== Vantablack SDR / Skywave Fallback Status ===
Carrier Active:      true
Frequency:           5.332 MHz (Channel 3 NVIS)
Target foF2:         6.1 MHz
Estimated MUF:       7.2 MHz
Tx Power:            20 W (Simulated / PA)
Modulation:          DSSS-QPSK / LDPC Rate 1/2
DTN Queue Depth:     0 bundles
```

### Control API (`GET /api/status`)
```json
{
  "skywave": {
    "enabled": true,
    "carrier_active": true,
    "frequency_hz": 5332000,
    "band": "HF-NVIS",
    "propagation_mode": "F2-Ionospheric-Reflection"
  }
}
```

---

## 6. Implementation Status & Roadmap

To maintain engineering transparency, the ABOS physical integration is structured in two distinct phases:

| Component | Status | Implementation Details |
| :--- | :--- | :--- |
| **Vantablack Bridge** | **Production** | `FallbackPath::Skywave`, DTN bundle serialization, CLI & API hooks |
| **DSP & PHY Math** | **Complete** | Pure-Rust OFDM modulation, LDPC forward error correction, Costas loop, Gardner timing, DSSS |
| **Protocol Framing** | **Complete** | Burst headers, Reed-Solomon/LDPC sharding, CRC32, timestamp sync |
| **SDR Hardware HAL** | *Prototyping* | In-memory RAM buffer streaming; native C/FFI bindings to SoapySDR/UHD planned for Phase 2 |

Developers interested in contributing to the DSP algorithms, radio frequency hardware drivers, or ionospheric sounding models can review the standalone repository at:  
[**https://github.com/KELLERBABG/ABOS**](https://github.com/KELLERBABG/ABOS)
