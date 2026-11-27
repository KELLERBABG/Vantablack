# Vantablack v3.8.1 — Metabolic Authority Decay (Tier-2 Sybil-Bounded Half-Life)

Vantablack **v3.8.1** wires `ghost::net::metabolic` (`MetabolicClock`) into `src/daemon/research_hooks.rs::metabolic_guard`, binding authority pulses to transport-verified `/16` (IPv4) and `/32` (IPv6) routing-cluster domains so same-prefix Sybils collapse to one unit and authority decays smoothly on silence (`20` daemon hook tests passing).

For full release notes and version-by-version changes, see the [**Detailed Update Logs**](https://vantablack.kellersystems.dev/docs#changelog).
