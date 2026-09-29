# CHANGELOG — Quantum Entanglement Link

## 2026-08-06
- What: Phase 3 — Ghost-Net topology layer + Ghost-Net integration.
- Why: complete the DEVELOPMENT_PLAN Phase 3 (topology optimizer, fidelity pathfinding, swap scheduling, visualization) and build QEL into the Global Ghost Net system.
- Added: `topology/` package (graph, routing, schedule, visualize, ghostnet); CLI `topology build|route`, `ghost-net`; Werner swap formula `F' = F1F2+(1-F1)(1-F2)/3` (order-independent noise; order matters only via memory decay); time-aware schedules with per-segment T1/T2 decay; ASCII/matplotlib rendering; bridge reads the Rust daemon's live `EXPORTTOPOLOGY` JSON.
- Fixed: Windows cp1252 crash from unicode arrows (ASCII-safe output); corrected swap-fidelity derivation.
- Tests: 112 green (81 prior + 31 new topology/bridge).
- Next: distillation-aware routing (choose paths where BBPSSW can lift fidelity); animated visualization.
