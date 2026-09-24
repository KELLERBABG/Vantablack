# Formal protocol models

This directory contains a small, executable ProVerif model of the security
claims that are independent of the operating system and hardware gates.

## Run

```bash
proverif formal/ghost_session.pv
proverif formal/shardsec_space_time.pv
```

The repository CI runs ProVerif in the `formal-model` job on Ubuntu. A
successful model run is a symbolic protocol result verifying:
1. `ghost_session.pv`: Authenticated hybrid ML-KEM/X25519 handshake secrecy, forward secrecy, and injective anti-replay sequence verification (`inj-event(recv_counter(...)) ==> inj-event(sent_counter(...))`).
2. `shardsec_space_time.pv`: 3-shard × 3-epoch space-time ladder proving mathematical zero information leakage against an adversary capturing 1 of 3 shards / epoch keys.

The model is intentionally an abstraction: it models cryptographic secrecy, authenticated ratchet transitions, and anti-replay invariants. It does not replace Rust tests, implementation review, or traffic-analysis experiments.
