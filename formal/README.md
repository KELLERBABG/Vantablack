# Formal protocol models

This directory contains a small, executable ProVerif model of the security
claims that are independent of the operating system and hardware gates.

## Run

```bash
proverif formal/ghost_session.pv
```

The repository CI runs this command in the `formal-model` job on Ubuntu. A
successful model run is a symbolic protocol result only; it does not replace
Rust tests, implementation review, hardware evidence, or traffic-analysis
experiments.

The model is intentionally an abstraction: it models the hybrid authenticated
handshake, session-key secrecy, and authenticated ratchet transition. It does
not claim to model Rust memory safety, ML-KEM's concrete implementation, QUIC,
NAT traversal, timing anonymity, or TPM/PKCS#11 behavior. Those require separate
models or host/device evidence.
