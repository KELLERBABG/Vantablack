//! GHOST Protocol Layers
//!
//! Each layer in the stack provides an independent cryptographic or resilience property:
//! - L0  Ed25519 + ML-DSA-65 Identity — Quantum-resistant device identity & signing
//! - L1  Hybrid KEM                   — X25519 + ML-KEM-512/768 key exchange with PSK mixing
//! - L2  AEAD                         — ChaCha20-Poly1305 / XChaCha20 encryption & authentication
//! - L3  Shamir SSS                   — Threshold secret sharing over GF(256)
//! - L4  Reed-Solomon                 — (2,1) erasure coding for packet-loss recovery
//! - L5  Noise Injection              — Jitter padding against traffic analysis
//! - L6  Session Guard                — Monotonic counters & sliding-window replay protection
//! - L7  LDPC FEC                     — Low-density parity-check forward error correction
//! - L8  Memory Security              — AES-XTS RAM encryption & bounded IPC ring buffers
//! - L9  Infrastructure               — TPM 2.0 enclave & secure deployment primitives
//! - L10 Quantum Anchor               — QEL bridge & ETSI GS QKD 014 appliance ratchet entropy

pub mod l0_identity;

pub mod l10_qel;
pub mod l10_qel_etsi;
pub mod l1_kem;
pub mod l2_aead;
pub mod l3_shamir;
pub mod l4_rs;
pub mod l5_noise;
pub mod l6_session;
pub mod l7_ldpc;
pub mod l8_memsec;
pub mod l9_infra;
