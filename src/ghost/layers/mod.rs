/// GHOST Protocol Layers
///
/// Each layer in the stack provides a specific security property.
/// Layers are independent and composable - an attacker must defeat
/// all layers simultaneously to compromise a session.
///
/// L0  Ed25519 Identity     — Permanent device identity & signing
/// L1  Hybrid KEM           — X25519 + Kyber-512 key exchange + optional PSK mixing
/// L2  AEAD                 — ChaCha20-Poly1305 encryption + MAC
/// L3  Shamir SSS           — Secret sharing over GF(256)
/// L4  Reed-Solomon         — (2,1) erasure coding for loss resilience
/// L5  Noise Injection      — Jitter padding vs traffic analysis
/// L6  Session Guard        — Replay protection + timeouts (128-bit sliding window)
/// L7  LDPC FEC             — Low-density parity-check forward error correction
/// L8  Memory Security      — AES-XTS RAM encryption, verified IPC buffers, XDP dispatch
/// L9  Infrastructure       — Portable packaging, TPM/HSM enclave, NTS time sync
pub mod l0_identity;
pub mod l1_kem;
pub mod l2_aead;
pub mod l3_shamir;
pub mod l4_rs;
pub mod l5_noise;
pub mod l6_session;
pub mod l7_ldpc;
pub mod l8_memsec;
pub mod l9_infra;
