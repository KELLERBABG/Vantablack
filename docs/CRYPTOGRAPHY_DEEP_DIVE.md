# Cryptographic Deep Dive: Post-Quantum Hybrid Defense

This document details the mathematical and algorithmic foundations of the cryptographic suite powering Global Ghost Net.

---

## 1. Threat Model & Post-Quantum Transition

Classical public-key cryptography (RSA, ECDH, Diffie-Hellman) relies on mathematical problems such as prime factorization and discrete logarithms. These problems can be solved in polynomial time by Shor’s algorithm running on a cryptographically relevant quantum computer (CRQC).

Mass-surveillance adversaries frequently engage in **"Store Now, Decrypt Later"** attacks: capturing and archiving encrypted network traffic today with the objective of decrypting it once quantum computing hardware matures.

To neutralize this threat, Global Ghost Net employs a **hybrid post-quantum cryptographic architecture**:
1. **Classical Hard Problem:** Elliptic curve discrete logarithm over Curve25519 (128-bit classical security).
2. **Post-Quantum Hard Problem:** Module Learning with Errors (MLWE) over polynomial rings via ML-KEM-512 (Kyber-512 / FIPS 203).

---

## 2. Ephemeral Hybrid Key Encapsulation (L1)

Every peer session negotiates an ephemeral symmetric key using a dual-primitive key exchange:

### Step 1: Ephemeral Key Generation
Both the initiator (Node A) and responder (Node B) generate fresh, ephemeral key pairs per session:
- **Node A:** Generates an ephemeral X25519 scalar key pair.
- **Node B:** Generates an ephemeral ML-KEM-512 key pair (encapsulation key `ek`, decapsulation key `dk`) and an ephemeral X25519 key pair.

### Step 2: Encapsulation & Exchange
1. Node A encapsulates a 32-byte post-quantum shared secret against Node B's encapsulation key:
   ```text
   (ciphertext_kem, shared_secret_kem) = ML-KEM-512_Encapsulate(ek_B)
   ```
2. Node A computes the classical Diffie-Hellman shared secret:
   ```text
   shared_secret_ecdh = X25519(sk_A, pk_B)
   ```

### Step 3: Key Derivation Function (HKDF-SHA256)
The master session key is derived by concatenating both shared secrets and feeding them into an HKDF extract-and-expand pipeline:

```text
PRK = HKDF-Extract(Salt: SessionSalt XOR PSK, shared_secret_ecdh || shared_secret_kem)
MasterKey = HKDF-Expand(PRK, Info: "vantablack-v1-hybrid-master", Length: 32 bytes)
```

**Security Guarantee:** If a quantum computer solves X25519, the master key remains secret due to the lattice-based ML-KEM-512 secret. Conversely, if an unforeseen algebraic shortcut weakens lattice cryptography, the proven security of X25519 protects the tunnel.

---

## 3. Authenticated Data Transport (L2)

Payload frames are authenticated and encrypted using **ChaCha20-Poly1305** (RFC 8439):
- **Symmetric Cipher:** 256-bit key from the hybrid derivation.
- **Directional Nonce Generation:**
  Nonce reuse in ChaCha20-Poly1305 catastrophically destroys authenticity. To make nonce collision impossible:
  ```text
  Nonce = [4-byte SessionHash] + [1-byte Direction] + [8-byte MonotonicCounter]
  ```
  - `Direction`: `0x00` for initiator-to-responder, `0x01` for responder-to-initiator.
  - `MonotonicCounter`: Atomic 64-bit integer advancing per packet across the session.

---

## 4. In-Memory Security & Zeroization (L8)

- **Volatile Zeroization on Drop:** Sensitive cryptographic keys implement `Zeroize` and `ZeroizeOnDrop`. When a session terminates or a key is rotated, the operating system memory addresses are wiped with zero bytes through compiler-barrier memory fences.
- **AES-256-XTS In-Memory Protection:** High-security session rings use AES-XTS memory encryption to protect transit frames while buffered in system RAM against unauthorized DMA reads or host memory dump exploits.
