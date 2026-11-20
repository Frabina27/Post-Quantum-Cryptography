# Hybrid Classical + PQC System Module

## Project Overview

For my role in our Data and Applications Security team project, I designed and implemented the **Hybrid Classical + Post-Quantum Cryptography (PQC) System**.

The primary objective of this module is to solve the real-world **transition problem** of migrating an organization's Public Key Infrastructure (PKI) and cryptographic communications from classical algorithms (RSA, ECC) to post-quantum algorithms (ML-KEM, ML-DSA).

### The Migration Problem & Why Hybrid Cryptography is Required
1. **"Harvest Now, Decrypt Later" (HNDL) Threat:** Adversaries and hostile actors can passively capture and store encrypted classical communications today, with the goal of retroactively decrypting them once a cryptanalytically relevant quantum computer (CRQC) becomes available. Organizations cannot wait to adopt post-quantum algorithms until quantum computers arrive.
2. **Mathematical Maturity Risk:** Post-quantum algorithms like ML-KEM (Kyber) and ML-DSA (Dilithium) are lattice-based primitives standardized under NIST FIPS 203 and FIPS 204. While rigorously analyzed, they do not possess the decades of production history that classical algorithms (RSA and ECC) have. If an unexpected algorithmic weakness is discovered in lattice cryptography, a pure post-quantum system would be compromised.
3. **The Solution (The Dual-Protection Guarantee):** 
   A hybrid scheme combines a classical algorithm with a post-quantum algorithm in a cryptographically bound construction. Based on the **Dual-PRF Combiner Theorem**, an attacker must simultaneously break **BOTH** the classical discrete-log/elliptic-curve problem and the post-quantum lattice problem to compromise confidentiality or forge a digital signature.

---

## Files and Directory Structure

```text
hybrid-module/
├── hybrid_kem.py        # Classical + PQ Key Encapsulation (X25519/P-256 + ML-KEM-768) + AES-256-GCM
├── hybrid_sig.py        # Composite Signatures (ECDSA/RSA + ML-DSA-65) with strict dual-verification
├── hybrid_pki.py        # PKI Transition Simulator (Dual-identity certs, CA issuance & policy validation)
├── test_hybrid.py       # Comprehensive unit tests & security tampering tests (15 test cases)
├── test_hybrid_kem_hardening.py  # KEM v2 hardening: KDF binding, strict parsing, bounds, AAD (29 cases)
├── benchmark_hybrid.py  # Performance measurement harness comparing Classical vs PQ vs Hybrid
├── requirements.txt     # Python dependency specifications (cryptography>=50.0.0)
├── hybrid-readme.md     # Module documentation, security proofs, and integration guide
└── results/
    └── hybrid_benchmark.csv  # Machine-readable benchmark numbers for team analysis
```

---

## What Was Implemented

### 1. Hybrid Key Encapsulation Mechanism (`hybrid_kem.py`)
- **Supported Profiles:**
  - `PROFILE_X25519_MLKEM768`: Same construction shape as IETF `draft-ietf-tls-ecdhe-mlkem` (X25519MLKEM768) and X-Wing. The wire format is this project's own, not TLS-compatible.
  - `PROFILE_P256_MLKEM768`: ECDH NIST P-256 + ML-KEM-768, with an SP 800-56C style KDF.
- **Cryptographic Combiner (v2):**
  - Ephemeral public keys and encapsulated ciphertexts are transmitted together.
  - The sender derives $SS_{\text{classical}} = \text{ECDH}(sk_{\text{eph}}, pk_{\text{peer}})$ and encapsulates $SS_{\text{pq}}, c_{\text{kem}} = \text{ML-KEM.Encaps}(pk_{\text{kem}})$.
  - HKDF-SHA256 uses the secrets as input keying material and binds the full transcript in `info` (each field is length-prefixed):
    $$K_{\text{session}} = \text{HKDF}\big(SS_{\text{pq}} \parallel SS_{\text{classical}},\ \text{info}=\text{"hybrid-kem-v2"} \parallel \text{id} \parallel c_{\text{kem}} \parallel pk_{\text{eph}} \parallel pk_{\text{kem}} \parallel pk_{\text{classical}}\big)$$
  - **Why bind the transcript:** ECDH on its own is not an IND-CCA KEM. Feeding the ephemeral key and the recipient's static key into the KDF, as X-Wing does, is what keeps the combined key secure when only the classical half holds. v1 hashed only the two secrets.
  - v2 ciphertexts use the magic `HKCT2`, so a v1 ciphertext fails to parse instead of silently deriving a different key.
- **Strict parsing:** unknown profile identifiers, wrong component sizes (32/65 B classical, 1184 B ML-KEM key, 1088 B ML-KEM ciphertext), trailing bytes, truncated envelopes and non-12-byte nonces are all rejected. Invalid classical points (X25519 low-order, P-256 off-curve) cause `DecapsulationError`.
- **Authenticated Data Encryption (AEAD):**
  - Uses $K_{\text{session}}$ with **AES-256-GCM** with a cryptographically secure 96-bit random nonce to encrypt and integrity-protect application payloads.
  - The serialized KEM ciphertext is authenticated as part of the GCM associated data, together with the caller's `associated_data`.

### 2. Composite Digital Signatures (`hybrid_sig.py`)
- **Supported Profiles:**
  - `PROFILE_ECDSA_MLDSA65`: Combines ECDSA (SECP256R1 + SHA-256) with ML-DSA-65 (FIPS 204).
  - `PROFILE_RSA_MLDSA65`: Combines RSA-2048 (PSS padding + SHA-256) with ML-DSA-65.
- **Strict Dual-Verification Semantic:**
  - A signature $\Sigma = (\sigma_{\text{classical}}, \sigma_{\text{pq}})$ is valid if and only if:
    $$\text{Verify}_{\text{composite}}(M, \Sigma) = \text{Verify}_{\text{classical}}(M, \sigma_{\text{classical}}) \land \text{Verify}_{\text{pq}}(M, \sigma_{\text{pq}})$$
  - Any single failure (e.g. classical forged or PQ corrupted) causes immediate rejection.
  - Includes a diagnostic `verify_detailed()` function exposing constituent status for automated security analysis.

### 3. Enterprise PKI Migration Simulator (`hybrid_pki.py`)
- Simulates an enterprise Certificate Authority (CA) transitioning to post-quantum:
  - Generates composite root CA keys (`ECDSA + ML-DSA-65`).
  - Issues hybrid identity certificates containing both classical and post-quantum subject public keys, signed by the CA's dual private key.
  - Provides a policy engine with 3 migration stages:
    1. `LEGACY_PERMISSIVE`: Allows backward compatibility with legacy clients (verifies classical signature).
    2. `HYBRID_STRICT`: Target migration phase (strictly enforces dual-verification of classical and PQ signatures).
    3. `PQ_STRICT`: Post-migration phase (enforces pure post-quantum verification).

### 4. Security & Negative Attack Testing (`test_hybrid.py`)
- Implements 15 automated test cases, including specific tampering scenarios for Teammate 9:
  - Tampered message detection.
  - 1-bit corruption in classical signature component $\rightarrow$ rejection.
  - 1-bit corruption in post-quantum signature component $\rightarrow$ rejection.
  - 1-bit corruption in ML-KEM ciphertext $\rightarrow$ decapsulation failure.
  - 1-byte corruption in AES-GCM ciphertext $\rightarrow$ AEAD authentication failure (`DecryptionError`).
  - Forged identity / altered subject DN in hybrid certificate $\rightarrow$ CA verification rejection.
  - Unauthorized public key substitution $\rightarrow$ rejection.

---

## Performance Benchmark Results

Measured on Linux x86_64 (Python 3.14, cryptography 50.0.2) across 200 iterations per operation, with the v2 KEM combiner:

| Cryptographic Scheme | Security Level / Type | Public Key | Private Key | Ciphertext / Sig | KeyGen | Primary Op (Encap / Sign) | Secondary Op (Decap / Verify) |
|---|---|---:|---:|---:|---:|---:|---:|
| **Classical X25519** | Classical (128-bit) | 32 B | 48 B | 32 B | 0.030 ms | 0.057 ms | 0.027 ms |
| **PQ ML-KEM-768** | Post-Quantum (Cat 3) | 1,184 B | 86 B | 1,088 B | 0.099 ms | 0.024 ms | 0.035 ms |
| **Hybrid X25519 + ML-KEM** | Hybrid (Dual-Protected) | 1,227 B | 134 B | 1,130 B | 0.165 ms | 0.127 ms | 0.095 ms |
| **Classical ECDSA P-256** | Classical (128-bit) | 91 B | 138 B | 71 B | 0.015 ms | 0.024 ms | 0.059 ms |
| **PQ ML-DSA-65** | Post-Quantum (Cat 3) | 1,952 B | 54 B | 3,309 B | 0.192 ms | 0.897 ms | 0.187 ms |
| **Hybrid ECDSA + ML-DSA** | Hybrid (Dual-Protected) | 2,054 B | 192 B | 3,392 B | 0.230 ms | 1.055 ms | 0.269 ms |

### Key Observations & Trade-off Analysis:
1. **Computational Latency:**
   - Post-quantum ML-KEM-768 encapsulation is very fast (0.024 ms), more than twice as fast as a classical X25519 ephemeral exchange (0.057 ms).
   - A hybrid KEM transaction costs ~0.13 ms to encapsulate and ~0.10 ms to decapsulate. That covers the ephemeral ECDH, ML-KEM, and the v2 HKDF combiner, which also hashes the ~2.3 KB transcript of ciphertexts and public keys. The combiner and serialization add roughly 0.03–0.05 ms on top of the two primitives.
   - For signatures, ML-DSA-65 signing takes ~0.90 ms and dominates hybrid signing time; ECDSA adds very little (~0.02 ms).
2. **Bandwidth / Storage Overhead:**
   - The primary trade-off in post-quantum and hybrid cryptography is **data size**, not computational speed.
   - Classical X25519 requires only 32 bytes for public keys and ciphertexts; Hybrid X25519 + ML-KEM-768 requires 1,227 bytes for public keys and 1,130 bytes for ciphertexts (~35x larger).
   - Classical ECDSA signatures are only ~71 bytes; Hybrid signatures require ~3,390 bytes (~48x larger; the ECDSA DER part varies by a few bytes per signature).
   - This demonstrates the crucial architectural finding for our group project: **enterprise networks migrating to PQC must account for larger packet sizes and MTU fragmentation rather than CPU bottlenecks.**

---

## Interfacing with Teammates

| Teammate / Sub-Task | Integration Points |
|---|---|
| **#1 RSA Module** | `hybrid_sig.py` supports `PROFILE_RSA_MLDSA65`, which integrates directly with RSA-2048 PSS keys. |
| **#2 ECC Module** | `hybrid_kem.py` uses SECP256R1/X25519 ECDH; `hybrid_sig.py` uses SECP256R1 ECDSA. |
| **#3 ML-KEM (Kyber)** | Fully conforms to FIPS 203 ML-KEM-768 parameter sets (1184B public key, 1088B ciphertext) matching Teammate 3's specifications. |
| **#4 ML-DSA (Dilithium)** | Conforms to FIPS 204 ML-DSA-65 (1952B public key, 3309B signature) matching Teammate 4's algorithm. |
| **#5 & #6 Classical & PQ PKI** | `hybrid_pki.py` demonstrates how a CA bridges classical X.509 chains with post-quantum identities across 3 migration policies. |
| **#8 Performance Benchmarking** | `benchmark_hybrid.py` exports timing and byte metrics to `results/hybrid_benchmark.csv`. |
| **#9 Security & Attack Testing** | `test_hybrid.py` and `verify_detailed()` provide programmatic hooks to inject tampered bits and verify rejection. |

---

## Running the Code

### 1. Install Requirements
From the repository root, create a virtual environment (`.venv/` is gitignored) and install the project-wide requirements:
```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt "pytest>=8" cmake
```
`cmake` is only needed by `security-testing-module`: on first import, `liboqs-python` builds the liboqs C library into `~/_oqs` (this needs a C compiler and git). The hybrid module itself only needs `cryptography>=50`.

### 2. Run the Unit & Security Tests
```bash
.venv/bin/python -m pytest hybrid-module -v
```

### 3. Run Performance Benchmarks
```bash
python hybrid-module/benchmark_hybrid.py
```
