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
  - `PROFILE_X25519_MLKEM768`: Modeled after IETF `draft-ietf-tls-hybrid-design` (used in modern TLS 1.3 / Chrome / Cloudflare).
  - `PROFILE_P256_MLKEM768`: Modeled after NIST SP 800-56C Rev 2 (ECDH NIST P-256 + ML-KEM-768).
- **Cryptographic Combiner:**
  - Ephemeral public keys and encapsulated ciphertexts are transmitted together.
  - The sender derives $SS_{\text{classical}} = \text{ECDH}(sk_{\text{eph}}, pk_{\text{peer}})$ and encapsulates $SS_{\text{pq}}, c_{\text{kem}} = \text{ML-KEM.Encaps}(pk_{\text{kem}})$.
  - A secure Key Derivation Function (HKDF-SHA256) extracts and expands the concatenated secrets:
    $$K_{\text{session}} = \text{HKDF-Extract-and-Expand}(SS_{\text{classical}} \parallel SS_{\text{pq}}, \text{info}=\text{"hybrid-kem-v1"})$$
- **Authenticated Data Encryption (AEAD):**
  - Uses $K_{\text{session}}$ with **AES-256-GCM** with a cryptographically secure 96-bit random nonce to encrypt and integrity-protect application payloads.

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

Measured on Windows x86_64 across 200 iterations per operation:

| Cryptographic Scheme | Security Level / Type | Public Key | Private Key | Ciphertext / Sig | KeyGen | Primary Op (Encap / Sign) | Secondary Op (Decap / Verify) |
|---|---|---:|---:|---:|---:|---:|---:|
| **Classical X25519** | Classical (128-bit) | 32 B | 48 B | 32 B | 0.039 ms | 0.070 ms | 0.031 ms |
| **PQ ML-KEM-768** | Post-Quantum (Cat 3) | 1,184 B | 86 B | 1,088 B | 0.185 ms | 0.052 ms | 0.075 ms |
| **Hybrid X25519 + ML-KEM** | Hybrid (Dual-Protected) | 1,227 B | 134 B | 1,130 B | 0.255 ms | 0.160 ms | 0.117 ms |
| **Classical ECDSA P-256** | Classical (128-bit) | 91 B | 138 B | 71 B | 0.022 ms | 0.031 ms | 0.068 ms |
| **PQ ML-DSA-65** | Post-Quantum (Cat 3) | 1,952 B | 54 B | 3,309 B | 0.233 ms | 1.322 ms | 0.249 ms |
| **Hybrid ECDSA + ML-DSA** | Hybrid (Dual-Protected) | 2,054 B | 192 B | 3,390 B | 0.287 ms | 1.306 ms | 0.368 ms |

### Key Observations & Trade-off Analysis:
1. **Computational Latency:**
   - Post-quantum ML-KEM-768 encapsulation is exceptionally fast (0.052 ms), slightly outperforming classical ECDH generation (0.070 ms).
   - The Hybrid KEM overhead is only ~0.16 ms per transaction, which includes ephemeral classical ECDH derivation, ML-KEM encapsulation, HKDF extraction, and secret combination.
   - For signatures, ML-DSA-65 signing requires 1.32 ms, which dominates the hybrid signing time; ECDSA adds negligible computational overhead (~0.03 ms).
2. **Bandwidth / Storage Overhead:**
   - The primary trade-off in post-quantum and hybrid cryptography is **data size**, not computational speed.
   - Classical X25519 requires only 32 bytes for public keys and ciphertexts; Hybrid X25519 + ML-KEM-768 requires 1,227 bytes for public keys and 1,130 bytes for ciphertexts (~35x larger).
   - Classical ECDSA signatures are only ~71 bytes; Hybrid signatures require 3,390 bytes (~47x larger).
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
```bash
pip install -r hybrid-module/requirements.txt
```

### 2. Run the Unit & Security Tests
```bash
python -m pytest hybrid-module/test_hybrid.py -v
```

### 3. Run Performance Benchmarks
```bash
python hybrid-module/benchmark_hybrid.py
```
