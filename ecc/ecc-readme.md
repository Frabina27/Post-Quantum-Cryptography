# ECC Cryptographic Module

## Project Overview

This module implements Elliptic Curve Cryptography (ECC) using Python.  
Its purpose is to demonstrate how modern classical elliptic‑curve systems work, including:

- Key generation  
- ECDH key agreement  
- ECDSA digital signatures  
- PEM key export  
- Curve selection (P‑256, P‑384, P‑521)

The module includes correctness tests to ensure the ECC implementation behaves as expected.  
These results will help our team compare ECC with post‑quantum algorithms later in the project.

---

## Files and What They Do

| File | Purpose |
|---|---|
| `ecc_crypto.py` | Main ECC implementation: key generation, ECDH, ECDSA, and PEM export. |
| `test_ecc.py` | Tests ECC functionality to ensure correctness. |
| `requirements.txt` | Lists required Python libraries. |
| `ecc-readme.md` | Documentation explaining the module and how to run it. |

---

## What I Implemented

### 1. ECC Key Generation

The module uses the Python `cryptography` library to generate elliptic‑curve keypairs.

Supported curves:

- **P‑256 (SECP256R1)**  
- **P‑384 (SECP384R1)**  
- **P‑521 (SECP521R1)**  

Each curve offers different security levels and performance characteristics.  
The private key is used for signing and deriving shared secrets, while the public key is used for verification and key agreement.

---

### 2. ECDH Key Agreement

ECC does not directly encrypt messages.  
Instead, two parties use **Elliptic Curve Diffie–Hellman (ECDH)** to derive a shared secret:

1. Each party generates an EC keypair.  
2. They exchange public keys.  
3. Each side computes the same shared secret using ECDH.  
4. The shared secret is expanded into a symmetric key using HKDF with SHA‑256.

This symmetric key can be used with algorithms like AES‑GCM for secure communication.

---

### 3. ECDSA Digital Signatures

The module implements digital signatures using **ECDSA with SHA‑256**.

- The private key signs a message.  
- The public key verifies the signature.  
- Verification fails if the message or signature is modified.

Digital signatures provide message integrity and authentication.

---

### 4. ECC Key Export

The module includes functions to export both public and private keys in PEM format.

This allows keys to be saved, inspected, and measured for storage size.  
PEM export also makes it easier to integrate ECC keys into other tools or modules.

---

### 5. ECC Testing

The test suite covers:

- Key generation  
- ECDH shared‑secret agreement  
- ECDSA signing and verification  
- Modified messages  
- Modified signatures  
- Curve selection  
- PEM formatting  

All tests passed in the reported run.

---

## How to Run the Module

Install dependencies:

```bash
python -m pip install -r ecc-module/requirements.txt
````

Run tests:
````bash
python ecc-module/test_ecc.py
````

## Current Limitations
- ECC does not support direct encryption; ECDH must be combined with a symmetric cipher.
- Private keys are exported without password protection (testing only).
- The module does not include post‑quantum algorithms; those are implemented separately.

## Next Steps
- Integrate ECC with the rest of the project modules.
- Compare ECC performance with post‑quantum algorithms.
- Add optional AES‑GCM encryption using ECDH‑derived keys.
- Prepare the module for the final project demonstration.

## Conclusion
This module implements the core ECC operations, includes correctness tests, and provides performance measurements for multiple curves.
It serves as a classical cryptography baseline for the project and will help our team understand how elliptic‑curve systems compare to post‑quantum cryptography.