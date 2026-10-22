# RSA Cryptographic Module

## Project Overview

For my part of the Post-Quantum Cryptography project, I worked on implementing RSA encryption, decryption, key generation, and digital signatures using Python.

The main purpose of my module is to show how classical RSA cryptography works and provide results that our team can compare with post-quantum algorithms like ML-KEM and ML-DSA.

I also added tests to check that everything works correctly and a benchmarking script to measure how RSA performs with different key sizes.

## Files and What They Do

| File | Purpose |
|---|---|
| `rsa_crypto.py` | Main RSA code for generating keys, encrypting/decrypting messages, and creating/verifying signatures. |
| `test_rsa.py` | Tests the RSA functions to make sure they work correctly. |
| `benchmark_rsa.py` | Measures how long RSA operations take using 2048-bit and 3072-bit keys. |
| `rsa_benchmark.csv` | Stores the benchmark results so we can compare them later. |
| `requirements.txt` | Lists the Python library needed to run the code. |
| `rsa-readme.md` | Explains my module, how it works, and how to run it. |

## What I Implemented

### 1. RSA Key Generation

I used the Python `cryptography` library to generate RSA public and private keys.

My module supports two key sizes:
- RSA-2048
- RSA-3072

The public key is used for encryption and signature verification, while the private key is used for decryption and signing.

### 2. Encryption and Decryption

I implemented RSA encryption using OAEP padding and SHA-256.

The program encrypts a message using the public key and then decrypts it using the private key. I tested this to make sure the decrypted message matches the original.

### 3. Digital Signatures

I implemented RSA-PSS digital signatures using SHA-256.

The private key creates a signature, and the public key verifies it. If someone changes the message or signature, verification should fail.

This is important because digital signatures help detect changes to information and verify who signed it.

### 4. RSA Key Export

I added functions to export public and private keys in PEM format.

This allows the keys to be saved in a standard format and lets us measure how much space they take up.

### 5. RSA Testing

I created seven tests to check that the module works as expected.

The tests cover:
- RSA key generation
- Encryption and decryption
- Digital signature verification
- Modified messages
- Modified signatures
- RSA-3072 operations
- PEM key formatting

All seven tests passed in the reported test run.

### 6. Performance Benchmarking

I created a benchmarking script to compare RSA-2048 and RSA-3072.

The script measures key generation, encryption, decryption, signing, and verification times. It also records public/private key sizes, ciphertext sizes, and signature sizes.

The results are saved in `results/rsa_benchmark.csv` so our team can use them for comparisons.

## Benchmark Results

These are the results saved from my RSA benchmark.

| Operation | RSA-2048 | RSA-3072 |
|---|---:|---:|
| Key Generation | 35.65 ms | 139.57 ms |
| Encryption | 0.0244 ms | 0.0436 ms |
| Decryption | 0.5149 ms | 1.8777 ms |
| Signing | 0.4592 ms | 3.6720 ms |
| Verification | 0.0211 ms | 0.0670 ms |
| Public Key (PEM) | 451 bytes | 625 bytes |
| Private Key (PEM) | 1,704 bytes | 2,484 bytes |
| Ciphertext | 256 bytes | 384 bytes |
| Signature | 256 bytes | 384 bytes |

### What I Noticed

Based on the saved results, RSA-3072 was slower than RSA-2048 for every operation.

RSA-3072 also produced larger keys, ciphertexts, and signatures. This shows one of the trade-offs in cryptography: using larger keys can provide stronger security, but it can also require more processing time and storage.

These results give our team a starting point for comparing RSA with post-quantum cryptography.

## How to Run My Module

First, install the required Python library from the main project folder:

```bash
python -m pip install -r rsa-module/requirements.txt
```

To run the RSA tests:

```bash
python rsa-module/test_rsa.py
```

To run the benchmarks:

```bash
python rsa-module/benchmark_rsa.py
```

The benchmark results will be saved in the `rsa-module/results/` folder.

## Current Limitations

My module currently works with short messages and does not support encrypting entire files. It also exports private keys without password protection, so those exported keys should only be used for testing.

The module does not include post-quantum algorithms itself because those are being developed by other team members.

## Next Steps

My next steps are to:

- Integrate my RSA module with the rest of the team's code.
- Help compare RSA performance with ML-KEM and ML-DSA.
- Add more security tests if needed.
- Make sure my module works properly during the final project demonstration.

## Conclusion

So far, I've implemented the main RSA functions, created tests, and collected performance measurements for RSA-2048 and RSA-3072.

My module will serve as one of the classical cryptography baselines for our project. Once the other modules are ready, we'll be able to compare their performance and better understand the differences between classical and post-quantum cryptography.