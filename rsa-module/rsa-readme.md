# Running the Module

## 1. Install Dependencies

From the root of the repository:

```bash
python -m pip install -r rsa-module/requirements.txt
```

## 2. Run RSA Tests

```bash
python rsa-module/test_rsa.py
```

A successful execution should end with:

```text
All RSA tests passed!
```

## 3. Run RSA Benchmarks

```bash
python rsa-module/benchmark_rsa.py
```

The benchmark evaluates **RSA-2048** and **RSA-3072** and generates the CSV containing the performance and storage results.

---

# Initial Benchmark Results

The following measurements were collected during an initial benchmark run:

| Metric | RSA-2048 | RSA-3072 |
|---|---:|---:|
| Key Generation | 64.2410 ms | 175.5931 ms |
| Encryption | 0.0868 ms | 0.0698 ms |
| Decryption | 0.8614 ms | 3.5834 ms |
| Signing | 0.9961 ms | 2.7412 ms |
| Verification | 0.0395 ms | 0.1071 ms |
| Public Key | 451 bytes | 625 bytes |
| Private Key | 1,704 bytes | 2,484 bytes |
| Ciphertext | 256 bytes | 384 bytes |
| Signature | 256 bytes | 384 bytes |

> **Note:** Performance measurements are machine-dependent and should therefore be interpreted as experimental results from this test environment rather than universal RSA performance values.

---

# Observations

The results demonstrate a clear performance and storage tradeoff between **RSA-2048** and **RSA-3072**.

RSA-3072 was substantially more expensive for **private-key operations**. Decryption increased from approximately **0.86 ms with RSA-2048 to 3.58 ms with RSA-3072**. Signature generation similarly increased from approximately **1.00 ms to 2.74 ms**.

RSA-3072 also required more storage. The serialized public key increased from **451 bytes to 625 bytes**, while the serialized private key increased from **1,704 bytes to 2,484 bytes**.

The larger RSA modulus also directly affected ciphertext and signature sizes. RSA-2048 produced **256-byte ciphertexts and signatures**, whereas RSA-3072 produced **384-byte ciphertexts and signatures**.

Key generation showed another significant difference. RSA-2048 key generation averaged approximately **64.24 ms**, compared with approximately **175.59 ms for RSA-3072**.

One unusual result was encryption performance. RSA-3072 encryption was measured at approximately **0.0698 ms**, slightly faster than the **0.0868 ms** measured for RSA-2048.

This result should **not** be interpreted as evidence that RSA-3072 encryption is inherently faster than RSA-2048. These operations complete extremely quickly, making individual measurements sensitive to normal benchmark variability such as operating-system scheduling, CPU state, background processes, caching, and timer resolution. Additional benchmark iterations or repeated benchmark runs can provide a more stable comparison.

Overall, the results demonstrate that increasing the RSA key size increases storage requirements and produces a particularly noticeable performance cost for private-key operations such as **decryption and signature generation**.