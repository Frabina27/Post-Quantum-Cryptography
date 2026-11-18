# pqpki — Post-Quantum PKI and Certificate Authority

This module is a certificate authority. It creates X.509 certificates, checks whether a certificate can be trusted, and revokes certificates that should no longer be accepted. The module is created in a way that it can do all of this with either classical algorithms (RSA, ECDSA) or post-quantum ones (ML-DSA), using the same code, so the two can be compared fairly. It produces real certificates, not examples.

## OS requirements
Works on Windows, macOS, and Linux. It was developed and tested on Windows 11.

## Programming language
Python 3.11 or newer.

## Required software and dependencies
Python - 3.11 or newer
`cryptography` - version 50 or newer
`pytest` - any recent version
`openssl` command - 3.5 or newer

## Installation
From the project root:

```bash
python -m venv .venv

# Windows
.venv\Scripts\activate
# macOS / Linux
source .venv/bin/activate

pip install -r requirements.txt
pip install pytest
```

## Commands to execute the program
```bash
# A nine-stage demo of the whole module, start to finish
python -m pqpki.cli                         # post-quantum (ML-DSA-65) by default
python -m pqpki.cli --algorithm ecdsa-p256  # classical instead
python -m pqpki.cli --all                   # run it once for every algorithm
python -m pqpki.cli --keep                  # keep the files it creates

# Measure speed and file sizes, saved to pqpki/results/pqpki_benchmark.csv
python -m pqpki.benchmark --iterations 10

# Run the certificate attacks and print PASS or FAIL for each one
python -m pqpki.attacks
python -m pqpki.attacks --algorithm ml-dsa-65 --verbose

# Run the tests
pytest tests
pytest tests -m "not interop"    # skip the tests that call openssl
```

## How it works

The module implements a PKI systems in five steps:
1. **Create a root CA.** It makes a key pair and signs its own certificate.
2. **Create an intermediate CA.** The intermediate makes its own key and sends a certificate signing request (CSR) to the root. The root checks that the requester really holds the matching private key, then signs it. 
3. **Issue an end-entity certificate.** A server or a user sends a CSR, and the intermediate signs a certificate for it.
4. **Validate the chain.** Given a certificate, the certificates above it, and the roots you trust, the module walks from the certificate up to the root and checks that the issuer names match, every signature is correct, the dates are valid, the CAs are allowed to be CAs, and nothing has been evoked. If something is wrong it says exactly what.
5. **Revoke a certificate.** The CA publishes a certificate revocation list (CRL), which is a signed list of serial numbers that are no longer valid.

### Supported algorithms
`ecdsa-p256` - classical
`rsa-2048` - classical
`ml-dsa-44` - post-quantum
`ml-dsa-65` - post-quantum (default)
`ml-dsa-87` - post-quantum 

The ML-DSA certificates follow RFC 9881, which is the standard for putting ML-DSA into X.509.

### Files
```
pqpki/
  algorithms.py   the only file that names an algorithm; signing and verifying
  errors.py       the exception types
  csr.py          certificate signing requests
  ca.py           the CertificateAuthority class: issuing, revoking, CRLs, saving
  validate.py     checking a certificate chain, with named reasons for failure
  revocation.py   reading CRLs and delta CRLs
  backend.py      PKIStore, a folder-based CA for a menu-driven program to use
  benchmark.py    timing and size measurements, written to a CSV file
  attacks.py      certificates broken on purpose, for the security-testing module
  cli.py          the nine-stage demo
```

## Results

1187 tests pass for this module. 56 of these tests run the real `openssl` command against the certificates this module produces.
All 90 certificate attacks are correctly rejected (18 attacks across 5 algorithms).

The measurements below come from running `python -m pqpki.benchmark`, with 10 runs per algorithm and a CRL holding 200 revocations.

| Algorithm | Public key | Signature | Certificate | CRL (200) | Delta CRL (2) | Key generation | Validation |
|---|---|---|---|---|---|---|---|
| `ecdsa-p256` | 91 | 71 | 474 | 7 100 | 327 | 0.10 ms | 0.25 ms |
| `rsa-2048` | 294 | 256 | 870 | 7 293 | 520 | 35.58 ms | 0.19 ms |
| `ml-dsa-44` | 1 334 | 2 420 | 4 070 | 9 453 | 2 680 | 0.09 ms | 0.35 ms |
| `ml-dsa-65` | 1 974 | 3 309 | 5 599 | 10 342 | 3 569 | 0.15 ms | 0.50 ms |
| `ml-dsa-87` | 2 614 | 4 627 | 7 557 | 11 660 | 4 887 | 0.22 ms | 0.81 ms |

1. **The cost of post-quantum is size, not speed.** An ML-DSA-65 certificate is 11.8 times the size of an ECDSA P-256 one and its signature is 47 times larger. But ML-DSA key generation is about 240 times faster than RSA-2048, and validating a chain is under twice as slow as ECDSA. The problem with moving to post-quantum is bandwidth and storage, not processing power.
2. **CRLs are affected much less than certificates.** With 200 revocations the ML-DSA-65 CRL is only 1.5 times the ECDSA one, because the list of serial numbers is far bigger than the signature. The more a file carries, the less the signature size matters.
3. **Delta CRLs help post-quantum the least.** Against a 200-entry base CRL, a 2-entry delta is 95.4% smaller for ECDSA but only 58.1% smaller for ML-DSA-87, because the large signature takes up most of a short delta.

## Limitations and incomplete features
This module was written to be read and compared against, not to be deployed. It is not safe to protect anything real with it. The specific gaps:
- **Private keys are kept in normal memory and normal files.** A real CA keeps its signing key inside hardware that will not give it back.
- **The root key is not kept offline.** It is loaded in the same program as everything else.
- **The revocation list is stored in a plain JSON file with no protection.** Anything that can write to that file could silently un-revoke a certificate.
- **There is no record of which certificates were issued**, so the CA cannot tell whether a serial number it is asked to revoke was ever one of its own.
- **No OCSP**, which is the protocol for asking about one certificate instead of downloading a whole list.
- **No audit log.**
- **No hybrid certificates** carrying both a classical and a post-quantum signature at the same time.

## References
- RFC 9881 — ML-DSA in X.509 certificates
- RFC 5280 — the X.509 certificate and CRL standard, including path validation
- RFC 4055 — why RSA sets `parameters` to NULL where ML-DSA leaves it out
- FIPS 204 — the ML-DSA standard
