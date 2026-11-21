# Hybrid Classical + PQC Module

Hybrid key encapsulation (X25519/P-256 + ML-KEM-768), composite signatures (ECDSA/RSA + ML-DSA-65), and a PKI migration simulator. Full design notes and benchmark results are in [hybrid-readme.md](hybrid-readme.md).

## OS Requirements
Tested on Linux x86_64. Any OS supported by Python and the `cryptography` package (macOS, Windows) should also work.

## Programming Languages
Python 3.11 or newer (tested with Python 3.14).

## Required Software and Dependencies
- Python 3.11+ with `pip` and `venv`
- `cryptography>=50` (provides ML-KEM and ML-DSA)
- `pytest>=8` for running the tests

## Installation Instructions
From the repository root, create a virtual environment and install the dependencies:
```bash
python3 -m venv .venv
.venv/bin/pip install "cryptography>=50" "pytest>=8"
```

## Commands to Execute the Program
Run all unit, security, and known-answer tests (from the repository root):
```bash
.venv/bin/python -m pytest hybrid-module -v
```
Run the performance benchmark, which prints a summary and writes `results/hybrid_benchmark.csv`:
```bash
.venv/bin/python hybrid-module/benchmark_hybrid.py
```

## Login Credentials for Testing
Not applicable. The module is a library with tests and a benchmark, and has no login or user accounts.

## Limitations & Incomplete Features
- The module is a library with no interactive interface; it is exercised through the tests and the benchmark.
- `hybrid_pki.py` uses a simplified JSON certificate format, not real X.509, so its certificates do not interoperate with standard tools.
- Composite signatures are modeled after the IETF composite-signature work but are not byte-compatible with it; only the KEM is checked against published test vectors.
- The X-Wing known-answer test imports the team's `Kyber/mlkem.py`, so the full repository must be checked out.
