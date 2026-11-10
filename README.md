# Post-Quantum-Cryptography
The project is currently incomplete, but uses Python 3.11 or newer. Current dependencies include liboqs-python and cryptography 50.0.0 or higher, with pytest 8.0.0 or higher used for testing.
At this stage of development, the individual modules have been tested separately to confirm that their functions work. However, the project has not yet been fully integrated or tested as a complete system. Because integration is still in progress, installation and run instructions have not yet been created and will be added when the project is completed.

## Post-Quantum PKI / Certificate Authority (`pqpki/`)

Maintainer: Aadit Aggarwal. Full documentation: [`pqpki/pqpki-readme.md`](pqpki/pqpki-readme.md).

A certificate authority that issues and validates real X.509 certificates
signed with either classical (RSA-2048, ECDSA P-256) or post-quantum
(ML-DSA-44/65/87) algorithms, through the same code path. ML-DSA certificates
follow RFC 9881. Requires `cryptography>=50`; it does not use `liboqs`.

```bash
python -m pqpki.cli --all      # nine-stage demo, once per algorithm
python -m pqpki.benchmark      # timings and sizes -> pqpki/results/pqpki_benchmark.csv
python -m pqpki.attacks        # certificate-level attacks, PASS/FAIL per attack
pytest tests                   # this module's test suite
```

`pqpki.PKIStore` exposes the whole hierarchy as a file-backed store for a front
end to drive, and `pqpki.attacks` exports deliberately broken certificate
chains for the security-testing module to run against.
