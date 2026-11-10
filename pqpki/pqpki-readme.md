# `pqpki` — Post-Quantum PKI and Certificate Authority

A certificate authority that issues and validates real X.509 certificates
signed with either classical or post-quantum algorithms, **through the same
code path**. Switching an entire hierarchy from ECDSA P-256 to ML-DSA-65 is a
one-string change.

Author: Aadit Aggarwal

---

## Why this module exists

A post-quantum signature algorithm cannot be deployed on its own. Real systems
distribute trust through certificates, so ML-DSA only becomes usable once a CA
can issue certificates carrying ML-DSA keys and a validator can build and check
a path back to a trust anchor. This module is that layer.

It is also where the project's central comparison becomes measurable. Because
one code path serves both families, any difference in certificate size, CRL
size, or validation time is a property of the algorithm rather than of two
different implementations.

## Supported algorithms

| Name | Kind | Signature OID |
|---|---|---|
| `ecdsa-p256` | classical | `1.2.840.10045.4.3.2` |
| `rsa-2048` | classical | `1.2.840.113549.1.1.11` |
| `ml-dsa-44` | post-quantum | `2.16.840.1.101.3.4.3.17` |
| `ml-dsa-65` | post-quantum (default) | `2.16.840.1.101.3.4.3.18` |
| `ml-dsa-87` | post-quantum | `2.16.840.1.101.3.4.3.19` |

ML-DSA certificates follow **RFC 9881**: pure ML-DSA, no pre-hash, empty
signing context, and an `AlgorithmIdentifier` whose `parameters` field is
**absent** rather than NULL. That last detail is the one most easily got wrong,
and getting it wrong produces certificates our own library accepts and every
other implementation rejects.

## Setup

Requires **Python 3.11+** and **`cryptography` 50 or newer**. Version 49 added
X.509 signing with ML-DSA keys; 50 added ML-DSA to the default path-validation
policy. Both are needed.

```bash
pip install -r requirements.txt
```

The OpenSSL interoperability tests additionally need the `openssl` binary at
**3.5 or newer**. They skip themselves, naming the version found, if it is
older or missing. No `liboqs` is required: ML-DSA comes from `cryptography`
itself.

## Running it

```bash
# A nine-stage demonstration, end to end
python -m pqpki.cli                  # post-quantum by default
python -m pqpki.cli --all            # once per algorithm, same code path
python -m pqpki.cli --algorithm ecdsa-p256 --keep

# Timings and artifact sizes for every algorithm -> results/pqpki_benchmark.csv
python -m pqpki.benchmark --iterations 10

# Certificate-level attacks, with PASS/FAIL per attack
python -m pqpki.attacks
python -m pqpki.attacks --algorithm ml-dsa-65 --verbose

# The test suite
pytest tests                         # this module only
pytest tests -m "not interop"        # skip the openssl cross-checks
```

The demo writes to a temporary directory outside the repository and removes it
unless `--keep` is passed. Every file it leaves behind is a real certificate or
CRL that `openssl` will parse.

## Public API

Import from the package root; the submodule layout is an implementation detail.

```python
from pqpki import CertificateAuthority, generate_csr, validate_chain

root = CertificateAuthority.create_root("Example Root", "ml-dsa-65")

key = root.algorithm.generate_key()
csr = generate_csr("Example Intermediate", key)
cert = root.issue_intermediate(csr, validity_days=1825)
intermediate = CertificateAuthority(cert, key)

leaf_key = intermediate.algorithm.generate_key()
leaf_csr = generate_csr("example.com", leaf_key, san_dns=["example.com"])
leaf = intermediate.issue_end_entity(leaf_csr, validity_days=90)

result = validate_chain(leaf, [cert], [root.certificate])
print(result.valid, result.failures)
```

Changing `"ml-dsa-65"` to `"rsa-2048"` on the first line is the only edit
needed to make that whole hierarchy classical.

### For a front end

`PKIStore` keeps a hierarchy in a directory so a menu-driven UI does not have
to hold objects between keystrokes. It needs no crypto imports of its own.

```python
from pqpki import PKIStore, CertificateProfile

store = PKIStore("./pki", passphrase="…", crl_url="http://crl.example/c.crl")
store.create_root("My Root", "ml-dsa-65")
store.create_intermediate("My Intermediate")

cert, cert_path, key_path = store.issue_certificate(
    "service.example", ["service.example"], CertificateProfile.SERVER
)
print(store.describe_certificate(cert_path))
print(store.validate_certificate(cert_path).valid)

store.revoke(cert.serial_number)
store.publish_crl()
store.publish_delta_crl()
```

Also available: `sign_csr`, `sign_file`, `verify_file`, `describe_csr`,
`crl_summary`, `write_chain_bundle`.

### For a security-testing harness

`pqpki.attacks` builds deliberately broken chains and asserts the *named*
reason each is rejected for, so a caller can check not just that something was
refused but that it was refused for the right reason.

```python
from pqpki.attacks import run_all

for outcome in run_all("ml-dsa-65"):
    print("PASS" if outcome.defended else "FAIL", outcome.name, outcome.detail)
```

18 attacks per algorithm, in two shapes: chains the validator must reject, and
requests the CA must refuse before signing anything.

## What is implemented

**Issuance.** Root and intermediate CAs, end-entity certificates, CSRs with
proof-of-possession verification, random serial numbers, and the required
extensions: `BasicConstraints` and `KeyUsage` critical, `SubjectKeyIdentifier`
throughout, `AuthorityKeyIdentifier` on everything except the self-signed root,
`SubjectAlternativeName` and `ExtendedKeyUsage` on leaves, and
`CRLDistributionPoints` / `FreshestCRL` when the CA is told where it publishes.

**Validation.** Written by hand rather than delegated to the library's
verifier, because the point is to make the steps visible and report *which* one
failed. Name chaining, signature at every link, validity windows, basic
constraints, path length, key usage, and revocation — accumulating every
failure rather than stopping at the first, since a certificate that is both
expired and revoked has two things wrong with it.

Sixteen named failure codes: `name-chaining`, `no-trust-anchor`, `signature`,
`signature-algorithm-mismatch`, `expired`, `not-yet-valid`,
`basic-constraints-missing`, `not-a-ca`, `basic-constraints-not-critical`,
`path-length`, `key-usage-missing`, `key-usage-cert-sign`,
`key-usage-digital-signature`, `revoked`, `crl-problem`,
`unsupported-algorithm`.

**Revocation.** Complete CRLs and delta CRLs, with monotonic `CRLNumber`
shared across both. A CRL is believed only after its signature is verified
against the issuer it claims. A delta CRL is applied only once its base is
present — on its own it is reported as a problem, never read as complete,
because doing so would make every serial listed only in the base look
unrevoked.

**Persistence.** `save()` writes the certificate, the key (optionally
passphrase-encrypted), and `ca-state.json` holding the revocation register and
CRL counters. A reloaded CA neither forgets its revocations nor restarts CRL
numbering.

**Measurement.** Every instrumented operation can emit a `MetricEvent` with a
duration and an artifact size through an optional `collector` callback.
`pqpki.benchmark` aggregates these across algorithms into a CSV.

## Architecture

`pqpki/algorithms.py` is the only module that names a concrete algorithm, curve,
key size, or OID. Everything else signs via `builder.sign(key, *spec.sign_args())`
and verifies via `spec.verify_signature(...)`, and never branches on algorithm.

That is not a convention to be remembered — it is enforced. An automated test
parses every other module's syntax tree and fails the build if an algorithm
name or OID appears outside the agility layer. It discovers modules by glob, so
a new file is covered the moment it is added.

```
pqpki/
  algorithms.py   the agility layer: registry, signing/verification seams, metrics
  errors.py       an 11-class exception hierarchy under PQPKIError
  csr.py          CSR generation and proof-of-possession verification
  ca.py           CertificateAuthority: issuance, revocation, CRLs, persistence
  validate.py     certification path validation, by hand, with named failures
  revocation.py   the relying party's half: CRL and delta CRL interpretation
  backend.py      PKIStore, a file-backed hierarchy for a front end to drive
  benchmark.py    timings and sizes across every algorithm, to CSV
  attacks.py      deliberately broken chains, for a security-testing harness
  cli.py          the nine-stage demonstration
```

## Results

**1187 tests pass** for this module (1266 repo-wide, across all modules), with
7 skipped for documented reasons: 5 POSIX permission assertions that cannot be
honestly checked on Windows, and 2 NULL-parameter injections that do not apply
to RSA, which correctly carries NULL already. 56 of them are OpenSSL
interoperability tests.

**90 of 90 certificate-level attacks are repelled** (18 per algorithm × 5).

**OpenSSL 3.5.4 independently agrees**, including on revocation: `openssl
verify -crl_check` rejects a certificate this CA revoked, `openssl crl` reports
our delta CRLs' critical `DeltaCRLIndicator`, and `openssl pkey` reads our
passphrase-encrypted ML-DSA keys.

### Sizes and timings

From `python -m pqpki.benchmark`; sizes are exact and machine-independent,
timings are indicative only.

Ten iterations per algorithm, 200 revocations on the base CRL and 2 on the
delta.

| Algorithm | Public key | Signature | Leaf cert | CRL (200) | Delta (2) | Keygen | Issue | Validate |
|---|---|---|---|---|---|---|---|---|
| `ecdsa-p256` | 91 | 71 | 474 | 7 100 | 327 | 0.10 ms | 0.05 ms | 0.25 ms |
| `rsa-2048` | 294 | 256 | 870 | 7 293 | 520 | 35.58 ms | 0.51 ms | 0.19 ms |
| `ml-dsa-44` | 1 334 | 2 420 | 4 070 | 9 453 | 2 680 | 0.09 ms | 0.50 ms | 0.35 ms |
| `ml-dsa-65` | 1 974 | 3 309 | 5 599 | 10 342 | 3 569 | 0.15 ms | 0.67 ms | 0.50 ms |
| `ml-dsa-87` | 2 614 | 4 627 | 7 557 | 11 660 | 4 887 | 0.22 ms | 1.11 ms | 0.81 ms |

Three findings worth stating plainly:

1. **The cost of post-quantum certificates is size, not speed.** An ML-DSA-65
   leaf is 11.8× an ECDSA P-256 one and its signature is 47×. But ML-DSA key
   generation is *faster* than RSA-2048 by roughly 240×, and is in the same
   range as ECDSA; chain validation is under 2× slower than ECDSA. The
   bottleneck for a PQ migration is bandwidth, storage, and protocol size
   limits — not CPU.

2. **CRL overhead amortises.** With 200 revocations the ML-DSA-65 CRL is only
   1.5× the ECDSA one, because the entry list dominates the fixed signature.
   Compare the certificate ratio of 11.8×: per-artifact overhead matters far
   less the more the artifact carries.

3. **Delta CRLs help post-quantum least, proportionally.** Against a 200-entry
   base, a 2-entry delta is 95.4% smaller for ECDSA but only 58.1% smaller for
   ML-DSA-87, because the large fixed signature dominates a short delta. Delta
   CRLs still help — they are just not the same win.

## This is a teaching implementation

Built to be read and compared against, not deployed. Deliberately:

- **No HSM or key isolation.** Keys live in ordinary process memory. A
  passphrase protects them at rest and nothing protects them in use.
- **No offline root.** The root key is loaded in the same process as
  everything else.
- **No constant-time or side-channel guarantees.** Timing is deliberately
  measured and exposed here, which is close to the opposite of what production
  code should do with it.
- **No issuance database**, so the CA cannot tell whether a serial it is asked
  to revoke was ever one of its own.
- **Revocation state is an unauthenticated JSON file.** Anything that can
  write it can silently un-revoke a certificate.
- **CRL distribution points are published, not fetched.** Nothing dereferences
  those URLs; CRLs arrive as arguments.
- **No OCSP, no audit log, no name constraints, no policy mapping.**
- **`0o600` is advisory on Windows**, where POSIX permission bits do not map
  onto ACLs — which is why the passphrase matters more there.

Do not use it to protect anything.

## References

- RFC 9881 — ML-DSA in X.509 (algorithm identifiers, absent `parameters`)
- RFC 5280 — X.509 certificate and CRL profile, path validation, delta CRLs
- RFC 4055 — why RSA carries NULL `parameters` where ML-DSA omits the field
- FIPS 204 — ML-DSA
