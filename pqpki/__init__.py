"""``pqpki`` -- a post-quantum-capable X.509 certificate authority and PKI layer.

This package issues and validates real X.509 certificates signed with either
classical (RSA, ECDSA) or post-quantum (ML-DSA) algorithms, using the same code
path for both. Every certificate it produces is a genuine, parseable
certificate that ``openssl`` and ``pyca/cryptography`` both accept; nothing here
is mocked or stubbed.

Public API
----------
Import from the package root. Submodule layout is an implementation detail::

    from pqpki import CertificateAuthority, generate_csr, validate_chain

Crypto agility is the organizing idea: :mod:`pqpki.algorithms` is the only
module that names a concrete algorithm, so moving a hierarchy from
``ecdsa-p256`` to ``ml-dsa-65`` is a one-string change.

This is a teaching implementation
---------------------------------
It is built to be read and compared against, not deployed. Specifically, and
deliberately:

* **No HSM or key isolation.** Private keys live in ordinary process memory and
  are written to ordinary files. A real CA keeps its signing key in hardware
  that will not export it.
* **No offline root.** The root key is loaded and used in the same process as
  everything else. A real root key lives on an air-gapped machine and comes out
  for scheduled ceremonies under dual control.
* **No constant-time or side-channel guarantees.** Timing is *deliberately
  measured and exposed* here for the benchmarking comparison, which is close to
  the opposite of what production code should do with it.
* **No serial-number database, no OCSP, no audit log, and no name-constraint
  or policy-mapping support.** Revocation state is persisted, but as an
  unauthenticated JSON file that anything with write access can edit.
* **CRL distribution points are published, not fetched.** A certificate says
  where its CRL lives; nothing here dereferences that URL. CRLs arrive as
  arguments, so a caller decides what to trust and when.
* **Keys written to disk** go in a ``keys/`` subdirectory with mode ``0o600``,
  optionally passphrase-encrypted. On Windows that mode is advisory: the POSIX
  permission bits do not map onto Windows ACLs, so the call succeeds without
  actually restricting access the way it would on Linux or macOS -- which
  makes the passphrase the only protection that really holds there.

Do not use it to protect anything.
"""

from __future__ import annotations

from .algorithms import (
    DEFAULT_ALGORITHM,
    AlgorithmSpec,
    Collector,
    MetricEvent,
    get_algorithm,
    list_algorithms,
)
from .ca import CertificateAuthority
from .csr import generate_csr, verify_csr_signature
from .errors import (
    AlgorithmError,
    CAError,
    CAStateError,
    CSRError,
    IssuanceError,
    PQPKIError,
    ProofOfPossessionError,
    RevocationError,
    UnknownAlgorithmError,
    UnsupportedKeyTypeError,
    ValidationInputError,
)
from .revocation import (
    RevocationStatus,
    check_revocation,
    crl_number,
    delta_base_number,
    is_delta_crl,
)
from .validate import FailureCode, ValidationResult, validate_chain

__version__ = "0.1.0"

__all__ = [
    # algorithms
    "AlgorithmSpec",
    "DEFAULT_ALGORITHM",
    "Collector",
    "MetricEvent",
    "get_algorithm",
    "list_algorithms",
    # certificate authority
    "CertificateAuthority",
    # certificate signing requests
    "generate_csr",
    "verify_csr_signature",
    # validation
    "validate_chain",
    "ValidationResult",
    "FailureCode",
    # revocation
    "check_revocation",
    "RevocationStatus",
    "is_delta_crl",
    "crl_number",
    "delta_base_number",
    # a file-backed hierarchy, for a front end to drive
    "PKIStore",
    "CertificateProfile",
    "SignatureCheck",
    # measurement
    "benchmark_algorithm",
    "AlgorithmResult",
    # certificate-level attacks, for the security-testing module
    "run_all",
    "ChainAttack",
    "IssuanceAttack",
    "AttackOutcome",
    # errors
    "PQPKIError",
    "AlgorithmError",
    "UnknownAlgorithmError",
    "UnsupportedKeyTypeError",
    "CAError",
    "CAStateError",
    "IssuanceError",
    "CSRError",
    "ProofOfPossessionError",
    "ValidationInputError",
    "RevocationError",
    "__version__",
]

# The tool modules -- the front-end backend, the benchmark harness, and the
# attack vectors -- are exported lazily rather than imported here.
#
# Two reasons. Each has a ``main()`` and is meant to be run as
# ``python -m pqpki.<name>``; importing it in this file means Python finds it
# already in ``sys.modules`` when ``-m`` goes to execute it, and prints a
# RuntimeWarning about unpredictable behaviour. And ``import pqpki`` should not
# drag in ``argparse``, ``csv`` and ``statistics`` for a caller that only wants
# to issue a certificate.
#
# PEP 562 keeps ``from pqpki import PKIStore`` working regardless.
_LAZY = {
    "AttackOutcome": "attacks",
    "ChainAttack": "attacks",
    "IssuanceAttack": "attacks",
    "run_all": "attacks",
    "CertificateProfile": "backend",
    "PKIStore": "backend",
    "SignatureCheck": "backend",
    "AlgorithmResult": "benchmark",
    "benchmark_algorithm": "benchmark",
}


def __getattr__(name: str) -> object:
    """Resolve the lazily exported names on first access."""
    module_name = _LAZY.get(name)
    if module_name is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

    import importlib

    module = importlib.import_module(f".{module_name}", __name__)
    value = getattr(module, name)
    globals()[name] = value  # resolved once; later lookups skip __getattr__
    return value


def __dir__() -> list[str]:
    return sorted(__all__)
