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
* **No serial-number database, no CRL distribution, no OCSP, no audit log, and
  no name-constraint or policy-mapping support.** Revocation state lives in
  memory for the life of a :class:`~pqpki.ca.CertificateAuthority` instance.
* **Keys written to disk** go in a ``keys/`` subdirectory with mode ``0o600``.
  On Windows that mode is advisory: the POSIX permission bits do not map onto
  Windows ACLs, so the call succeeds without actually restricting access the
  way it would on Linux or macOS.

Do not use it to protect anything.
"""

from __future__ import annotations

from .algorithms import (
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

__version__ = "0.1.0"

__all__ = [
    # algorithms
    "AlgorithmSpec",
    "Collector",
    "MetricEvent",
    "get_algorithm",
    "list_algorithms",
    # certificate authority
    "CertificateAuthority",
    # certificate signing requests
    "generate_csr",
    "verify_csr_signature",
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
