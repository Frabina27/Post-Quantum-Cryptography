"""Exception hierarchy for :mod:`pqpki`.

Every exception raised by this package derives from :class:`PQPKIError`, so a
caller that wants to catch "anything this library did wrong" needs exactly one
``except`` clause.

A note on validation, because it is the one place where the convention is
deliberately inverted: :func:`pqpki.validate.validate_chain` does **not** raise
on a certificate that fails to validate. An untrusted or expired chain is an
expected outcome, not a programming error, and a caller usually wants every
reason a chain was rejected rather than just the first. Those reasons are
returned in :attr:`pqpki.validate.ValidationResult.failures`.
:class:`ValidationInputError` is reserved for the separate case where the
validator could not even begin -- for example, an empty trust-root list.
"""

from __future__ import annotations

__all__ = [
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
]


class PQPKIError(Exception):
    """Base class for every error raised by :mod:`pqpki`."""


# --------------------------------------------------------------------------
# Crypto-agility layer
# --------------------------------------------------------------------------


class AlgorithmError(PQPKIError):
    """Base class for failures in the crypto-agility layer."""


class UnknownAlgorithmError(AlgorithmError):
    """A signature algorithm was requested by a name that is not registered.

    Raised by :func:`pqpki.algorithms.get_algorithm`. The message lists the
    registered names, since the usual cause is a typo or a stale algorithm
    string in a config file.
    """

    def __init__(self, name: str, known: list[str]) -> None:
        self.name = name
        self.known = known
        super().__init__(
            f"unknown algorithm {name!r}; registered algorithms are: "
            + ", ".join(known)
        )


class UnsupportedKeyTypeError(AlgorithmError):
    """A key or certificate could not be mapped back to a registered algorithm.

    Raised by the reverse-lookup helpers in :mod:`pqpki.algorithms` when handed
    a key this package has no :class:`~pqpki.algorithms.AlgorithmSpec` for --
    an Ed25519 key, or an RSA key of a size other than the registered one.
    """


# --------------------------------------------------------------------------
# Certificate authority
# --------------------------------------------------------------------------


class CAError(PQPKIError):
    """Base class for certificate-authority failures."""


class CAStateError(CAError):
    """The CA was asked to do something its current state does not allow.

    Covers loading a CA whose key and certificate do not match each other, and
    issuing from a certificate that does not assert ``BasicConstraints``
    ``CA=TRUE``.
    """


class IssuanceError(CAError):
    """A certificate could not be issued from the supplied request.

    Raised when the request itself is the problem -- a CSR that fails
    proof-of-possession, or an intermediate requested at a path length the
    issuing CA's own constraint cannot accommodate.
    """


# --------------------------------------------------------------------------
# Certificate signing requests
# --------------------------------------------------------------------------


class CSRError(PQPKIError):
    """Base class for certificate-signing-request failures."""


class ProofOfPossessionError(CSRError):
    """A CSR's self-signature did not verify.

    The signature on a CSR is the requester's proof that it holds the private
    key matching the public key inside. If it does not verify, the request
    proves nothing and must not be signed.
    """


# --------------------------------------------------------------------------
# Validation and revocation
# --------------------------------------------------------------------------


class ValidationInputError(PQPKIError):
    """Path validation could not start because its inputs were unusable.

    Distinct from a chain that validates to *invalid*; see the module
    docstring.
    """


class RevocationError(PQPKIError):
    """A CRL could not be generated, parsed, or applied."""
