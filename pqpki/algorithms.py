"""The crypto-agility layer -- the only module in :mod:`pqpki` that names a
concrete signature algorithm.

Everything else in the package reaches an algorithm through an
:class:`AlgorithmSpec`. No other module imports ``rsa``, ``ec``, or ``mldsa``,
and no other module contains an algorithm name, a key size, a curve, or an OID.
That is what lets the classical and post-quantum certificate paths be the same
code: switching a hierarchy from ``ecdsa-p256`` to ``ml-dsa-65`` changes one
string and nothing else.

The seam that makes this work is :meth:`AlgorithmSpec.sign_args`. ``pyca``
spells "sign with a hash-then-sign algorithm" as ``sign(key, SHA256())`` and
"sign with pure ML-DSA" as ``sign(key, None)``. Call sites write::

    builder.sign(key, *spec.sign_args())

and stay ignorant of which family they are in.

RFC 9881 conformance notes
--------------------------
* ML-DSA signature OIDs are ``2.16.840.1.101.3.4.3.17`` / ``.18`` / ``.19`` for
  ML-DSA-44 / -65 / -87. For ML-DSA the signature OID and the
  ``SubjectPublicKeyInfo`` key OID are the same value; for the classical
  algorithms they differ, which is why both :attr:`AlgorithmSpec.oid` and
  :attr:`AlgorithmSpec.key_oid` exist.
* The ``AlgorithmIdentifier`` ``parameters`` field must be *absent* for ML-DSA,
  not NULL. ``pyca/cryptography`` encodes it correctly; the RFC 9881 tests
  assert it structurally against the DER rather than trusting the library.
* These are the *pure* ML-DSA algorithms, not the pre-hash (HashML-DSA)
  variants, and the signing context string is empty for X.509 certificates and
  CRLs. ``pyca`` gives no way to set a context when signing a certificate, so
  an empty context is what we get and what the RFC requires.

This is a teaching implementation. See :mod:`pqpki` for the full list of what
it deliberately does not do.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, mldsa, padding, rsa
from cryptography.hazmat.primitives.asymmetric.types import (
    CertificateIssuerPrivateKeyTypes,
    PrivateKeyTypes,
    PublicKeyTypes,
)

from .errors import UnknownAlgorithmError, UnsupportedKeyTypeError

__all__ = [
    "AlgorithmSpec",
    "DEFAULT_ALGORITHM",
    "MetricEvent",
    "Collector",
    "get_algorithm",
    "list_algorithms",
    "spec_for_key",
    "spec_for_certificate",
    "spec_for_signature_oid",
    "public_key_size",
]


# --------------------------------------------------------------------------
# Instrumentation
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class MetricEvent:
    """One timed, sized operation, handed to a ``collector`` callback.

    This package does not aggregate, store, or report these -- a teammate owns
    the benchmarking harness. All this layer promises is that the data is
    reachable: pass a ``collector`` and you get an event per instrumented
    operation.

    Attributes:
        operation: What was done. One of ``"generate_key"``,
            ``"issue_intermediate"``, ``"issue_end_entity"``, ``"publish_crl"``,
            or ``"validate_chain"``.
        algorithm: The :attr:`AlgorithmSpec.name` involved.
        duration_s: Wall-clock seconds, from :func:`time.perf_counter`. Wall
            clock on a shared machine is noisy; treat a single event as
            indicative, not authoritative.
        artifact_bytes: Size in bytes of what the operation produced -- the DER
            certificate, the DER CRL, or the DER ``SubjectPublicKeyInfo`` for a
            generated key. ``None`` when the operation produces no artifact,
            as with :func:`~pqpki.validate.validate_chain`.
    """

    operation: str
    algorithm: str
    duration_s: float
    artifact_bytes: int | None = None


Collector = Callable[[MetricEvent], None]
"""A sink for :class:`MetricEvent`. Keyword-only and optional everywhere.

Exceptions raised by a collector are *not* caught. A broken measurement
harness should fail loudly rather than silently skew a comparison.
"""


def _emit(
    collector: Collector | None,
    operation: str,
    algorithm: str,
    duration_s: float,
    artifact_bytes: int | None = None,
) -> None:
    """Hand one event to ``collector``, if there is one."""
    if collector is not None:
        collector(MetricEvent(operation, algorithm, duration_s, artifact_bytes))


def public_key_size(key: PublicKeyTypes | PrivateKeyTypes) -> int:
    """Return the DER ``SubjectPublicKeyInfo`` length of ``key`` in bytes.

    This is the artifact size the benchmarking module cares about for a key:
    it is what actually goes into a certificate, and it is comparable across
    algorithm families in a way that a raw key or a modulus size is not.
    Accepts a private or a public key.
    """
    pub = key.public_key() if hasattr(key, "public_key") else key
    return len(
        pub.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )


# --------------------------------------------------------------------------
# AlgorithmSpec
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class AlgorithmSpec:
    """Describes one signature algorithm. The agility layer.

    Instances are immutable, registered once at import, and compared by
    :attr:`name`. Get one from :func:`get_algorithm` rather than constructing
    it; the constructor is not part of the public API.
    """

    name: str
    """Stable identifier, e.g. ``"ml-dsa-65"``. This is what callers pass
    around and what appears in
    :attr:`~pqpki.validate.ValidationResult.algorithms_used`."""

    is_post_quantum: bool
    """True for the ML-DSA family, False for RSA and ECDSA."""

    oid: str
    """Dotted OID of the *signature* algorithm -- what appears in a
    certificate ``signatureAlgorithm`` field and in
    ``TBSCertificate.signature``. For ECDSA this is ``ecdsa-with-SHA256``, not
    ``id-ecPublicKey``."""

    key_oid: str
    """Dotted OID of the *public key* algorithm, as it appears in
    ``SubjectPublicKeyInfo``. Equal to :attr:`oid` for ML-DSA."""

    _generate: Callable[[], CertificateIssuerPrivateKeyTypes] = field(
        repr=False, compare=False
    )
    _hash_factory: Callable[[], hashes.HashAlgorithm] | None = field(
        repr=False, compare=False
    )
    _identify: Callable[[Any], bool] = field(repr=False, compare=False)
    _verify: Callable[[Any, bytes, bytes], None] = field(repr=False, compare=False)

    # -- signing seam ------------------------------------------------------

    @property
    def hash_algorithm(self) -> hashes.HashAlgorithm | None:
        """A fresh hash instance for this algorithm, or ``None`` for ML-DSA.

        ``None`` is meaningful rather than missing: pure ML-DSA signs the
        message directly, so there is no pre-hash to name.
        """
        return None if self._hash_factory is None else self._hash_factory()

    def sign_args(self) -> tuple[hashes.HashAlgorithm | None]:
        """Positional arguments to splat into a ``pyca`` ``.sign(key, ...)``.

        Use as ``builder.sign(key, *spec.sign_args())``. This is the single
        place where the hash-then-sign and pure-signature families diverge; if
        a future algorithm needs a different signing call shape, it changes
        here and nowhere else.
        """
        return (self.hash_algorithm,)

    # -- verification seam -------------------------------------------------

    def verify_signature(
        self, public_key: PublicKeyTypes, signature: bytes, data: bytes
    ) -> None:
        """Verify ``signature`` over ``data`` using ``public_key``.

        The mirror of :meth:`sign_args`, and the reason :mod:`pqpki.validate`
        can check a signature at every link of a chain by hand without ever
        branching on algorithm. Each family needs a differently shaped
        ``verify()`` call -- ECDSA wants an ``ECDSA(hash)`` wrapper, RSA wants
        a padding and a hash, pure ML-DSA wants neither -- and that difference
        lives here and nowhere else.

        Args:
            public_key: The issuer's public key. Must belong to this
                algorithm; a caller should have obtained this spec from
                :func:`spec_for_key` on that very key.
            signature: The raw signature bytes, e.g.
                ``certificate.signature``.
            data: The signed bytes, e.g.
                ``certificate.tbs_certificate_bytes``.

        Raises:
            cryptography.exceptions.InvalidSignature: If the signature does
                not verify. Returns ``None`` on success, following the
                ``pyca`` convention -- a verification routine that returned a
                bool would invite callers to ignore it.
        """
        self._verify(public_key, signature, data)

    # -- key generation ----------------------------------------------------

    def generate_key(
        self, *, collector: Collector | None = None
    ) -> CertificateIssuerPrivateKeyTypes:
        """Generate a fresh private key for this algorithm.

        Args:
            collector: Optional sink for a ``"generate_key"``
                :class:`MetricEvent`. Keyword-only, and omitting it makes this
                match the plain ``generate_key() -> PrivateKeyTypes`` contract.

        Returns:
            A newly generated private key. Key generation cost varies by
            orders of magnitude across the registry -- RSA-2048 is far slower
            and far more variable than either ECDSA or ML-DSA -- which is
            worth knowing when writing tests against it.
        """
        started = time.perf_counter()
        key = self._generate()
        elapsed = time.perf_counter() - started
        _emit(collector, "generate_key", self.name, elapsed, public_key_size(key))
        return key

    def matches_key(self, key: PublicKeyTypes | PrivateKeyTypes) -> bool:
        """True if ``key`` is a key of this algorithm. Private or public."""
        pub = key.public_key() if hasattr(key, "public_key") else key
        return self._identify(pub)


# --------------------------------------------------------------------------
# Identity predicates
# --------------------------------------------------------------------------
#
# A public-key class alone is not enough to pin down an algorithm: every NIST
# curve shares EllipticCurvePublicKey and every modulus size shares
# RSAPublicKey. Each spec therefore carries a predicate specific enough to
# distinguish it from any sibling we might later register.


def _is_ecdsa_p256(pub: Any) -> bool:
    return isinstance(pub, ec.EllipticCurvePublicKey) and isinstance(
        pub.curve, ec.SECP256R1
    )


def _is_rsa_2048(pub: Any) -> bool:
    return isinstance(pub, rsa.RSAPublicKey) and pub.key_size == 2048


def _isinstance_of(cls: type) -> Callable[[Any], bool]:
    def check(pub: Any) -> bool:
        return isinstance(pub, cls)

    return check


# --------------------------------------------------------------------------
# Verification calls
# --------------------------------------------------------------------------
#
# Each family spells verify() differently. Keeping the three shapes here is
# what lets validate.py check every link of a chain with one call.


def _verify_ecdsa(pub: Any, signature: bytes, data: bytes) -> None:
    pub.verify(signature, data, ec.ECDSA(hashes.SHA256()))


def _verify_rsa(pub: Any, signature: bytes, data: bytes) -> None:
    pub.verify(signature, data, padding.PKCS1v15(), hashes.SHA256())


def _verify_pure(pub: Any, signature: bytes, data: bytes) -> None:
    """Pure ML-DSA: no pre-hash, and an empty context string, per RFC 9881."""
    pub.verify(signature, data)


# --------------------------------------------------------------------------
# The registry
# --------------------------------------------------------------------------

DEFAULT_ALGORITHM = "ml-dsa-65"
"""The algorithm to use when a caller expresses no preference.

Post-quantum by default, since demonstrating the PQ path is the point of this
package. It lives here rather than at the call site because the set of
algorithms and the choice of a default are the same concern: renaming or
retiring an algorithm must not leave a dangling default somewhere else in the
tree.
"""

_ML_DSA_44_OID = "2.16.840.1.101.3.4.3.17"
_ML_DSA_65_OID = "2.16.840.1.101.3.4.3.18"
_ML_DSA_87_OID = "2.16.840.1.101.3.4.3.19"

_REGISTRY: dict[str, AlgorithmSpec] = {
    spec.name: spec
    for spec in (
        AlgorithmSpec(
            name="ecdsa-p256",
            is_post_quantum=False,
            oid="1.2.840.10045.4.3.2",  # ecdsa-with-SHA256
            key_oid="1.2.840.10045.2.1",  # id-ecPublicKey
            _generate=lambda: ec.generate_private_key(ec.SECP256R1()),
            _hash_factory=hashes.SHA256,
            _identify=_is_ecdsa_p256,
            _verify=_verify_ecdsa,
        ),
        AlgorithmSpec(
            name="rsa-2048",
            is_post_quantum=False,
            oid="1.2.840.113549.1.1.11",  # sha256WithRSAEncryption
            key_oid="1.2.840.113549.1.1.1",  # rsaEncryption
            _generate=lambda: rsa.generate_private_key(
                public_exponent=65537, key_size=2048
            ),
            _hash_factory=hashes.SHA256,
            _identify=_is_rsa_2048,
            _verify=_verify_rsa,
        ),
        AlgorithmSpec(
            name="ml-dsa-44",
            is_post_quantum=True,
            oid=_ML_DSA_44_OID,
            key_oid=_ML_DSA_44_OID,
            _generate=mldsa.MLDSA44PrivateKey.generate,
            _hash_factory=None,
            _identify=_isinstance_of(mldsa.MLDSA44PublicKey),
            _verify=_verify_pure,
        ),
        AlgorithmSpec(
            name="ml-dsa-65",
            is_post_quantum=True,
            oid=_ML_DSA_65_OID,
            key_oid=_ML_DSA_65_OID,
            _generate=mldsa.MLDSA65PrivateKey.generate,
            _hash_factory=None,
            _identify=_isinstance_of(mldsa.MLDSA65PublicKey),
            _verify=_verify_pure,
        ),
        AlgorithmSpec(
            name="ml-dsa-87",
            is_post_quantum=True,
            oid=_ML_DSA_87_OID,
            key_oid=_ML_DSA_87_OID,
            _generate=mldsa.MLDSA87PrivateKey.generate,
            _hash_factory=None,
            _identify=_isinstance_of(mldsa.MLDSA87PublicKey),
            _verify=_verify_pure,
        ),
    )
}


# --------------------------------------------------------------------------
# Lookup
# --------------------------------------------------------------------------


def get_algorithm(name: str) -> AlgorithmSpec:
    """Return the registered :class:`AlgorithmSpec` called ``name``.

    Raises:
        UnknownAlgorithmError: If ``name`` is not registered. The message
            lists what is.
    """
    try:
        return _REGISTRY[name]
    except KeyError:
        raise UnknownAlgorithmError(name, list_algorithms()) from None


def list_algorithms() -> list[str]:
    """Every registered algorithm name, classical first then post-quantum.

    The test suite parameterizes over this, so registering an algorithm here
    is enough to get it tested on every path.
    """
    return list(_REGISTRY)


def spec_for_key(key: PublicKeyTypes | PrivateKeyTypes) -> AlgorithmSpec:
    """Identify the algorithm of ``key``. Accepts a private or a public key.

    Raises:
        UnsupportedKeyTypeError: If no registered algorithm matches -- an
            Ed25519 key, or an RSA key of an unregistered size.
    """
    pub = key.public_key() if hasattr(key, "public_key") else key
    for spec in _REGISTRY.values():
        if spec._identify(pub):
            return spec
    detail = type(pub).__name__
    if isinstance(pub, rsa.RSAPublicKey):
        detail += f" (key_size={pub.key_size})"
    elif isinstance(pub, ec.EllipticCurvePublicKey):
        detail += f" (curve={pub.curve.name})"
    raise UnsupportedKeyTypeError(
        f"no registered algorithm for key type {detail}; "
        f"registered algorithms are: {', '.join(list_algorithms())}"
    )


def spec_for_certificate(cert: x509.Certificate) -> AlgorithmSpec:
    """Identify the algorithm of the ``cert`` subject public key.

    This is the algorithm the certificate *subject* signs with -- so for a CA
    certificate, the algorithm it will issue with. It is deliberately not the
    algorithm that signed ``cert``; for that, see
    :func:`spec_for_signature_oid`, and note that in a cross-signed or
    transitional hierarchy the two genuinely differ.
    """
    return spec_for_key(cert.public_key())


def spec_for_signature_oid(oid: str) -> AlgorithmSpec:
    """Identify the algorithm from a signature ``AlgorithmIdentifier`` OID.

    Used to check that a certificate outer ``signatureAlgorithm`` names an
    algorithm we recognise, and that it agrees with the issuer key.

    Resolution is registry-scoped and returns the first match, which matters
    because a signature OID is not always unique: ``ecdsa-with-SHA256`` names
    the hash and the signature family but not the curve, so every NIST curve
    would share it. With one EC curve registered this is unambiguous. If a
    second is ever added, callers needing the curve must go through
    :func:`spec_for_key` on the issuer public key instead.

    Raises:
        UnsupportedKeyTypeError: If no registered algorithm uses ``oid``.
    """
    for spec in _REGISTRY.values():
        if spec.oid == oid:
            return spec
    raise UnsupportedKeyTypeError(
        f"no registered algorithm for signature OID {oid!r}; registered OIDs are: "
        + ", ".join(f"{s.name}={s.oid}" for s in _REGISTRY.values())
    )
