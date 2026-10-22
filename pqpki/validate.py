"""Certification path validation, written by hand.

``cryptography`` ships a perfectly good verifier in
``cryptography.x509.verification``. This module deliberately does not use it.
The point of this package is to make the steps of path validation visible and
to report *which* one failed, and a verifier that answers yes or no cannot do
that. The library's verifier appears in the test suite instead, as an
independent oracle to cross-check these results against.

Checks run in this order, and every one that fails is reported rather than
stopping at the first:

1. **Name chaining** -- each certificate's issuer name equals its issuer's
   subject name, walking from the leaf up to a trust anchor.
2. **Signature** -- verified at every link, plus the anchor's self-signature.
3. **Validity window** -- at every link, against ``at_time``.
4. **Basic constraints** -- ``CA=TRUE``, critical, on every certificate used as
   an issuer. A ``CA=FALSE`` certificate is rejected as an issuer.
5. **Path length** -- an issuer's ``pathLenConstraint`` must accommodate the
   number of intermediate CAs below it.
6. **Key usage** -- ``keyCertSign`` on issuers, ``digitalSignature`` on leaves.
7. **Revocation** -- against any supplied CRLs, via :mod:`pqpki.revocation`.

Accumulating failures rather than short-circuiting is a deliberate choice. A
certificate that is both expired and revoked has two things wrong with it, and
an operator debugging a broken deployment wants both, not whichever the
implementation happened to notice first.

Nothing here names an algorithm: signature checks go through
:meth:`~pqpki.algorithms.AlgorithmSpec.verify_signature`.

What this does not implement, and a real validator must: name constraints,
policy constraints and policy mapping, inhibitAnyPolicy, extended key usage
chaining, or any of RFC 5280 section 6.1's state machine beyond path length.
"""

from __future__ import annotations

import dataclasses
import datetime
import time

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization

from .algorithms import Collector, _emit, spec_for_key
from .errors import UnsupportedKeyTypeError, ValidationInputError
from .revocation import check_revocation

__all__ = ["ValidationResult", "FailureCode", "validate_chain"]

#: A chain longer than this is treated as a loop rather than a hierarchy.
MAX_CHAIN_LENGTH = 16


class FailureCode:
    """Stable names for validation failures.

    Every entry in :attr:`ValidationResult.failures` begins with one of these
    followed by ``": "`` and a human-readable explanation. The code is there so
    callers -- including the security-test harness -- can assert on *why*
    something was rejected without matching on prose.
    """

    NAME_CHAINING = "name-chaining"
    NO_TRUST_ANCHOR = "no-trust-anchor"
    SIGNATURE = "signature"
    SIGNATURE_ALGORITHM_MISMATCH = "signature-algorithm-mismatch"
    EXPIRED = "expired"
    NOT_YET_VALID = "not-yet-valid"
    BASIC_CONSTRAINTS_MISSING = "basic-constraints-missing"
    NOT_A_CA = "not-a-ca"
    BASIC_CONSTRAINTS_NOT_CRITICAL = "basic-constraints-not-critical"
    PATH_LENGTH = "path-length"
    KEY_USAGE_MISSING = "key-usage-missing"
    KEY_USAGE_CERT_SIGN = "key-usage-cert-sign"
    KEY_USAGE_DIGITAL_SIGNATURE = "key-usage-digital-signature"
    REVOKED = "revoked"
    CRL_PROBLEM = "crl-problem"
    UNSUPPORTED_ALGORITHM = "unsupported-algorithm"


@dataclasses.dataclass
class ValidationResult:
    """The outcome of :func:`validate_chain`.

    Attributes:
        valid: True only if ``failures`` is empty.
        chain_length: Number of certificates in the path that was built,
            counting the leaf and the trust anchor. A root -> intermediate ->
            leaf hierarchy gives 3. On a chain that could not be built, this
            is how far the walk got.
        failures: Every reason the chain was rejected, each prefixed with a
            :class:`FailureCode`. Empty if and only if ``valid``.
        algorithms_used: The signature algorithm at each link, positionally
            matching the built chain from leaf to anchor -- entry *i* is the
            algorithm that signed certificate *i*, which is the algorithm of
            certificate *i+1*'s key. The anchor self-signs, so its entry is its
            own algorithm. Supplied for the benchmarking module, which wants to
            know what a mixed or transitional hierarchy actually exercised.
    """

    valid: bool
    chain_length: int
    failures: list[str]
    algorithms_used: list[str]


def _fail(code: str, detail: str) -> str:
    return f"{code}: {detail}"


def _name(cert: x509.Certificate) -> str:
    return cert.subject.rfc4514_string()


def _normalize_time(at_time: datetime.datetime | None) -> datetime.datetime:
    """Coerce ``at_time`` to an aware UTC datetime.

    A naive datetime is interpreted as UTC rather than rejected, because the
    alternative -- comparing a naive value against an aware one -- raises
    ``TypeError`` deep inside a comparison, which is a worse experience than
    an assumption stated in a docstring.
    """
    if at_time is None:
        return datetime.datetime.now(datetime.timezone.utc)
    if at_time.tzinfo is None:
        return at_time.replace(tzinfo=datetime.timezone.utc)
    return at_time.astimezone(datetime.timezone.utc)


def _same_certificate(a: x509.Certificate, b: x509.Certificate) -> bool:
    """Byte-for-byte identity, not merely an equal subject name.

    Compared on the DER rather than a fingerprint so that no hash algorithm
    needs choosing outside the agility layer.
    """
    encoding = serialization.Encoding.DER
    return a.public_bytes(encoding) == b.public_bytes(encoding)


def _is_self_issued(cert: x509.Certificate) -> bool:
    return cert.subject == cert.issuer


# --------------------------------------------------------------------------
# Path building
# --------------------------------------------------------------------------


def _build_path(
    leaf: x509.Certificate,
    intermediates: list[x509.Certificate],
    trust_roots: list[x509.Certificate],
) -> tuple[list[x509.Certificate], list[str]]:
    """Walk from ``leaf`` to a trust anchor by issuer/subject name.

    Returns the path built and any failure that stopped it. The path is
    returned even when incomplete, so the caller can still run per-certificate
    checks on what was found and report everything at once.
    """
    if any(_same_certificate(leaf, root) for root in trust_roots):
        # The leaf is itself a trust anchor. Unusual, but well-defined.
        return [leaf], []

    path = [leaf]
    remaining = list(intermediates)

    while len(path) < MAX_CHAIN_LENGTH:
        current = path[-1]

        anchor = next(
            (root for root in trust_roots if root.subject == current.issuer), None
        )
        if anchor is not None:
            path.append(anchor)
            return path, []

        candidate = next(
            (cert for cert in remaining if cert.subject == current.issuer), None
        )
        if candidate is None:
            if _is_self_issued(current):
                return path, [
                    _fail(
                        FailureCode.NO_TRUST_ANCHOR,
                        f"the chain terminates at self-signed certificate "
                        f"{_name(current)}, which is not among the supplied "
                        f"trust roots",
                    )
                ]
            return path, [
                _fail(
                    FailureCode.NAME_CHAINING,
                    f"no certificate with subject "
                    f"{current.issuer.rfc4514_string()} was supplied, so the "
                    f"chain from {_name(leaf)} does not reach a trust root",
                )
            ]

        remaining.remove(candidate)
        path.append(candidate)

    return path, [
        _fail(
            FailureCode.PATH_LENGTH,
            f"chain exceeded the maximum length of {MAX_CHAIN_LENGTH}, which "
            f"usually means the supplied certificates form a loop",
        )
    ]


# --------------------------------------------------------------------------
# Individual checks
# --------------------------------------------------------------------------


def _check_signature(
    cert: x509.Certificate, issuer: x509.Certificate, failures: list[str]
) -> None:
    """Verify ``cert``'s signature against ``issuer``'s key."""
    try:
        spec = spec_for_key(issuer.public_key())
    except UnsupportedKeyTypeError as exc:
        failures.append(
            _fail(
                FailureCode.UNSUPPORTED_ALGORITHM,
                f"cannot verify {_name(cert)}: issuer {_name(issuer)} uses an "
                f"unsupported key. {exc}",
            )
        )
        return

    # The algorithm named in the certificate must be the one the issuer's key
    # can actually produce. A mismatch means the certificate was assembled
    # from parts.
    if cert.signature_algorithm_oid.dotted_string != spec.oid:
        failures.append(
            _fail(
                FailureCode.SIGNATURE_ALGORITHM_MISMATCH,
                f"{_name(cert)} declares signature algorithm OID "
                f"{cert.signature_algorithm_oid.dotted_string}, but its issuer "
                f"{_name(issuer)} holds a {spec.name} key (OID {spec.oid})",
            )
        )
        return

    try:
        spec.verify_signature(
            issuer.public_key(), cert.signature, cert.tbs_certificate_bytes
        )
    except InvalidSignature:
        failures.append(
            _fail(
                FailureCode.SIGNATURE,
                f"the signature on {_name(cert)} does not verify against the "
                f"public key of its issuer {_name(issuer)}",
            )
        )


def _check_validity(
    cert: x509.Certificate, at_time: datetime.datetime, failures: list[str]
) -> None:
    if at_time < cert.not_valid_before_utc:
        failures.append(
            _fail(
                FailureCode.NOT_YET_VALID,
                f"{_name(cert)} is not valid until "
                f"{cert.not_valid_before_utc.isoformat()}, which is after the "
                f"validation time {at_time.isoformat()}",
            )
        )
    if at_time > cert.not_valid_after_utc:
        failures.append(
            _fail(
                FailureCode.EXPIRED,
                f"{_name(cert)} expired at "
                f"{cert.not_valid_after_utc.isoformat()}, before the validation "
                f"time {at_time.isoformat()}",
            )
        )


def _check_basic_constraints(
    issuer: x509.Certificate, failures: list[str]
) -> x509.BasicConstraints | None:
    """Check that ``issuer`` is entitled to act as a CA. Returns its constraints."""
    try:
        extension = issuer.extensions.get_extension_for_class(x509.BasicConstraints)
    except x509.ExtensionNotFound:
        failures.append(
            _fail(
                FailureCode.BASIC_CONSTRAINTS_MISSING,
                f"{_name(issuer)} is used as an issuer but has no "
                f"BasicConstraints extension, so it never claimed the right to "
                f"sign certificates",
            )
        )
        return None

    if not extension.value.ca:
        failures.append(
            _fail(
                FailureCode.NOT_A_CA,
                f"{_name(issuer)} is used as an issuer but asserts "
                f"BasicConstraints CA=FALSE; an end-entity certificate must "
                f"never sign another certificate",
            )
        )
        return extension.value

    if not extension.critical:
        failures.append(
            _fail(
                FailureCode.BASIC_CONSTRAINTS_NOT_CRITICAL,
                f"{_name(issuer)} carries BasicConstraints as non-critical; "
                f"RFC 5280 requires it to be critical in a CA certificate",
            )
        )

    return extension.value


def _check_path_length(
    issuer: x509.Certificate,
    constraints: x509.BasicConstraints | None,
    intermediates_below: int,
    failures: list[str],
) -> None:
    """Enforce ``pathLenConstraint``.

    ``pathLenConstraint`` caps the number of non-self-issued intermediate CA
    certificates that may follow this one on the path toward the leaf. The
    leaf itself is not an intermediate and does not count.
    """
    if constraints is None or constraints.path_length is None:
        return
    if intermediates_below > constraints.path_length:
        failures.append(
            _fail(
                FailureCode.PATH_LENGTH,
                f"{_name(issuer)} has a path length constraint of "
                f"{constraints.path_length}, but {intermediates_below} "
                f"intermediate CA certificate(s) appear below it in this chain",
            )
        )


def _check_issuer_key_usage(issuer: x509.Certificate, failures: list[str]) -> None:
    try:
        extension = issuer.extensions.get_extension_for_class(x509.KeyUsage)
    except x509.ExtensionNotFound:
        failures.append(
            _fail(
                FailureCode.KEY_USAGE_MISSING,
                f"{_name(issuer)} is used as an issuer but carries no KeyUsage "
                f"extension. RFC 5280 tolerates this, but the certificate "
                f"profile this package issues and validates requires it",
            )
        )
        return

    if not extension.value.key_cert_sign:
        failures.append(
            _fail(
                FailureCode.KEY_USAGE_CERT_SIGN,
                f"{_name(issuer)} is used as an issuer but its KeyUsage does "
                f"not assert keyCertSign, so its key must not be used to sign "
                f"certificates",
            )
        )


def _check_leaf_key_usage(leaf: x509.Certificate, failures: list[str]) -> None:
    try:
        extension = leaf.extensions.get_extension_for_class(x509.KeyUsage)
    except x509.ExtensionNotFound:
        failures.append(
            _fail(
                FailureCode.KEY_USAGE_MISSING,
                f"end-entity certificate {_name(leaf)} carries no KeyUsage "
                f"extension, which the profile this package issues requires",
            )
        )
        return

    if not extension.value.digital_signature:
        failures.append(
            _fail(
                FailureCode.KEY_USAGE_DIGITAL_SIGNATURE,
                f"end-entity certificate {_name(leaf)} does not assert "
                f"digitalSignature in its KeyUsage",
            )
        )


def _check_revocation(
    cert: x509.Certificate,
    issuer: x509.Certificate,
    crls: list[x509.CertificateRevocationList],
    at_time: datetime.datetime,
    failures: list[str],
) -> None:
    status = check_revocation(cert, issuer, crls, at_time)

    for problem in status.problems:
        failures.append(_fail(FailureCode.CRL_PROBLEM, problem))

    if status.revoked:
        reason = status.reason.value if status.reason is not None else "unspecified"
        when = (
            status.revoked_at.isoformat() if status.revoked_at is not None else "an unrecorded time"
        )
        failures.append(
            _fail(
                FailureCode.REVOKED,
                f"{_name(cert)} (serial {cert.serial_number:x}) was revoked at "
                f"{when} with reason {reason}",
            )
        )


# --------------------------------------------------------------------------
# Public entry point
# --------------------------------------------------------------------------


def validate_chain(
    leaf: x509.Certificate,
    intermediates: list[x509.Certificate],
    trust_roots: list[x509.Certificate],
    *,
    at_time: datetime.datetime | None = None,
    crls: list[x509.CertificateRevocationList] | None = None,
    collector: Collector | None = None,
) -> ValidationResult:
    """Validate ``leaf`` up to one of ``trust_roots``.

    Args:
        leaf: The certificate being validated.
        intermediates: Candidate intermediate CA certificates, in any order.
            Extra certificates that turn out not to be on the path are ignored.
        trust_roots: The trust anchors. A chain is valid only if it terminates
            at one of these.
        at_time: The instant to validate as of. Defaults to now. A naive
            datetime is interpreted as UTC.
        crls: CRLs to check revocation against. When ``None``, revocation is
            not checked at all and no failure is reported for it -- the caller
            asked a question that did not include revocation.
        collector: Optional metric sink, keyword-only. Emits one
            ``"validate_chain"`` event with ``artifact_bytes=None``, since
            validation produces no artifact.

    Returns:
        A :class:`ValidationResult` listing every problem found.

    Raises:
        ValidationInputError: If ``trust_roots`` is empty. Validating against
            no trust anchors cannot succeed, and silently returning "invalid"
            would disguise a caller's configuration bug as a bad certificate.
    """
    started = time.perf_counter()

    if not trust_roots:
        raise ValidationInputError(
            "no trust roots supplied; a chain cannot be validated against an "
            "empty set of trust anchors"
        )

    at = _normalize_time(at_time)
    failures: list[str] = []

    path, build_failures = _build_path(leaf, intermediates, trust_roots)
    failures.extend(build_failures)
    anchored = not build_failures

    # 1. Name chaining. Path building matched on names, so this is a defensive
    #    re-check that the path handed to the remaining steps is coherent.
    for lower, upper in zip(path, path[1:]):
        if lower.issuer != upper.subject:
            failures.append(
                _fail(
                    FailureCode.NAME_CHAINING,
                    f"the issuer name of {_name(lower)} does not equal the "
                    f"subject name of {_name(upper)}",
                )
            )

    # 2. Signature at every link, plus the anchor's own self-signature.
    for index, cert in enumerate(path[:-1]):
        _check_signature(cert, path[index + 1], failures)
    if anchored:
        anchor = path[-1]
        if _is_self_issued(anchor):
            _check_signature(anchor, anchor, failures)

    # 3. Validity window, every certificate on the path.
    for cert in path:
        _check_validity(cert, at, failures)

    # 4/5. Basic constraints and path length on every issuer.
    for index, issuer in enumerate(path[1:], start=1):
        constraints = _check_basic_constraints(issuer, failures)
        # Certificates below `issuer` on the path, excluding the leaf itself,
        # are the intermediates its pathLenConstraint governs.
        _check_path_length(issuer, constraints, index - 1, failures)

    # 6. Key usage: issuers sign certificates, leaves sign data.
    for issuer in path[1:]:
        _check_issuer_key_usage(issuer, failures)
    _check_leaf_key_usage(path[0], failures)

    # 7. Revocation, if the caller supplied CRLs to check against.
    if crls is not None:
        for index, cert in enumerate(path[:-1]):
            _check_revocation(cert, path[index + 1], crls, at, failures)

    algorithms_used = _algorithms_along(path)

    elapsed = time.perf_counter() - started
    _emit(
        collector,
        "validate_chain",
        algorithms_used[0] if algorithms_used else "unknown",
        elapsed,
        None,
    )

    return ValidationResult(
        valid=not failures,
        chain_length=len(path),
        failures=failures,
        algorithms_used=algorithms_used,
    )


def _algorithms_along(path: list[x509.Certificate]) -> list[str]:
    """The algorithm that signed each certificate on ``path``.

    Entry *i* is the algorithm of the key that signed certificate *i*, which
    belongs to certificate *i+1*. The anchor signs itself, so its entry is its
    own algorithm. An unrecognised key yields ``"unknown"`` rather than
    raising: this is reporting data for the benchmarking module, and a chain
    that failed validation still deserves a usable answer.
    """
    algorithms: list[str] = []
    for index, _ in enumerate(path):
        issuer = path[index + 1] if index + 1 < len(path) else path[index]
        try:
            algorithms.append(spec_for_key(issuer.public_key()).name)
        except UnsupportedKeyTypeError:
            algorithms.append("unknown")
    return algorithms
