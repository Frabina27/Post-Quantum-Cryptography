"""Checking certificate revocation status against CRLs.

The CA side of revocation -- the revocation register and CRL issuance -- lives
in :mod:`pqpki.ca`, because that state belongs to the authority. This module is
the relying party's half: given a CRL somebody handed you, decide what it says
about a certificate.

The split matters because the two halves trust different things. A CA knows its
own revocations. A relying party knows nothing until it has verified that the
CRL was signed by the issuer whose certificates it purports to revoke -- which
is the first thing :func:`check_revocation` does, and the reason an unsigned or
wrongly signed CRL is reported as a problem rather than quietly believed.

CRLs here are signed through the same agility layer as certificates, so a
post-quantum CA publishes an ML-DSA-signed CRL and this module verifies it with
no algorithm-specific code.

What this deliberately does not do: no CRL distribution point fetching, no
OCSP, no delta CRLs, and no caching. CRLs arrive as arguments.
"""

from __future__ import annotations

import dataclasses
import datetime

from cryptography import x509
from cryptography.exceptions import InvalidSignature

from .algorithms import spec_for_key
from .errors import UnsupportedKeyTypeError

__all__ = ["RevocationStatus", "crls_from_issuer", "check_revocation"]


@dataclasses.dataclass(frozen=True)
class RevocationStatus:
    """What the supplied CRLs say about one certificate.

    Attributes:
        revoked: True only if a *usable* CRL listed the serial. A CRL that
            failed its signature check never sets this, because an attacker
            who could forge one could otherwise revoke anything.
        reason: The reason code from the CRL entry, when it carried one.
        revoked_at: The revocation date from the CRL entry.
        problems: Human-readable descriptions of anything wrong with the CRLs
            themselves -- a bad signature, an expired CRL. Separate from
            ``revoked`` because "this CRL is untrustworthy" and "this
            certificate is revoked" are different statements.
        checked: True if at least one CRL from the right issuer was usable. If
            False, revocation status is *unknown* rather than good.
    """

    revoked: bool = False
    reason: x509.ReasonFlags | None = None
    revoked_at: datetime.datetime | None = None
    problems: tuple[str, ...] = ()
    checked: bool = False


def crls_from_issuer(
    issuer: x509.Certificate, crls: list[x509.CertificateRevocationList]
) -> list[x509.CertificateRevocationList]:
    """Select the CRLs whose issuer name matches ``issuer``'s subject.

    Name matching only; whether the CRL was really signed by that issuer is a
    separate question, answered by verifying the signature.
    """
    return [crl for crl in crls if crl.issuer == issuer.subject]


def _verify_crl_signature(
    crl: x509.CertificateRevocationList, issuer: x509.Certificate
) -> str | None:
    """Return a problem description, or None if the CRL signature is good."""
    try:
        spec = spec_for_key(issuer.public_key())
    except UnsupportedKeyTypeError as exc:
        return f"CRL issuer key is not a supported algorithm: {exc}"

    try:
        spec.verify_signature(
            issuer.public_key(), crl.signature, crl.tbs_certlist_bytes
        )
    except InvalidSignature:
        return (
            f"CRL claiming to be issued by {issuer.subject.rfc4514_string()} is "
            f"not signed by that issuer key"
        )
    return None


def check_revocation(
    certificate: x509.Certificate,
    issuer: x509.Certificate,
    crls: list[x509.CertificateRevocationList],
    at_time: datetime.datetime,
) -> RevocationStatus:
    """Decide what ``crls`` say about ``certificate``, as issued by ``issuer``.

    Only CRLs issued by ``issuer`` are consulted: a CRL from anyone else has no
    authority over this certificate, however genuine it may be.

    Args:
        certificate: The certificate whose status is in question.
        issuer: The certificate that issued it, supplying the key that must
            have signed any applicable CRL.
        crls: Candidate CRLs. Ones from other issuers are ignored, not treated
            as errors -- a caller normally passes every CRL it has.
        at_time: The moment to evaluate at, used to decide whether a CRL is
            past its ``nextUpdate``.

    Returns:
        A :class:`RevocationStatus`. Note the distinction between
        ``revoked=False, checked=True`` (a good CRL says this certificate is
        fine) and ``revoked=False, checked=False`` (nobody could tell us).
    """
    applicable = crls_from_issuer(issuer, crls)
    if not applicable:
        return RevocationStatus(checked=False)

    problems: list[str] = []
    checked = False
    revoked_entry: x509.RevokedCertificate | None = None

    for crl in applicable:
        problem = _verify_crl_signature(crl, issuer)
        if problem is not None:
            problems.append(problem)
            # An unverified CRL is evidence of nothing, in either direction.
            continue

        # A CRL past its nextUpdate is stale: the issuer has stopped vouching
        # for it, and newer revocations may have happened since. It is not
        # evidence that nothing was revoked.
        if crl.next_update_utc is not None and at_time > crl.next_update_utc:
            problems.append(
                f"CRL from {crl.issuer.rfc4514_string()} expired at "
                f"{crl.next_update_utc.isoformat()}, so revocation status is "
                f"unknown rather than good"
            )
            continue

        checked = True
        entry = crl.get_revoked_certificate_by_serial_number(
            certificate.serial_number
        )
        if entry is not None:
            revoked_entry = entry
            break

    if revoked_entry is None:
        return RevocationStatus(
            revoked=False, problems=tuple(problems), checked=checked
        )

    reason: x509.ReasonFlags | None = None
    try:
        reason = revoked_entry.extensions.get_extension_for_class(
            x509.CRLReason
        ).value.reason
    except x509.ExtensionNotFound:
        # The reason code is optional; absence means unspecified, not invalid.
        reason = None

    return RevocationStatus(
        revoked=True,
        reason=reason,
        revoked_at=revoked_entry.revocation_date_utc,
        problems=tuple(problems),
        checked=True,
    )
