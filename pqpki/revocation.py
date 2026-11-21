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

Delta CRLs are understood, and the rule governing them is the interesting part.
A delta CRL lists only what changed since a specific complete CRL, identified
by the ``DeltaCRLIndicator`` extension it carries. So a delta is never evidence
on its own: reading one as though it were complete would make every serial that
appears only in the base look unrevoked, which is strictly worse than having no
CRL at all. This module therefore applies a delta only once it has the base
CRL whose number the delta names, and reports an unmatched delta as a problem
rather than using it.

What this deliberately does not do: no CRL distribution point *fetching* (the
URLs in a certificate are published by :mod:`pqpki.ca` and read by whoever
holds the certificate, not dereferenced here), no OCSP, and no caching. CRLs
arrive as arguments.
"""

from __future__ import annotations

import dataclasses
import datetime

from cryptography import x509
from cryptography.exceptions import InvalidSignature

from .algorithms import spec_for_key
from .errors import UnsupportedKeyTypeError

__all__ = [
    "RevocationStatus",
    "crls_from_issuer",
    "check_revocation",
    "is_delta_crl",
    "crl_number",
    "delta_base_number",
]


def is_delta_crl(crl: x509.CertificateRevocationList) -> bool:
    """True if ``crl`` is a delta CRL rather than a complete one."""
    return delta_base_number(crl) is not None


def crl_number(crl: x509.CertificateRevocationList) -> int | None:
    """The CRLNumber extension value, or None if the CRL carries none.

    RFC 5280 requires a conforming CA to include it, but a CRL without one is
    still parseable, so this reports its absence instead of raising.
    """
    try:
        return crl.extensions.get_extension_for_class(x509.CRLNumber).value.crl_number
    except x509.ExtensionNotFound:
        return None


def delta_base_number(crl: x509.CertificateRevocationList) -> int | None:
    """The base CRLNumber a delta CRL is relative to, or None if not a delta."""
    try:
        extension = crl.extensions.get_extension_for_class(x509.DeltaCRLIndicator)
    except x509.ExtensionNotFound:
        return None
    return extension.value.crl_number


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
        checked: True if at least one *complete* CRL from the right issuer was
            usable. If False, revocation status is *unknown* rather than good.
            A delta CRL never sets this on its own, however well formed: it
            reports changes since a base, so it cannot testify that a serial
            absent from it was never revoked.
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

    usable: list[x509.CertificateRevocationList] = []
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

        usable.append(crl)

    complete = [c for c in usable if not is_delta_crl(c)]
    deltas = [c for c in usable if is_delta_crl(c)]

    # A delta is only usable on top of the base it names. Collect the numbers
    # of the complete CRLs we actually verified, so an orphan delta -- one
    # whose base we were not given -- is reported rather than applied.
    available_bases = {
        number for number in (crl_number(c) for c in complete) if number is not None
    }
    applicable_deltas: list[x509.CertificateRevocationList] = []
    for delta in deltas:
        base = delta_base_number(delta)
        if base in available_bases:
            applicable_deltas.append(delta)
        else:
            problems.append(
                f"delta CRL from {delta.issuer.rfc4514_string()} is relative to "
                f"base CRLNumber {base}, which was not supplied; a delta CRL "
                f"cannot be applied without its base, and must not be read as "
                f"a complete CRL"
            )

    if complete:
        # Only a complete CRL can establish that a certificate is *not*
        # revoked. Deltas refine that answer; they never stand in for it.
        checked = True

    # Complete CRLs first, then deltas, because a delta's entry for a serial
    # supersedes the base's: that is what makes it an update. The one case
    # where the delta's entry is not a revocation is reason `removeFromCRL`,
    # which withdraws an earlier revocation -- used when a certificate was put
    # on hold and then released. Taking the last entry found and then checking
    # for that reason handles both directions.
    for crl in complete + applicable_deltas:
        entry = crl.get_revoked_certificate_by_serial_number(
            certificate.serial_number
        )
        if entry is not None:
            revoked_entry = entry

    if revoked_entry is not None and _entry_reason(revoked_entry) is (
        x509.ReasonFlags.remove_from_crl
    ):
        return RevocationStatus(
            revoked=False, problems=tuple(problems), checked=checked
        )

    if revoked_entry is None:
        return RevocationStatus(
            revoked=False, problems=tuple(problems), checked=checked
        )

    return RevocationStatus(
        revoked=True,
        reason=_entry_reason(revoked_entry),
        revoked_at=revoked_entry.revocation_date_utc,
        problems=tuple(problems),
        checked=True,
    )


def _entry_reason(entry: x509.RevokedCertificate) -> x509.ReasonFlags | None:
    """The CRLReason on a revocation entry, or None if it carried none.

    The reason code is optional: its absence means unspecified, not invalid.
    """
    try:
        return entry.extensions.get_extension_for_class(x509.CRLReason).value.reason
    except x509.ExtensionNotFound:
        return None
