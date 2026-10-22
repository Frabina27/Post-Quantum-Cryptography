"""A minimal DER reader, for asserting encoding facts the library hides.

RFC 9881 makes claims about the *bytes* of a certificate -- that an ML-DSA
``AlgorithmIdentifier`` carries no ``parameters`` field at all, rather than an
explicit NULL. ``pyca`` reports both cases as
``signature_algorithm_parameters is None``, so trusting it would mean testing
our belief about the library instead of the encoding. This module reads the DER
directly.

It is a test helper, deliberately not part of the shipped package: it handles
only the definite-length constructs that appear in the structures under test,
and it is not a general-purpose ASN.1 parser.

Relevant grammar (RFC 5280)::

    Certificate ::= SEQUENCE {
        tbsCertificate       TBSCertificate,
        signatureAlgorithm   AlgorithmIdentifier,
        signatureValue       BIT STRING }

    TBSCertificate ::= SEQUENCE {
        version         [0] EXPLICIT Version DEFAULT v1,
        serialNumber        CertificateSerialNumber,
        signature           AlgorithmIdentifier,
        issuer              Name,
        validity            Validity,
        subject             Name,
        subjectPublicKeyInfo SubjectPublicKeyInfo,
        ... }

    AlgorithmIdentifier ::= SEQUENCE {
        algorithm   OBJECT IDENTIFIER,
        parameters  ANY DEFINED BY algorithm OPTIONAL }
"""

from __future__ import annotations

import dataclasses

TAG_SEQUENCE = 0x30
TAG_OID = 0x06
TAG_NULL = 0x05

#: DER for an explicit ASN.1 NULL -- the thing RFC 9881 says must NOT be there.
DER_NULL = b"\x05\x00"


@dataclasses.dataclass(frozen=True)
class TLV:
    """One tag-length-value triple."""

    tag: int
    value: bytes
    raw: bytes
    """The complete encoding including the header, so it can be spliced."""

    @property
    def is_constructed(self) -> bool:
        return bool(self.tag & 0x20)


def parse_tlv(data: bytes, offset: int = 0) -> TLV:
    """Parse one TLV at ``offset``. Definite-length form only."""
    start = offset
    tag = data[offset]
    offset += 1

    first = data[offset]
    offset += 1
    if first & 0x80:
        count = first & 0x7F
        if count == 0:
            raise ValueError("indefinite length is not valid DER")
        length = int.from_bytes(data[offset : offset + count], "big")
        offset += count
    else:
        length = first

    value = data[offset : offset + length]
    if len(value) != length:
        raise ValueError("truncated TLV")
    return TLV(tag=tag, value=value, raw=data[start : offset + length])


def children(tlv: TLV) -> list[TLV]:
    """Parse the direct children of a constructed TLV."""
    if not tlv.is_constructed:
        raise ValueError(f"tag 0x{tlv.tag:02x} is primitive and has no children")
    out: list[TLV] = []
    offset = 0
    while offset < len(tlv.value):
        child = parse_tlv(tlv.value, offset)
        out.append(child)
        offset += len(child.raw)
    return out


def encode_length(length: int) -> bytes:
    """DER length encoding, short form where permitted."""
    if length < 0x80:
        return bytes([length])
    body = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def encode_sequence(content: bytes) -> bytes:
    return bytes([TAG_SEQUENCE]) + encode_length(len(content)) + content


def decode_oid(tlv: TLV) -> str:
    """Decode an OBJECT IDENTIFIER to dotted form."""
    if tlv.tag != TAG_OID:
        raise ValueError(f"expected OBJECT IDENTIFIER, got tag 0x{tlv.tag:02x}")
    data = tlv.value
    first = data[0]
    parts = [str(first // 40), str(first % 40)]
    value = 0
    for byte in data[1:]:
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            parts.append(str(value))
            value = 0
    return ".".join(parts)


# --------------------------------------------------------------------------
# AlgorithmIdentifier
# --------------------------------------------------------------------------


def algorithm_oid(algid: TLV) -> str:
    """The OID out of an AlgorithmIdentifier SEQUENCE."""
    return decode_oid(children(algid)[0])


def has_parameters(algid: TLV) -> bool:
    """True if the AlgorithmIdentifier carries a ``parameters`` field at all.

    This is the RFC 9881 question. An AlgorithmIdentifier with parameters
    absent has exactly one child, the OID. One carrying an explicit NULL has
    two, and is non-conformant for ML-DSA even though NULL is semantically
    empty.
    """
    return len(children(algid)) > 1


def parameters(algid: TLV) -> TLV | None:
    kids = children(algid)
    return kids[1] if len(kids) > 1 else None


# --------------------------------------------------------------------------
# Structure accessors
# --------------------------------------------------------------------------


def _signed_structure(der: bytes) -> tuple[TLV, TLV, TLV]:
    """Split any SIGNED{} structure into (tbs, signatureAlgorithm, signature).

    Certificates, CRLs, and CSRs all share this three-field outer shape, which
    is why one accessor serves all three.
    """
    outer = parse_tlv(der)
    tbs, algid, signature = children(outer)[:3]
    return tbs, algid, signature


def outer_algorithm_identifier(der: bytes) -> TLV:
    """The ``signatureAlgorithm`` sitting beside the signed body."""
    return _signed_structure(der)[1]


def tbs_algorithm_identifier(der: bytes) -> TLV:
    """The ``signature`` AlgorithmIdentifier *inside* the signed body.

    For a certificate this is ``TBSCertificate.signature``; RFC 5280 requires
    it to equal the outer ``signatureAlgorithm``. Because it is inside the
    signed region and the outer one is not, a mismatch is the signature of a
    tampering attempt rather than a formatting quirk.

    Applies to certificates and CRLs, whose signed bodies both begin with an
    optional version followed by this field. A **CSR has no equivalent**:
    ``CertificationRequestInfo`` carries no inner algorithm identifier, so
    calling this on one returns the subject ``Name`` instead. There is nothing
    to cross-check on a CSR.
    """
    tbs = _signed_structure(der)[0]
    for child in children(tbs):
        # Skip the optional [0] EXPLICIT version and the serial INTEGER; the
        # first SEQUENCE in a TBSCertificate is the signature AlgorithmIdentifier.
        if child.tag == TAG_SEQUENCE:
            return child
    raise ValueError("no AlgorithmIdentifier found in the signed body")


def subject_public_key_algorithm_identifier(der: bytes) -> TLV:
    """The AlgorithmIdentifier inside ``SubjectPublicKeyInfo``.

    RFC 9881 requires absent parameters here too, not only on the signature.
    """
    tbs = _signed_structure(der)[0]
    sequences = [c for c in children(tbs) if c.tag == TAG_SEQUENCE]
    # In a TBSCertificate the SEQUENCEs are, in order: signature, issuer,
    # validity, subject, subjectPublicKeyInfo.
    spki = sequences[4]
    return children(spki)[0]


def csr_subject_public_key_algorithm_identifier(der: bytes) -> TLV:
    """The SPKI AlgorithmIdentifier inside a ``CertificationRequestInfo``.

    Separate from the certificate accessor because the field order differs:
    a CertificationRequestInfo is version, subject, subjectPKInfo, attributes,
    so the SPKI is the second SEQUENCE rather than the fifth.
    """
    info = _signed_structure(der)[0]
    sequences = [c for c in children(info) if c.tag == TAG_SEQUENCE]
    return children(sequences[1])[0]


def splice_signature_value(der: bytes, donor_der: bytes) -> bytes:
    """Return ``der`` carrying the signature value lifted from ``donor_der``.

    Builds the "signature swapped in from another certificate" case. The outer
    SEQUENCE is re-encoded because the two signatures need not be the same
    length, so this cannot be done by overwriting bytes in place.
    """
    tbs, algid, _ = _signed_structure(der)
    donor_signature = _signed_structure(donor_der)[2]
    return encode_sequence(tbs.raw + algid.raw + donor_signature.raw)


def flip_bytes(der: bytes, marker: bytes, replacement: bytes) -> bytes:
    """Replace ``marker`` with ``replacement`` in place, lengths unchanged.

    Used to corrupt a byte inside the signed region. Because the replacement
    is the same length, every enclosing DER length stays correct and the
    result still parses -- so what the test exercises is signature
    verification, not the parser rejecting malformed input.
    """
    if len(marker) != len(replacement):
        raise ValueError("replacement must be the same length as the marker")
    index = der.find(marker)
    if index == -1:
        raise ValueError(f"marker {marker!r} not found in the encoding")
    return der[:index] + replacement + der[index + len(marker) :]


def splice_outer_parameters(der: bytes, injected: bytes = DER_NULL) -> bytes:
    """Return ``der`` with ``injected`` added to the outer AlgorithmIdentifier.

    Used to build the negative test for an AlgorithmIdentifier carrying NULL
    parameters. Only the *outer* identifier is modified, because it lies
    outside the signed region: the result is still a structurally valid
    encoding whose signature over the body remains intact, which is exactly
    the case a validator has to catch on its own rather than getting for free
    from a failed signature check.
    """
    outer = parse_tlv(der)
    tbs, algid, signature = children(outer)[:3]

    oid = children(algid)[0]
    tampered_algid = encode_sequence(oid.raw + injected)

    return encode_sequence(tbs.raw + tampered_algid + signature.raw)
