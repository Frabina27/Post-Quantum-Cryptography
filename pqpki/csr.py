"""Certificate signing requests and proof of possession.

A CSR carries a subject name and a public key, and is signed by the *private*
key matching that public key. That self-signature is the whole point: it is the
requester's proof that it actually holds the private half of the key it is
asking a CA to certify. Without it, anyone could ask a CA to bind someone
else's public key to a name they control.

This module never names an algorithm. Which signature algorithm a CSR uses is
whatever the supplied private key implies, resolved through
:mod:`pqpki.algorithms`, so a caller who hands in an ML-DSA key gets an ML-DSA
CSR by the same code path as an ECDSA one.
"""

from __future__ import annotations

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.types import (
    CertificateIssuerPrivateKeyTypes,
)
from cryptography.x509.oid import NameOID

from .algorithms import spec_for_key

__all__ = ["generate_csr", "verify_csr_signature"]


def generate_csr(
    common_name: str,
    private_key: CertificateIssuerPrivateKeyTypes,
    san_dns: list[str] | None = None,
) -> x509.CertificateSigningRequest:
    """Build a CSR for ``common_name``, signed by ``private_key``.

    The signature algorithm is derived from the key, not chosen by the caller.
    That is the agility layer doing its job: this function has no idea whether
    it just produced a classical or a post-quantum request.

    Args:
        common_name: The subject common name. For an end entity this is
            conventionally the hostname, but the name that actually gets
            validated is the SAN -- see :func:`pqpki.ca.CertificateAuthority.
            issue_end_entity`.
        private_key: The requester's private key. Its public half goes into
            the CSR, and it signs the request to prove possession.
        san_dns: Optional DNS names to request in a ``SubjectAlternativeName``
            extension. A CA is free to ignore or override what a CSR requests;
            this is a request, not an instruction.

    Returns:
        A signed CSR whose ``is_signature_valid`` is true.

    Raises:
        UnsupportedKeyTypeError: If ``private_key`` is not a registered
            algorithm's key type.
    """
    spec = spec_for_key(private_key)

    builder = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    )

    if san_dns:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(name) for name in san_dns]),
            critical=False,
        )

    return builder.sign(private_key, *spec.sign_args())


def verify_csr_signature(csr: x509.CertificateSigningRequest) -> bool:
    """Verify a CSR's self-signature -- its proof of possession.

    Returns ``True`` only if the signature verifies against the public key
    carried inside the CSR itself, meaning the requester demonstrably holds
    the matching private key.

    This returns a bool rather than raising because callers ask it as a
    question. :mod:`pqpki.ca` is the one that turns a ``False`` here into a
    refusal to issue.

    Note what this does *not* establish: possession proves the requester owns
    the key, not that it is entitled to the name in the subject. Binding a name
    to a key is an authorization decision, and a real CA makes it out of band
    -- domain control validation, an enrollment secret, an operator's
    judgement. This package has no opinion on it, which is one of the several
    reasons it is not a production CA.
    """
    try:
        return bool(csr.is_signature_valid)
    except Exception:
        # A CSR carrying an algorithm this build cannot verify, or a structure
        # that fails to parse on access, is not a valid proof of possession.
        # It is emphatically not a reason to crash the caller.
        return False
