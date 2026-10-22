"""Tests for CSR generation and proof of possession.

Parameterized over every registered algorithm via the ``algorithm`` fixture, so
the classical and post-quantum paths are tested identically.
"""

from __future__ import annotations

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.x509.oid import NameOID

from pqpki import generate_csr, verify_csr_signature
from pqpki.algorithms import get_algorithm
from pqpki.errors import UnsupportedKeyTypeError

TAMPER_MARKER = "tamper-me-please"
TAMPER_REPLACEMENT = b"tampered-already"  # same length, so the DER stays valid


@pytest.fixture(scope="session")
def csr_key(algorithm: str):
    """One key per algorithm per session; CSR generation does not mutate it."""
    return get_algorithm(algorithm).generate_key()


def test_csr_is_signed_and_proves_possession(algorithm: str, csr_key) -> None:
    csr = generate_csr("possession.example", csr_key)
    assert verify_csr_signature(csr) is True
    assert csr.is_signature_valid


def test_csr_subject_common_name(csr_key) -> None:
    csr = generate_csr("subject.example", csr_key)
    (cn,) = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    assert cn.value == "subject.example"


def test_csr_carries_the_requesters_public_key(csr_key) -> None:
    """The CA certifies this key, so it must be the requester's own."""
    csr = generate_csr("pubkey.example", csr_key)
    encoding = serialization.Encoding.DER
    fmt = serialization.PublicFormat.SubjectPublicKeyInfo
    assert csr.public_key().public_bytes(encoding, fmt) == csr_key.public_key().public_bytes(
        encoding, fmt
    )


def test_csr_signature_algorithm_matches_the_key(algorithm: str, csr_key) -> None:
    """The agility layer must pick the signature algorithm from the key."""
    csr = generate_csr("algmatch.example", csr_key)
    assert csr.signature_algorithm_oid.dotted_string == get_algorithm(algorithm).oid


def test_csr_requests_san_when_asked(csr_key) -> None:
    csr = generate_csr("san.example", csr_key, san_dns=["a.example", "b.example"])
    san = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    assert san.value.get_values_for_type(x509.DNSName) == ["a.example", "b.example"]
    assert san.critical is False


def test_csr_omits_san_when_not_asked(csr_key) -> None:
    csr = generate_csr("nosan.example", csr_key)
    with pytest.raises(x509.ExtensionNotFound):
        csr.extensions.get_extension_for_class(x509.SubjectAlternativeName)


def test_empty_san_list_is_treated_as_no_san(csr_key) -> None:
    """An empty SAN extension would be malformed; omitting it is correct."""
    csr = generate_csr("emptysan.example", csr_key, san_dns=[])
    with pytest.raises(x509.ExtensionNotFound):
        csr.extensions.get_extension_for_class(x509.SubjectAlternativeName)


def test_tampered_csr_fails_proof_of_possession(csr_key) -> None:
    """A flipped byte in the signed region must break the self-signature.

    The subject CN sits inside CertificationRequestInfo, which is what the CSR
    signature covers. Replacing it with a same-length string keeps the DER
    structurally valid, so this tests signature verification rather than the
    parser rejecting malformed input.
    """
    csr = generate_csr(TAMPER_MARKER, csr_key, san_dns=["tamper.example"])
    der = bytearray(csr.public_bytes(serialization.Encoding.DER))

    index = bytes(der).find(TAMPER_MARKER.encode())
    assert index != -1, "marker should appear in the DER"
    der[index : index + len(TAMPER_REPLACEMENT)] = TAMPER_REPLACEMENT

    tampered = x509.load_der_x509_csr(bytes(der))

    # It still parses, and the subject really did change...
    (cn,) = tampered.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    assert cn.value == TAMPER_REPLACEMENT.decode()
    # ...but it no longer proves possession of anything.
    assert verify_csr_signature(tampered) is False


def test_verify_returns_false_rather_than_raising_on_garbage(csr_key) -> None:
    """Callers ask this as a question; it must answer, not explode."""

    class Exploding:
        @property
        def is_signature_valid(self) -> bool:
            raise ValueError("unsupported algorithm in this build")

    assert verify_csr_signature(Exploding()) is False  # type: ignore[arg-type]


def test_generate_csr_rejects_unregistered_key_type() -> None:
    with pytest.raises(UnsupportedKeyTypeError):
        generate_csr("ed25519.example", ed25519.Ed25519PrivateKey.generate())


def test_two_csrs_from_one_key_are_both_valid(csr_key) -> None:
    """Signing is deterministic or randomized per algorithm; both must verify."""
    first = generate_csr("first.example", csr_key)
    second = generate_csr("second.example", csr_key)
    assert verify_csr_signature(first)
    assert verify_csr_signature(second)
