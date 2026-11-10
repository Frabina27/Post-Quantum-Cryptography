"""Two additions to existing modules: raw data signing, and certificate profiles.

``AlgorithmSpec.sign_data`` is a third signing shape. The package already had
two -- ``sign_args()`` for the ``pyca`` builders, which assemble the call
themselves, and ``verify_signature()`` for checking arbitrary bytes. Signing
arbitrary bytes needed its own seam, because the builders silently choose RSA's
padding and nothing was choosing it for a bare ``key.sign()``.

The invariant worth stating: ``sign_data`` and ``verify_signature`` must be
exact inverses for every algorithm. If they drift -- different padding,
different hash -- signatures stop round-tripping, and the failure would show up
only in whatever used them. So they are tested together, per algorithm.

``extended_key_usage`` on ``issue_end_entity`` is the smaller change: a
certificate should say what it is for, and before this every leaf claimed
server authentication whatever it was really for.
"""

from __future__ import annotations

import pytest
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.x509.oid import ExtendedKeyUsageOID

from pqpki import generate_csr
from pqpki.algorithms import get_algorithm, spec_for_key
from pqpki.errors import IssuanceError

MESSAGE = b"the bytes that were signed"


# --------------------------------------------------------------------------
# sign_data / verify_signature are inverses, for every algorithm
# --------------------------------------------------------------------------


def test_sign_data_round_trips(algorithm) -> None:
    spec = get_algorithm(algorithm)
    key = spec.generate_key()
    signature = spec.sign_data(key, MESSAGE)
    spec.verify_signature(key.public_key(), signature, MESSAGE)


def test_sign_data_rejects_altered_data(algorithm) -> None:
    spec = get_algorithm(algorithm)
    key = spec.generate_key()
    signature = spec.sign_data(key, MESSAGE)
    with pytest.raises(InvalidSignature):
        spec.verify_signature(key.public_key(), signature, MESSAGE + b"!")


def test_sign_data_rejects_a_flipped_signature_bit(algorithm) -> None:
    spec = get_algorithm(algorithm)
    key = spec.generate_key()
    signature = bytearray(spec.sign_data(key, MESSAGE))
    signature[0] ^= 0x01
    with pytest.raises(InvalidSignature):
        spec.verify_signature(key.public_key(), bytes(signature), MESSAGE)


def test_sign_data_rejects_another_keys_signature(algorithm) -> None:
    spec = get_algorithm(algorithm)
    signer = spec.generate_key()
    stranger = spec.generate_key()
    signature = spec.sign_data(signer, MESSAGE)
    with pytest.raises(InvalidSignature):
        spec.verify_signature(stranger.public_key(), signature, MESSAGE)


def test_sign_data_handles_empty_input(algorithm) -> None:
    """Zero bytes is a legitimate message, not a missing one."""
    spec = get_algorithm(algorithm)
    key = spec.generate_key()
    spec.verify_signature(key.public_key(), spec.sign_data(key, b""), b"")


def test_sign_data_handles_large_input(algorithm) -> None:
    spec = get_algorithm(algorithm)
    key = spec.generate_key()
    payload = b"x" * 1_000_000
    spec.verify_signature(key.public_key(), spec.sign_data(key, payload), payload)


def test_signature_length_matches_the_certificate_signature(hierarchy) -> None:
    """The same primitive signs data and certificates, so sizes should agree.

    ECDSA is excluded from an exact comparison: its signature is a DER pair of
    integers whose length varies by a byte or two with the values, so the
    assertion is a range rather than equality.
    """
    spec = hierarchy.spec
    signature = spec.sign_data(hierarchy.leaf_key, MESSAGE)
    certificate_signature = len(hierarchy.leaf.signature)
    assert abs(len(signature) - certificate_signature) <= 2


def test_sign_data_is_reachable_through_spec_for_key(algorithm) -> None:
    """A caller holding only a key can find the right spec and sign with it."""
    key = get_algorithm(algorithm).generate_key()
    spec = spec_for_key(key)
    spec.verify_signature(key.public_key(), spec.sign_data(key, MESSAGE), MESSAGE)


def test_post_quantum_signatures_are_larger_than_classical() -> None:
    sizes = {}
    for name in ("ecdsa-p256", "rsa-2048", "ml-dsa-44", "ml-dsa-87"):
        spec = get_algorithm(name)
        sizes[name] = len(spec.sign_data(spec.generate_key(), MESSAGE))

    assert sizes["ml-dsa-44"] > sizes["rsa-2048"] > sizes["ecdsa-p256"]
    assert sizes["ml-dsa-87"] > sizes["ml-dsa-44"]


# --------------------------------------------------------------------------
# Certificate profiles
# --------------------------------------------------------------------------


@pytest.fixture
def leaf_request(fresh_hierarchy):
    """A CSR ready to be issued under the fresh hierarchy's intermediate."""
    key = fresh_hierarchy.spec.generate_key()
    return generate_csr("profile.example", key, san_dns=["profile.example"])


def test_default_purpose_is_server_authentication(fresh_hierarchy, leaf_request) -> None:
    certificate = fresh_hierarchy.intermediate_ca.issue_end_entity(
        leaf_request, validity_days=30
    )
    usage = certificate.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    assert list(usage) == [ExtendedKeyUsageOID.SERVER_AUTH]


@pytest.mark.parametrize(
    "oid",
    [
        ExtendedKeyUsageOID.CLIENT_AUTH,
        ExtendedKeyUsageOID.CODE_SIGNING,
        ExtendedKeyUsageOID.EMAIL_PROTECTION,
        ExtendedKeyUsageOID.TIME_STAMPING,
    ],
)
def test_an_explicit_purpose_is_honoured(fresh_hierarchy, leaf_request, oid) -> None:
    certificate = fresh_hierarchy.intermediate_ca.issue_end_entity(
        leaf_request, validity_days=30, extended_key_usage=[oid]
    )
    usage = certificate.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    assert list(usage) == [oid]


def test_several_purposes_can_be_set(fresh_hierarchy, leaf_request) -> None:
    purposes = [ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]
    certificate = fresh_hierarchy.intermediate_ca.issue_end_entity(
        leaf_request, validity_days=30, extended_key_usage=purposes
    )
    usage = certificate.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    assert list(usage) == purposes


def test_an_empty_purpose_list_is_refused(fresh_hierarchy, leaf_request) -> None:
    """An empty ExtendedKeyUsage permits nothing, so the certificate is useless."""
    with pytest.raises(IssuanceError, match="empty"):
        fresh_hierarchy.intermediate_ca.issue_end_entity(
            leaf_request, validity_days=30, extended_key_usage=[]
        )


def test_extended_key_usage_is_not_critical(fresh_hierarchy, leaf_request) -> None:
    certificate = fresh_hierarchy.intermediate_ca.issue_end_entity(
        leaf_request, validity_days=30, extended_key_usage=[ExtendedKeyUsageOID.CODE_SIGNING]
    )
    assert not certificate.extensions.get_extension_for_class(
        x509.ExtendedKeyUsage
    ).critical


def test_a_profiled_certificate_still_validates(fresh_hierarchy, leaf_request) -> None:
    """Changing the purpose must not change whether the chain is trusted."""
    from pqpki import validate_chain

    certificate = fresh_hierarchy.intermediate_ca.issue_end_entity(
        leaf_request,
        validity_days=30,
        extended_key_usage=[ExtendedKeyUsageOID.CLIENT_AUTH],
    )
    result = validate_chain(
        certificate, [fresh_hierarchy.intermediate], [fresh_hierarchy.root]
    )
    assert result.valid, result.failures


def test_purpose_is_keyword_only(fresh_hierarchy, leaf_request) -> None:
    """Positional would be mistaken for san_dns, which is the argument before it."""
    with pytest.raises(TypeError):
        fresh_hierarchy.intermediate_ca.issue_end_entity(
            leaf_request, 30, ["profile.example"], [ExtendedKeyUsageOID.CLIENT_AUTH]
        )
