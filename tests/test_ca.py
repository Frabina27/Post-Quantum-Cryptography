"""Tests for the certificate authority.

Parameterized over every registered algorithm. The same assertions run against
a classical and a post-quantum hierarchy, which is the property Phase 3 checks
explicitly.
"""

from __future__ import annotations

import os
import stat

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from pqpki import CertificateAuthority, generate_csr
from pqpki.algorithms import MetricEvent, get_algorithm
from pqpki.ca import CERT_FILENAME, KEY_DIRNAME, KEY_FILENAME
from pqpki.errors import CAStateError, IssuanceError, UnknownAlgorithmError

from conftest import LEAF_DNS_NAME, Hierarchy, build_hierarchy


def _basic_constraints(cert: x509.Certificate) -> x509.Extension:
    return cert.extensions.get_extension_for_class(x509.BasicConstraints)


def _key_usage(cert: x509.Certificate) -> x509.Extension:
    return cert.extensions.get_extension_for_class(x509.KeyUsage)


# --------------------------------------------------------------------------
# Root creation
# --------------------------------------------------------------------------


def test_root_is_self_signed(hierarchy: Hierarchy) -> None:
    root = hierarchy.root
    assert root.subject == root.issuer
    # Not just name equality: the signature must actually verify against its
    # own key, which is what makes it a trust anchor rather than a claim.
    root.verify_directly_issued_by(root)


def test_root_basic_constraints(hierarchy: Hierarchy) -> None:
    ext = _basic_constraints(hierarchy.root)
    assert ext.critical is True
    assert ext.value.ca is True
    # Unconstrained by default, as real roots normally are.
    assert ext.value.path_length is None


def test_root_key_usage(hierarchy: Hierarchy) -> None:
    ext = _key_usage(hierarchy.root)
    assert ext.critical is True
    assert ext.value.key_cert_sign is True
    assert ext.value.crl_sign is True
    assert ext.value.digital_signature is False


def test_root_has_subject_key_identifier(hierarchy: Hierarchy) -> None:
    ski = hierarchy.root.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
    assert ski.value.digest


def test_root_has_no_authority_key_identifier(hierarchy: Hierarchy) -> None:
    """A self-signed root's AKI would only point back at itself."""
    with pytest.raises(x509.ExtensionNotFound):
        hierarchy.root.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier)


def test_root_uses_the_requested_algorithm(hierarchy: Hierarchy) -> None:
    spec = get_algorithm(hierarchy.algorithm)
    assert hierarchy.root_ca.algorithm is spec
    assert hierarchy.root.signature_algorithm_oid.dotted_string == spec.oid


def test_create_root_rejects_unknown_algorithm() -> None:
    with pytest.raises(UnknownAlgorithmError):
        CertificateAuthority.create_root("Bad Root", "ml-dsa-1024")


def test_root_path_length_is_configurable(algorithm: str) -> None:
    ca = CertificateAuthority.create_root("Constrained", algorithm, path_length=1)
    assert _basic_constraints(ca.certificate).value.path_length == 1


# --------------------------------------------------------------------------
# Serial numbers
# --------------------------------------------------------------------------


def test_serial_numbers_are_random_not_sequential(hierarchy: Hierarchy) -> None:
    """Predictable serials enable collision attacks against weak hashes."""
    serials = {hierarchy.root.serial_number, hierarchy.intermediate.serial_number,
               hierarchy.leaf.serial_number}
    assert len(serials) == 3
    for serial in serials:
        assert serial > 0
        # x509.random_serial_number() draws 20 bytes and clears the top bit.
        # Anything small enough to be a counter is a red flag.
        assert serial.bit_length() > 64


def test_repeated_issuance_produces_distinct_serials(hierarchy: Hierarchy) -> None:
    key = hierarchy.spec.generate_key()
    csr = generate_csr("repeat.example", key, san_dns=["repeat.example"])
    serials = {
        hierarchy.intermediate_ca.issue_end_entity(csr, validity_days=30).serial_number
        for _ in range(5)
    }
    assert len(serials) == 5


# --------------------------------------------------------------------------
# Intermediate issuance
# --------------------------------------------------------------------------


def test_intermediate_chains_to_root(hierarchy: Hierarchy) -> None:
    assert hierarchy.intermediate.issuer == hierarchy.root.subject
    hierarchy.intermediate.verify_directly_issued_by(hierarchy.root)


def test_intermediate_basic_constraints(hierarchy: Hierarchy) -> None:
    ext = _basic_constraints(hierarchy.intermediate)
    assert ext.critical is True
    assert ext.value.ca is True
    # Default 0: may issue end entities, but no further CAs.
    assert ext.value.path_length == 0


def test_intermediate_key_usage(hierarchy: Hierarchy) -> None:
    ext = _key_usage(hierarchy.intermediate)
    assert ext.critical is True
    assert ext.value.key_cert_sign is True
    assert ext.value.crl_sign is True


def test_intermediate_authority_key_identifier_matches_root_ski(
    hierarchy: Hierarchy,
) -> None:
    """AKI and the issuer's SKI must agree, or path building breaks."""
    aki = hierarchy.intermediate.extensions.get_extension_for_class(
        x509.AuthorityKeyIdentifier
    )
    ski = hierarchy.root.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
    assert aki.value.key_identifier == ski.value.digest


def test_intermediate_has_its_own_ski(hierarchy: Hierarchy) -> None:
    ski = hierarchy.intermediate.extensions.get_extension_for_class(
        x509.SubjectKeyIdentifier
    )
    root_ski = hierarchy.root.extensions.get_extension_for_class(
        x509.SubjectKeyIdentifier
    )
    assert ski.value.digest != root_ski.value.digest


def test_path_length_zero_ca_cannot_issue_an_intermediate(
    hierarchy: Hierarchy,
) -> None:
    """The intermediate defaults to path_length 0, so it must refuse."""
    key = hierarchy.spec.generate_key()
    csr = generate_csr("grandchild.example", key)
    with pytest.raises(IssuanceError, match="path length of 0"):
        hierarchy.intermediate_ca.issue_intermediate(csr, validity_days=365)


def test_requested_path_length_must_fit_within_the_issuers(algorithm: str) -> None:
    """A subordinate CA may have at most issuer_pathlen - 1."""
    root = CertificateAuthority.create_root("PL Root", algorithm, path_length=1)
    key = root.algorithm.generate_key()
    csr = generate_csr("toolong.example", key)
    with pytest.raises(IssuanceError, match="at most 0"):
        root.issue_intermediate(csr, validity_days=365, path_length=1)
    # ...but 0 is fine.
    assert root.issue_intermediate(csr, validity_days=365, path_length=0)


def test_negative_path_length_is_rejected(hierarchy: Hierarchy) -> None:
    key = hierarchy.spec.generate_key()
    csr = generate_csr("negative.example", key)
    with pytest.raises(IssuanceError, match="non-negative"):
        hierarchy.root_ca.issue_intermediate(csr, validity_days=365, path_length=-1)


# --------------------------------------------------------------------------
# End-entity issuance
# --------------------------------------------------------------------------


def test_leaf_chains_to_intermediate(hierarchy: Hierarchy) -> None:
    assert hierarchy.leaf.issuer == hierarchy.intermediate.subject
    hierarchy.leaf.verify_directly_issued_by(hierarchy.intermediate)


def test_full_chain_verifies_link_by_link(hierarchy: Hierarchy) -> None:
    """The whole point of Phase 2: a real three-link chain."""
    hierarchy.leaf.verify_directly_issued_by(hierarchy.intermediate)
    hierarchy.intermediate.verify_directly_issued_by(hierarchy.root)
    hierarchy.root.verify_directly_issued_by(hierarchy.root)


def test_leaf_basic_constraints_is_not_a_ca(hierarchy: Hierarchy) -> None:
    ext = _basic_constraints(hierarchy.leaf)
    assert ext.critical is True
    assert ext.value.ca is False


def test_leaf_key_usage(hierarchy: Hierarchy) -> None:
    ext = _key_usage(hierarchy.leaf)
    assert ext.critical is True
    assert ext.value.digital_signature is True
    # A leaf that could sign certificates would be an unconstrained CA.
    assert ext.value.key_cert_sign is False


def test_leaf_subject_alternative_name(hierarchy: Hierarchy) -> None:
    san = hierarchy.leaf.extensions.get_extension_for_class(
        x509.SubjectAlternativeName
    )
    assert san.value.get_values_for_type(x509.DNSName) == [LEAF_DNS_NAME]


def test_leaf_has_authority_key_identifier(hierarchy: Hierarchy) -> None:
    aki = hierarchy.leaf.extensions.get_extension_for_class(
        x509.AuthorityKeyIdentifier
    )
    ski = hierarchy.intermediate.extensions.get_extension_for_class(
        x509.SubjectKeyIdentifier
    )
    assert aki.value.key_identifier == ski.value.digest


def test_san_argument_overrides_the_csr_request(hierarchy: Hierarchy) -> None:
    """The CA decides names; a CSR only asks."""
    key = hierarchy.spec.generate_key()
    csr = generate_csr("override.example", key, san_dns=["requested.example"])
    leaf = hierarchy.intermediate_ca.issue_end_entity(
        csr, validity_days=30, san_dns=["granted.example"]
    )
    san = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    assert san.value.get_values_for_type(x509.DNSName) == ["granted.example"]


def test_san_falls_back_to_the_csr_request(hierarchy: Hierarchy) -> None:
    key = hierarchy.spec.generate_key()
    csr = generate_csr("fallback.example", key, san_dns=["fallback.example"])
    leaf = hierarchy.intermediate_ca.issue_end_entity(csr, validity_days=30)
    san = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    assert san.value.get_values_for_type(x509.DNSName) == ["fallback.example"]


def test_leaf_without_any_san_is_refused(hierarchy: Hierarchy) -> None:
    """Name validation reads the SAN; a leaf without one identifies nothing."""
    key = hierarchy.spec.generate_key()
    csr = generate_csr("nosan.example", key)
    with pytest.raises(IssuanceError, match="SubjectAlternativeName"):
        hierarchy.intermediate_ca.issue_end_entity(csr, validity_days=30)


def test_validity_window_respects_validity_days(hierarchy: Hierarchy) -> None:
    key = hierarchy.spec.generate_key()
    csr = generate_csr("window.example", key, san_dns=["window.example"])
    leaf = hierarchy.intermediate_ca.issue_end_entity(csr, validity_days=45)
    span = leaf.not_valid_after_utc - leaf.not_valid_before_utc
    assert span.days == 45


def test_certificate_is_valid_at_the_moment_it_is_issued(
    hierarchy: Hierarchy,
) -> None:
    """Sub-second rounding must not make a fresh certificate not-yet-valid."""
    import datetime

    key = hierarchy.spec.generate_key()
    csr = generate_csr("now.example", key, san_dns=["now.example"])
    leaf = hierarchy.intermediate_ca.issue_end_entity(csr, validity_days=1)
    now = datetime.datetime.now(datetime.timezone.utc)
    assert leaf.not_valid_before_utc <= now < leaf.not_valid_after_utc


# --------------------------------------------------------------------------
# Proof of possession is enforced at issuance
# --------------------------------------------------------------------------


def test_issuance_refuses_a_csr_that_fails_proof_of_possession(
    hierarchy: Hierarchy,
) -> None:
    """A CSR whose self-signature is broken must never be signed."""
    key = hierarchy.spec.generate_key()
    marker, replacement = "pop-marker-here", b"pop-marker-gone"
    csr = generate_csr(marker, key, san_dns=["pop.example"])

    der = bytearray(csr.public_bytes(serialization.Encoding.DER))
    index = bytes(der).find(marker.encode())
    assert index != -1
    der[index : index + len(replacement)] = replacement
    tampered = x509.load_der_x509_csr(bytes(der))

    with pytest.raises(IssuanceError, match="possession"):
        hierarchy.intermediate_ca.issue_end_entity(tampered, validity_days=30)
    with pytest.raises(IssuanceError, match="possession"):
        hierarchy.root_ca.issue_intermediate(tampered, validity_days=30)


# --------------------------------------------------------------------------
# CA invariants
# --------------------------------------------------------------------------


def test_leaf_cannot_be_used_as_a_ca(hierarchy: Hierarchy) -> None:
    """BasicConstraints CA=FALSE must be refused at construction."""
    with pytest.raises(CAStateError, match="CA=FALSE"):
        CertificateAuthority(hierarchy.leaf, hierarchy.leaf_key)


def test_mismatched_key_and_certificate_are_refused(hierarchy: Hierarchy) -> None:
    other_key = hierarchy.spec.generate_key()
    with pytest.raises(CAStateError, match="does not match"):
        CertificateAuthority(hierarchy.root, other_key)


# --------------------------------------------------------------------------
# Persistence
# --------------------------------------------------------------------------


def test_save_and_load_round_trip(hierarchy: Hierarchy, tmp_path) -> None:
    hierarchy.root_ca.save(tmp_path)

    cert_path = tmp_path / CERT_FILENAME
    key_path = tmp_path / KEY_DIRNAME / KEY_FILENAME
    assert cert_path.is_file()
    assert key_path.is_file()

    reloaded = CertificateAuthority.load(cert_path, key_path)
    assert reloaded.certificate == hierarchy.root_ca.certificate
    assert reloaded.algorithm is hierarchy.root_ca.algorithm

    # A reloaded CA must actually be able to sign.
    key = reloaded.algorithm.generate_key()
    csr = generate_csr("afterload.example", key, san_dns=["afterload.example"])
    issued = reloaded.issue_end_entity(csr, validity_days=30)
    issued.verify_directly_issued_by(reloaded.certificate)


def test_private_key_goes_in_a_keys_subdirectory(
    hierarchy: Hierarchy, tmp_path
) -> None:
    hierarchy.root_ca.save(tmp_path)
    assert (tmp_path / KEY_DIRNAME).is_dir()
    assert (tmp_path / KEY_FILENAME).exists() is False


@pytest.mark.skipif(
    os.name != "posix",
    reason="POSIX permission bits do not map onto Windows ACLs, so chmod "
    "succeeds without restricting access and the assertion would be a lie",
)
def test_private_key_file_mode_is_0600(hierarchy: Hierarchy, tmp_path) -> None:
    hierarchy.root_ca.save(tmp_path)
    mode = stat.S_IMODE((tmp_path / KEY_DIRNAME / KEY_FILENAME).stat().st_mode)
    assert mode == 0o600


def test_load_rejects_a_mismatched_key_file(hierarchy: Hierarchy, tmp_path) -> None:
    hierarchy.root_ca.save(tmp_path)
    # Overwrite the key with a different one of the same algorithm.
    other = hierarchy.spec.generate_key()
    (tmp_path / KEY_DIRNAME / KEY_FILENAME).write_bytes(
        other.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    with pytest.raises(CAStateError, match="does not match"):
        CertificateAuthority.load(
            tmp_path / CERT_FILENAME, tmp_path / KEY_DIRNAME / KEY_FILENAME
        )


def test_load_reports_unreadable_files_clearly(tmp_path) -> None:
    (tmp_path / "junk.crt").write_bytes(b"not a certificate")
    (tmp_path / "junk.key").write_bytes(b"not a key")
    with pytest.raises(CAStateError, match="could not load CA certificate"):
        CertificateAuthority.load(tmp_path / "junk.crt", tmp_path / "junk.key")


# --------------------------------------------------------------------------
# Revocation register and CRLs
# --------------------------------------------------------------------------


def test_crl_is_signed_by_the_ca(fresh_hierarchy: Hierarchy) -> None:
    ca = fresh_hierarchy.intermediate_ca
    crl = ca.publish_crl()
    assert crl.issuer == ca.certificate.subject
    assert crl.is_signature_valid(ca.certificate.public_key())
    assert crl.signature_algorithm_oid.dotted_string == fresh_hierarchy.spec.oid


def test_revoked_serial_appears_in_the_crl(fresh_hierarchy: Hierarchy) -> None:
    ca = fresh_hierarchy.intermediate_ca
    serial = fresh_hierarchy.leaf.serial_number
    ca.revoke(serial, x509.ReasonFlags.key_compromise)

    crl = ca.publish_crl()
    entry = crl.get_revoked_certificate_by_serial_number(serial)
    assert entry is not None
    reason = entry.extensions.get_extension_for_class(x509.CRLReason)
    assert reason.value.reason == x509.ReasonFlags.key_compromise


def test_unrevoked_serial_is_absent_from_the_crl(fresh_hierarchy: Hierarchy) -> None:
    crl = fresh_hierarchy.intermediate_ca.publish_crl()
    assert (
        crl.get_revoked_certificate_by_serial_number(
            fresh_hierarchy.leaf.serial_number
        )
        is None
    )


def test_crl_number_increases_on_each_publish(fresh_hierarchy: Hierarchy) -> None:
    """A relying party uses CRLNumber to reject a replayed older CRL."""
    ca = fresh_hierarchy.intermediate_ca
    numbers = [
        ca.publish_crl().extensions.get_extension_for_class(x509.CRLNumber).value.crl_number
        for _ in range(3)
    ]
    assert numbers == sorted(numbers)
    assert len(set(numbers)) == 3


def test_revoking_twice_keeps_the_original_date(fresh_hierarchy: Hierarchy) -> None:
    ca = fresh_hierarchy.intermediate_ca
    serial = fresh_hierarchy.leaf.serial_number
    ca.revoke(serial, x509.ReasonFlags.key_compromise)
    first = ca.revoked_serials[serial]
    ca.revoke(serial, x509.ReasonFlags.superseded)
    assert ca.revoked_serials[serial] == first


def test_revoked_serials_is_a_copy(fresh_hierarchy: Hierarchy) -> None:
    ca = fresh_hierarchy.intermediate_ca
    ca.revoke(1234, x509.ReasonFlags.unspecified)
    ca.revoked_serials.clear()
    assert 1234 in ca.revoked_serials


def test_crl_validity_window(fresh_hierarchy: Hierarchy) -> None:
    crl = fresh_hierarchy.intermediate_ca.publish_crl(validity_days=3)
    assert (crl.next_update_utc - crl.last_update_utc).days == 3


# --------------------------------------------------------------------------
# Instrumentation
# --------------------------------------------------------------------------


def test_collector_sees_issuance_and_crl_events(algorithm: str) -> None:
    events: list[MetricEvent] = []
    hierarchy = build_hierarchy(algorithm, collector=events.append)
    hierarchy.intermediate_ca.publish_crl()

    operations = [e.operation for e in events]
    assert operations.count("generate_key") == 3
    assert operations.count("issue_intermediate") == 1
    assert operations.count("issue_end_entity") == 1
    assert operations.count("publish_crl") == 1

    for event in events:
        assert event.algorithm == algorithm
        assert event.duration_s >= 0.0
        assert event.artifact_bytes is not None and event.artifact_bytes > 0


def test_issuance_artifact_size_matches_the_der_certificate(algorithm: str) -> None:
    """The size a benchmarking harness reads must be the real artifact size."""
    events: list[MetricEvent] = []
    hierarchy = build_hierarchy(algorithm, collector=events.append)
    issued = [e for e in events if e.operation == "issue_end_entity"]
    (event,) = issued
    assert event.artifact_bytes == len(
        hierarchy.leaf.public_bytes(serialization.Encoding.DER)
    )


def test_collector_is_optional_throughout(hierarchy: Hierarchy) -> None:
    """Every instrumented call must work with no collector attached."""
    key = hierarchy.spec.generate_key()
    csr = generate_csr("nocollector.example", key, san_dns=["nocollector.example"])
    assert hierarchy.intermediate_ca.issue_end_entity(csr, validity_days=30) is not None
    # Note the `is not None`: CertificateRevocationList defines __len__, so a
    # CRL with no revoked certificates is falsy. A bare truthiness assertion
    # here would fail for the wrong reason.
    assert hierarchy.root_ca.publish_crl() is not None
