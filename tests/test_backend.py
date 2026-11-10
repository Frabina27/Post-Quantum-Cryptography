"""The file-backed store a terminal UI drives.

These tests stand in for the front end: each one does what a menu selection
would do and checks that the result is what the UI would then display. The
cross-cutting claim is that the same sequence of menu actions produces a
working hierarchy whether the algorithm chosen is classical or post-quantum,
which is tested by parameterizing over every registered algorithm.

Most tests use one fast algorithm, because what is under test is the store's
bookkeeping rather than the cryptography; the ones that genuinely depend on the
algorithm say so by taking the ``algorithm`` fixture.
"""

from __future__ import annotations

import pytest
from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID

from pqpki.backend import (
    CertificateProfile,
    PKIStore,
    available_algorithms,
)
from pqpki.errors import CAStateError, CSRError, ValidationInputError

FAST_ALGORITHM = "ecdsa-p256"
CRL_URL = "http://crl.store.example/latest.crl"
DELTA_URL = "http://crl.store.example/delta.crl"
PASSPHRASE = "store passphrase"


@pytest.fixture
def store(tmp_path) -> PKIStore:
    """An empty store, as the UI would create on first run."""
    return PKIStore(
        tmp_path / "pki",
        passphrase=PASSPHRASE,
        crl_url=CRL_URL,
        delta_crl_url=DELTA_URL,
    )


@pytest.fixture
def populated(store) -> PKIStore:
    """A store with a root and an intermediate, as after CA setup."""
    store.create_root("Store Root", FAST_ALGORITHM)
    store.create_intermediate("Store Intermediate")
    return store


# --------------------------------------------------------------------------
# What the UI offers
# --------------------------------------------------------------------------


def test_available_algorithms_includes_classical_and_post_quantum() -> None:
    names = available_algorithms()
    assert any(not n.startswith("ml-dsa") for n in names)
    assert any(n.startswith("ml-dsa") for n in names)


def test_profile_names_are_the_three_the_menu_offers() -> None:
    assert set(CertificateProfile.names()) == {"server", "client", "code-signing"}


def test_unknown_profile_is_refused() -> None:
    with pytest.raises(ValidationInputError, match="unknown certificate profile"):
        CertificateProfile.purposes("nonsense")


# --------------------------------------------------------------------------
# CA management
# --------------------------------------------------------------------------


def test_new_store_has_no_ca(store) -> None:
    assert not store.has_root()
    assert not store.has_intermediate()


def test_create_root_persists_it(store) -> None:
    certificate = store.create_root("Store Root", FAST_ALGORITHM)
    assert store.has_root()
    assert store.load_root().certificate == certificate


def test_create_root_twice_is_refused(store) -> None:
    """Overwriting a root orphans everything issued under it."""
    store.create_root("Store Root", FAST_ALGORITHM)
    with pytest.raises(CAStateError, match="already exists"):
        store.create_root("Another Root", FAST_ALGORITHM)


def test_create_root_rejects_an_unknown_algorithm(store) -> None:
    from pqpki.errors import UnknownAlgorithmError

    with pytest.raises(UnknownAlgorithmError):
        store.create_root("Store Root", "rot13")
    assert not store.has_root()


def test_intermediate_requires_a_root(store) -> None:
    with pytest.raises(CAStateError, match="no root CA"):
        store.create_intermediate("Store Intermediate")


def test_create_intermediate_inherits_the_root_algorithm(store) -> None:
    store.create_root("Store Root", FAST_ALGORITHM)
    store.create_intermediate("Store Intermediate")
    assert store.load_intermediate().algorithm.name == FAST_ALGORITHM


def test_create_intermediate_can_use_a_different_algorithm(store) -> None:
    """A mixed hierarchy is one shape a real migration takes."""
    store.create_root("Store Root", FAST_ALGORITHM)
    store.create_intermediate("Store Intermediate", "ml-dsa-44")
    assert store.load_intermediate().algorithm.name == "ml-dsa-44"


def test_create_intermediate_twice_is_refused(populated) -> None:
    with pytest.raises(CAStateError, match="already exists"):
        populated.create_intermediate("Another Intermediate")


def test_loading_a_missing_intermediate_explains_itself(store) -> None:
    store.create_root("Store Root", FAST_ALGORITHM)
    with pytest.raises(CAStateError, match="no intermediate CA"):
        store.load_intermediate()


def test_issuing_ca_prefers_the_intermediate(populated) -> None:
    assert populated.issuing_ca().certificate == populated.load_intermediate().certificate


def test_issuing_ca_falls_back_to_the_root(store) -> None:
    store.create_root("Store Root", FAST_ALGORITHM)
    assert store.issuing_ca().certificate == store.load_root().certificate


def test_chain_bundle_is_leaf_to_root_order(populated) -> None:
    path = populated.write_chain_bundle()
    text = path.read_text(encoding="utf-8")
    assert text.count("BEGIN CERTIFICATE") == 2

    certificates = x509.load_pem_x509_certificates(path.read_bytes())
    assert certificates[0].subject.rfc4514_string() == "CN=Store Intermediate"
    assert certificates[1].subject.rfc4514_string() == "CN=Store Root"


def test_ca_keys_on_disk_are_encrypted(populated) -> None:
    key_bytes = (populated.root_dir / "keys" / "ca.key").read_bytes()
    assert b"BEGIN ENCRYPTED PRIVATE KEY" in key_bytes


def test_a_store_reopened_with_the_wrong_passphrase_fails(populated, tmp_path) -> None:
    reopened = PKIStore(populated.directory, passphrase="wrong")
    with pytest.raises(CAStateError, match="passphrase is wrong"):
        reopened.load_root()


def test_a_store_survives_being_reopened(populated) -> None:
    """The UI is restarted between runs, so this is the normal case."""
    reopened = PKIStore(populated.directory, passphrase=PASSPHRASE)
    assert reopened.has_root()
    assert reopened.has_intermediate()


# --------------------------------------------------------------------------
# Issuance
# --------------------------------------------------------------------------


def test_issue_certificate_writes_a_certificate_and_a_key(populated) -> None:
    certificate, cert_path, key_path = populated.issue_certificate(
        "web.example", ["web.example"]
    )
    assert cert_path.exists()
    assert key_path.exists()
    assert f"{certificate.serial_number:x}" in cert_path.name


def test_issued_certificate_validates(populated) -> None:
    _, cert_path, _ = populated.issue_certificate("web.example", ["web.example"])
    result = populated.validate_certificate(cert_path)
    assert result.valid, result.failures


def test_issued_certificate_chain_is_three_long(populated) -> None:
    _, cert_path, _ = populated.issue_certificate("web.example", ["web.example"])
    assert populated.validate_certificate(cert_path).chain_length == 3


@pytest.mark.parametrize(
    ("profile", "expected_oid"),
    [
        (CertificateProfile.SERVER, ExtendedKeyUsageOID.SERVER_AUTH),
        (CertificateProfile.CLIENT, ExtendedKeyUsageOID.CLIENT_AUTH),
        (CertificateProfile.CODE_SIGNING, ExtendedKeyUsageOID.CODE_SIGNING),
    ],
)
def test_each_profile_sets_its_own_extended_key_usage(
    populated, profile, expected_oid
) -> None:
    certificate, _, _ = populated.issue_certificate(
        "subject.example", ["subject.example"], profile
    )
    usage = certificate.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    assert list(usage) == [expected_oid]


def test_issuance_requires_a_dns_name(populated) -> None:
    with pytest.raises(ValidationInputError, match="at least one DNS name"):
        populated.issue_certificate("web.example", [])


def test_issuance_requires_a_ca(store) -> None:
    with pytest.raises(CAStateError, match="no root CA"):
        store.issue_certificate("web.example", ["web.example"])


def test_issued_certificate_carries_the_configured_crl_url(populated) -> None:
    certificate, _, _ = populated.issue_certificate("web.example", ["web.example"])
    extension = certificate.extensions.get_extension_for_class(
        x509.CRLDistributionPoints
    )
    assert extension.value[0].full_name[0].value == CRL_URL


def test_sign_csr_accepts_a_valid_request(populated, tmp_path) -> None:
    from cryptography.hazmat.primitives import serialization

    from pqpki import generate_csr

    key = populated.issuing_ca().algorithm.generate_key()
    csr = generate_csr("external.example", key, san_dns=["external.example"])
    csr_path = tmp_path / "request.csr"
    csr_path.write_bytes(csr.public_bytes(serialization.Encoding.PEM))

    certificate, written = populated.sign_csr(csr_path)
    assert certificate.subject.rfc4514_string() == "CN=external.example"
    assert written.exists()


def test_sign_csr_rejects_a_missing_file(populated, tmp_path) -> None:
    with pytest.raises(CSRError, match="could not read"):
        populated.sign_csr(tmp_path / "absent.csr")


def test_sign_csr_rejects_a_file_that_is_not_a_csr(populated, tmp_path) -> None:
    path = tmp_path / "not.csr"
    path.write_bytes(b"this is not a certificate request")
    with pytest.raises(CSRError, match="not a PEM or DER"):
        populated.sign_csr(path)


# --------------------------------------------------------------------------
# Revocation
# --------------------------------------------------------------------------


def test_revocation_is_persisted_immediately(populated) -> None:
    """A revocation lost on exit is the one state loss with a security cost."""
    certificate, _, _ = populated.issue_certificate("web.example", ["web.example"])
    populated.revoke(certificate.serial_number, x509.ReasonFlags.key_compromise)

    reopened = PKIStore(populated.directory, passphrase=PASSPHRASE)
    assert certificate.serial_number in reopened.issuing_ca().revoked_serials


def test_published_crl_lists_the_revocation(populated) -> None:
    certificate, _, _ = populated.issue_certificate("web.example", ["web.example"])
    populated.revoke(certificate.serial_number, x509.ReasonFlags.key_compromise)
    path = populated.publish_crl()

    crl = x509.load_pem_x509_crl(path.read_bytes())
    assert crl.get_revoked_certificate_by_serial_number(certificate.serial_number)


def test_validation_fails_after_revocation(populated) -> None:
    from pqpki import FailureCode

    certificate, cert_path, _ = populated.issue_certificate(
        "web.example", ["web.example"]
    )
    assert populated.validate_certificate(cert_path).valid

    populated.revoke(certificate.serial_number, x509.ReasonFlags.key_compromise)
    populated.publish_crl()

    result = populated.validate_certificate(cert_path)
    assert not result.valid
    assert any(f.startswith(FailureCode.REVOKED) for f in result.failures)


def test_validation_can_skip_revocation(populated) -> None:
    certificate, cert_path, _ = populated.issue_certificate(
        "web.example", ["web.example"]
    )
    populated.revoke(certificate.serial_number, x509.ReasonFlags.key_compromise)
    populated.publish_crl()

    assert populated.validate_certificate(cert_path, check_revocation=False).valid


def test_delta_crl_requires_a_complete_one_first(populated) -> None:
    with pytest.raises(CAStateError, match="before a complete CRL"):
        populated.publish_delta_crl()


def test_crl_summary_is_empty_before_publication(populated) -> None:
    assert populated.crl_summary() == []


def test_crl_summary_describes_both_crls(populated) -> None:
    certificate, _, _ = populated.issue_certificate("web.example", ["web.example"])
    populated.publish_crl()
    populated.revoke(certificate.serial_number, x509.ReasonFlags.key_compromise)
    populated.publish_delta_crl()

    lines = populated.crl_summary()
    assert any(line.startswith("complete CRL") for line in lines)
    assert any("delta CRL" in line and "relative to base" in line for line in lines)


def test_crl_numbers_keep_increasing_across_reopens(populated) -> None:
    populated.publish_crl()
    reopened = PKIStore(populated.directory, passphrase=PASSPHRASE)
    reopened.publish_crl()

    numbers = [
        crl.extensions.get_extension_for_class(x509.CRLNumber).value.crl_number
        for crl in reopened.load_crls()
    ]
    assert numbers == [2]


# --------------------------------------------------------------------------
# Inspection
# --------------------------------------------------------------------------


def test_describe_certificate_reports_the_algorithm(populated) -> None:
    _, cert_path, _ = populated.issue_certificate("web.example", ["web.example"])
    lines = populated.describe_certificate(cert_path)
    assert any(FAST_ALGORITHM in line for line in lines)


def test_describe_certificate_lists_extensions(populated) -> None:
    _, cert_path, _ = populated.issue_certificate("web.example", ["web.example"])
    lines = populated.describe_certificate(cert_path)
    assert any("basicConstraints" in line for line in lines)


def test_describe_certificate_rejects_a_non_certificate(populated, tmp_path) -> None:
    path = tmp_path / "junk.crt"
    path.write_bytes(b"not a certificate")
    with pytest.raises(ValidationInputError, match="not a PEM or DER"):
        populated.describe_certificate(path)


def test_describe_csr_reports_proof_of_possession(populated, tmp_path) -> None:
    from cryptography.hazmat.primitives import serialization

    from pqpki import generate_csr

    key = populated.issuing_ca().algorithm.generate_key()
    csr = generate_csr("inspect.example", key, san_dns=["inspect.example"])
    path = tmp_path / "inspect.csr"
    path.write_bytes(csr.public_bytes(serialization.Encoding.PEM))

    lines = populated.describe_csr(path)
    assert any("verifies" in line for line in lines)


# --------------------------------------------------------------------------
# Detached file signatures
# --------------------------------------------------------------------------


def test_sign_and_verify_a_file(populated, tmp_path) -> None:
    _, cert_path, key_path = populated.issue_certificate(
        "signer.example", ["signer.example"]
    )
    document = tmp_path / "document.txt"
    document.write_bytes(b"the contents that were signed")

    signature = populated.sign_file(document, key_path, tmp_path / "document.sig")
    check = populated.verify_file(document, signature, cert_path)
    assert check.valid
    assert check.algorithm == FAST_ALGORITHM


def test_a_tampered_file_fails_verification(populated, tmp_path) -> None:
    _, cert_path, key_path = populated.issue_certificate(
        "signer.example", ["signer.example"]
    )
    document = tmp_path / "document.txt"
    document.write_bytes(b"the original contents")
    signature = populated.sign_file(document, key_path, tmp_path / "document.sig")

    document.write_bytes(b"the altered contents!")
    check = populated.verify_file(document, signature, cert_path)
    assert not check.valid
    assert "does not verify" in check.detail


def test_a_signature_from_the_wrong_key_fails(populated, tmp_path) -> None:
    _, cert_path, _ = populated.issue_certificate("signer.example", ["signer.example"])
    _, _, other_key = populated.issue_certificate("other.example", ["other.example"])

    document = tmp_path / "document.txt"
    document.write_bytes(b"contents")
    signature = populated.sign_file(document, other_key, tmp_path / "document.sig")

    assert not populated.verify_file(document, signature, cert_path).valid


def test_chain_is_reported_separately_from_the_signature(populated, tmp_path) -> None:
    """A good signature from an untrusted signer is not the same as a good one."""
    certificate, cert_path, key_path = populated.issue_certificate(
        "signer.example", ["signer.example"]
    )
    document = tmp_path / "document.txt"
    document.write_bytes(b"contents")
    signature = populated.sign_file(document, key_path, tmp_path / "document.sig")

    populated.revoke(certificate.serial_number, x509.ReasonFlags.key_compromise)
    populated.publish_crl()

    check = populated.verify_file(document, signature, cert_path, check_chain=True)
    assert check.valid
    assert check.chain is not None and not check.chain.valid
    assert "unauthenticated" in check.detail


def test_chain_is_none_when_not_requested(populated, tmp_path) -> None:
    _, cert_path, key_path = populated.issue_certificate(
        "signer.example", ["signer.example"]
    )
    document = tmp_path / "document.txt"
    document.write_bytes(b"contents")
    signature = populated.sign_file(document, key_path, tmp_path / "document.sig")

    assert populated.verify_file(document, signature, cert_path).chain is None


def test_sign_file_rejects_a_missing_file(populated, tmp_path) -> None:
    _, _, key_path = populated.issue_certificate("signer.example", ["signer.example"])
    with pytest.raises(ValidationInputError, match="could not read"):
        populated.sign_file(tmp_path / "absent.txt", key_path, tmp_path / "out.sig")


def test_sign_file_rejects_a_file_that_is_not_a_key(populated, tmp_path) -> None:
    document = tmp_path / "document.txt"
    document.write_bytes(b"contents")
    fake_key = tmp_path / "fake.key"
    fake_key.write_bytes(b"not a key")

    with pytest.raises(ValidationInputError, match="private key"):
        populated.sign_file(document, fake_key, tmp_path / "out.sig")


# --------------------------------------------------------------------------
# The cross-algorithm claim
# --------------------------------------------------------------------------


def test_the_whole_workflow_runs_for_every_algorithm(algorithm, tmp_path) -> None:
    """One UI, one code path, classical or post-quantum.

    This is the integration claim the front end depends on: nothing in the
    sequence of menu actions changes with the algorithm.
    """
    store = PKIStore(
        tmp_path / algorithm,
        passphrase=PASSPHRASE,
        crl_url=CRL_URL,
        delta_crl_url=DELTA_URL,
    )
    store.create_root("Cross Root", algorithm)
    store.create_intermediate("Cross Intermediate")

    certificate, cert_path, key_path = store.issue_certificate(
        "cross.example", ["cross.example"]
    )
    assert store.validate_certificate(cert_path).valid

    document = tmp_path / f"{algorithm}.txt"
    document.write_bytes(b"cross-algorithm contents")
    signature = store.sign_file(document, key_path, tmp_path / f"{algorithm}.sig")
    assert store.verify_file(document, signature, cert_path).valid

    store.revoke(certificate.serial_number, x509.ReasonFlags.key_compromise)
    store.publish_crl()
    store.publish_delta_crl()
    assert not store.validate_certificate(cert_path).valid
    assert len(store.crl_summary()) == 2
