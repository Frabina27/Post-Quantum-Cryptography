"""Saving and reloading a CA: revocation state, CRL numbering, key encryption.

The property under test is that a reloaded CA is the *same* CA. Before this
existed, `save` wrote only the certificate and key, so a reloaded CA forgot
every revocation and restarted CRL numbering at 1 -- and a CRL whose number has
gone backwards is indistinguishable, to a relying party, from a replay of an
old one. That is the bug these tests are here to keep fixed.
"""

from __future__ import annotations

import json

import pytest
from cryptography import x509

from conftest import build_hierarchy
from pqpki import CertificateAuthority
from pqpki.ca import CERT_FILENAME, KEY_DIRNAME, KEY_FILENAME, STATE_FILENAME
from pqpki.errors import CAStateError
from pqpki.revocation import crl_number

PASSPHRASE = "a passphrase for the tests"


def _reload(directory, passphrase=None) -> CertificateAuthority:
    return CertificateAuthority.load(
        directory / CERT_FILENAME,
        directory / KEY_DIRNAME / KEY_FILENAME,
        passphrase=passphrase,
    )


# --------------------------------------------------------------------------
# Revocation state survives a round trip
# --------------------------------------------------------------------------


def test_save_writes_a_state_file(fresh_hierarchy, tmp_path) -> None:
    fresh_hierarchy.root_ca.save(tmp_path)
    assert (tmp_path / STATE_FILENAME).exists()


def test_revocations_survive_save_and_load(fresh_hierarchy, tmp_path) -> None:
    ca = fresh_hierarchy.intermediate_ca
    serial = fresh_hierarchy.leaf.serial_number
    ca.revoke(serial, x509.ReasonFlags.key_compromise)
    ca.save(tmp_path)

    reloaded = _reload(tmp_path)
    assert serial in reloaded.revoked_serials


def test_revocation_reason_and_date_survive(fresh_hierarchy, tmp_path) -> None:
    ca = fresh_hierarchy.intermediate_ca
    serial = fresh_hierarchy.leaf.serial_number
    ca.revoke(serial, x509.ReasonFlags.affiliation_changed)
    original_at, original_reason = ca.revoked_serials[serial]
    ca.save(tmp_path)

    restored_at, restored_reason = _reload(tmp_path).revoked_serials[serial]
    assert restored_reason is original_reason
    assert restored_at == original_at


def test_a_reloaded_crl_still_lists_the_revocation(fresh_hierarchy, tmp_path) -> None:
    """The point of persisting state: the republished CRL has not forgotten."""
    ca = fresh_hierarchy.intermediate_ca
    serial = fresh_hierarchy.leaf.serial_number
    ca.revoke(serial, x509.ReasonFlags.key_compromise)
    ca.publish_crl()
    ca.save(tmp_path)

    republished = _reload(tmp_path).publish_crl()
    assert republished.get_revoked_certificate_by_serial_number(serial) is not None


def test_large_serials_round_trip_exactly(fresh_hierarchy, tmp_path) -> None:
    """Serials are up to 160 bits, so they must not go through a JSON number."""
    ca = fresh_hierarchy.root_ca
    serial = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
    ca.revoke(serial, x509.ReasonFlags.unspecified)
    ca.save(tmp_path)

    assert serial in _reload(tmp_path).revoked_serials


# --------------------------------------------------------------------------
# CRL numbering
# --------------------------------------------------------------------------


def test_crl_numbers_increase_within_one_instance(fresh_hierarchy) -> None:
    ca = fresh_hierarchy.intermediate_ca
    numbers = [crl_number(ca.publish_crl()) for _ in range(3)]
    assert numbers == sorted(numbers)
    assert len(set(numbers)) == 3


def test_crl_number_does_not_restart_after_a_reload(
    fresh_hierarchy, tmp_path
) -> None:
    """A CRLNumber going backwards looks exactly like a replayed CRL."""
    ca = fresh_hierarchy.intermediate_ca
    first = crl_number(ca.publish_crl())
    second = crl_number(ca.publish_crl())
    ca.save(tmp_path)

    after_reload = crl_number(_reload(tmp_path).publish_crl())
    assert after_reload > second > first


def test_base_crl_number_survives_a_reload(fresh_hierarchy, tmp_path) -> None:
    ca = fresh_hierarchy.intermediate_ca
    ca.publish_crl()
    expected = ca.base_crl_number
    ca.save(tmp_path)

    assert _reload(tmp_path).base_crl_number == expected


def test_delta_crl_is_publishable_after_a_reload(fresh_hierarchy, tmp_path) -> None:
    """A reloaded CA remembers its base, so it can still publish deltas."""
    ca = fresh_hierarchy.intermediate_ca
    ca.publish_crl()
    ca.save(tmp_path)

    reloaded = _reload(tmp_path)
    reloaded.revoke(fresh_hierarchy.leaf.serial_number, x509.ReasonFlags.superseded)
    delta = reloaded.publish_delta_crl()
    assert len(list(delta)) == 1


def test_delta_after_reload_lists_only_the_new_revocation(
    fresh_hierarchy, tmp_path
) -> None:
    """The base's contents are remembered, not just the base's number."""
    ca = fresh_hierarchy.intermediate_ca
    ca.revoke(11, x509.ReasonFlags.superseded)
    ca.revoke(22, x509.ReasonFlags.superseded)
    ca.publish_crl()
    ca.save(tmp_path)

    reloaded = _reload(tmp_path)
    reloaded.revoke(33, x509.ReasonFlags.key_compromise)
    delta = reloaded.publish_delta_crl()
    assert [entry.serial_number for entry in delta] == [33]


# --------------------------------------------------------------------------
# Private key encryption
# --------------------------------------------------------------------------


def test_key_is_unencrypted_by_default(fresh_hierarchy, tmp_path) -> None:
    fresh_hierarchy.root_ca.save(tmp_path)
    key_bytes = (tmp_path / KEY_DIRNAME / KEY_FILENAME).read_bytes()
    assert b"BEGIN PRIVATE KEY" in key_bytes


def test_passphrase_encrypts_the_key_file(fresh_hierarchy, tmp_path) -> None:
    fresh_hierarchy.root_ca.save(tmp_path, passphrase=PASSPHRASE)
    key_bytes = (tmp_path / KEY_DIRNAME / KEY_FILENAME).read_bytes()
    assert b"BEGIN ENCRYPTED PRIVATE KEY" in key_bytes


def test_encrypted_key_reloads_with_the_right_passphrase(
    fresh_hierarchy, tmp_path
) -> None:
    fresh_hierarchy.root_ca.save(tmp_path, passphrase=PASSPHRASE)
    reloaded = _reload(tmp_path, passphrase=PASSPHRASE)
    assert reloaded.certificate == fresh_hierarchy.root


def test_a_bytes_passphrase_works_the_same_as_a_string(
    fresh_hierarchy, tmp_path
) -> None:
    fresh_hierarchy.root_ca.save(tmp_path, passphrase=PASSPHRASE)
    assert _reload(tmp_path, passphrase=PASSPHRASE.encode()) is not None


def test_wrong_passphrase_is_refused(fresh_hierarchy, tmp_path) -> None:
    fresh_hierarchy.root_ca.save(tmp_path, passphrase=PASSPHRASE)
    with pytest.raises(CAStateError, match="passphrase is wrong"):
        _reload(tmp_path, passphrase="not the passphrase")


def test_missing_passphrase_is_refused(fresh_hierarchy, tmp_path) -> None:
    fresh_hierarchy.root_ca.save(tmp_path, passphrase=PASSPHRASE)
    with pytest.raises(CAStateError, match="encrypted"):
        _reload(tmp_path)


def test_unnecessary_passphrase_is_refused(fresh_hierarchy, tmp_path) -> None:
    """Silently ignoring it would hide a caller's wrong assumption."""
    fresh_hierarchy.root_ca.save(tmp_path)
    with pytest.raises(CAStateError, match="not encrypted"):
        _reload(tmp_path, passphrase=PASSPHRASE)


def test_empty_passphrase_is_rejected_at_save(fresh_hierarchy, tmp_path) -> None:
    with pytest.raises(CAStateError, match="empty passphrase"):
        fresh_hierarchy.root_ca.save(tmp_path, passphrase="")


def test_an_encrypted_key_still_signs_correctly(fresh_hierarchy, tmp_path) -> None:
    """Encryption is at rest only; the reloaded key must be fully usable."""
    from pqpki import generate_csr, validate_chain

    fresh_hierarchy.root_ca.save(tmp_path, passphrase=PASSPHRASE)
    reloaded = _reload(tmp_path, passphrase=PASSPHRASE)

    key = reloaded.algorithm.generate_key()
    csr = generate_csr("reloaded leaf", key, san_dns=["reloaded.example"])
    leaf = reloaded.issue_end_entity(csr, validity_days=30)

    result = validate_chain(leaf, [], [reloaded.certificate])
    assert result.valid, result.failures


# --------------------------------------------------------------------------
# Malformed state is an error, never a silent un-revocation
# --------------------------------------------------------------------------


def test_missing_state_file_is_not_an_error(fresh_hierarchy, tmp_path) -> None:
    """A CA saved by an older version, or never revoked anything."""
    fresh_hierarchy.root_ca.save(tmp_path)
    (tmp_path / STATE_FILENAME).unlink()
    assert _reload(tmp_path).revoked_serials == {}


def test_corrupt_state_file_raises(fresh_hierarchy, tmp_path) -> None:
    fresh_hierarchy.root_ca.save(tmp_path)
    (tmp_path / STATE_FILENAME).write_text("{not json", encoding="utf-8")
    with pytest.raises(CAStateError, match="could not read CA state"):
        _reload(tmp_path)


def test_state_file_of_the_wrong_version_raises(fresh_hierarchy, tmp_path) -> None:
    fresh_hierarchy.root_ca.save(tmp_path)
    path = tmp_path / STATE_FILENAME
    document = json.loads(path.read_text(encoding="utf-8"))
    document["version"] = 999
    path.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(CAStateError, match="version"):
        _reload(tmp_path)


def test_state_file_with_a_bad_serial_raises(fresh_hierarchy, tmp_path) -> None:
    ca = fresh_hierarchy.root_ca
    ca.revoke(7, x509.ReasonFlags.unspecified)
    ca.save(tmp_path)

    path = tmp_path / STATE_FILENAME
    document = json.loads(path.read_text(encoding="utf-8"))
    document["revoked"][0]["serial"] = "not a hex number"
    path.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(CAStateError, match="malformed"):
        _reload(tmp_path)


def test_state_file_claiming_a_future_base_raises(fresh_hierarchy, tmp_path) -> None:
    """A base newer than the latest CRL cannot have been issued."""
    ca = fresh_hierarchy.root_ca
    ca.publish_crl()
    ca.save(tmp_path)

    path = tmp_path / STATE_FILENAME
    document = json.loads(path.read_text(encoding="utf-8"))
    document["base_crl_number"] = document["crl_number"] + 5
    path.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(CAStateError, match="cannot be newer"):
        _reload(tmp_path)


def test_state_file_with_a_negative_crl_number_raises(
    fresh_hierarchy, tmp_path
) -> None:
    fresh_hierarchy.root_ca.save(tmp_path)
    path = tmp_path / STATE_FILENAME
    document = json.loads(path.read_text(encoding="utf-8"))
    document["crl_number"] = -1
    path.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(CAStateError, match="negative"):
        _reload(tmp_path)


def test_explicit_state_path_is_honoured(fresh_hierarchy, tmp_path) -> None:
    ca = fresh_hierarchy.root_ca
    ca.revoke(5, x509.ReasonFlags.unspecified)
    ca.save(tmp_path)

    moved = tmp_path / "elsewhere.json"
    (tmp_path / STATE_FILENAME).rename(moved)

    loaded = CertificateAuthority.load(
        tmp_path / CERT_FILENAME,
        tmp_path / KEY_DIRNAME / KEY_FILENAME,
        state_path=moved,
    )
    assert 5 in loaded.revoked_serials


def test_state_file_contains_no_private_material(fresh_hierarchy, tmp_path) -> None:
    """It sits outside keys/ and is world-readable, so it must hold no secrets."""
    fresh_hierarchy.root_ca.save(tmp_path, passphrase=PASSPHRASE)
    text = (tmp_path / STATE_FILENAME).read_text(encoding="utf-8")
    assert "PRIVATE" not in text.upper()
    assert PASSPHRASE not in text


# --------------------------------------------------------------------------
# Cross-algorithm: encryption must work for every algorithm, not just RSA
# --------------------------------------------------------------------------


def test_every_algorithm_can_encrypt_its_key(algorithm, tmp_path) -> None:
    """PKCS#8 encryption of an ML-DSA key is newer than that of an RSA key."""
    hierarchy = build_hierarchy(algorithm, name_prefix="pqpki Encrypted")
    hierarchy.root_ca.save(tmp_path, passphrase=PASSPHRASE)
    reloaded = _reload(tmp_path, passphrase=PASSPHRASE)
    assert reloaded.algorithm.name == algorithm
