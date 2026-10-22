"""Tests for hand-written path validation.

Every negative test asserts the *named* failure code, not merely that
validation failed. A validator that rejects everything would pass a suite that
only checked ``valid is False``.

The library's own verifier appears here only as an independent oracle, in the
cross-check tests at the bottom.
"""

from __future__ import annotations

import datetime

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID
from cryptography.x509.verification import PolicyBuilder, Store

import derutil
from conftest import LEAF_DNS_NAME, Hierarchy, build_hierarchy
from pqpki import FailureCode, generate_csr, validate_chain
from pqpki.algorithms import MetricEvent, spec_for_key
from pqpki.errors import ValidationInputError

UTC = datetime.timezone.utc


def codes(result) -> set[str]:
    """The failure codes in a result, discarding the human-readable detail."""
    return {failure.split(":", 1)[0] for failure in result.failures}


def assert_failed_with(result, code: str) -> None:
    assert result.valid is False
    assert code in codes(result), (
        f"expected failure code {code!r}, got {sorted(codes(result))}. "
        f"Full failures: {result.failures}"
    )


def _now() -> datetime.datetime:
    return datetime.datetime.now(UTC).replace(microsecond=0)


def forge_certificate(
    issuer_cert: x509.Certificate,
    issuer_key,
    subject_cn: str,
    subject_key,
    extensions: list[tuple[x509.ExtensionType, bool]],
    *,
    not_before: datetime.datetime | None = None,
    days: int = 365,
) -> x509.Certificate:
    """Sign a certificate directly, bypassing CertificateAuthority's guards.

    The CA class refuses to issue malformed certificates, which is correct and
    also means the validator's negative paths cannot be reached through it.
    This stands in for a misbehaving or hostile CA.
    """
    spec = spec_for_key(issuer_key)
    start = not_before if not_before is not None else _now()

    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_cn)]))
        .issuer_name(issuer_cert.subject)
        .public_key(subject_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(start)
        .not_valid_after(start + datetime.timedelta(days=days))
    )
    for extension, critical in extensions:
        builder = builder.add_extension(extension, critical=critical)
    return builder.sign(issuer_key, *spec.sign_args())


CA_KEY_USAGE = x509.KeyUsage(
    digital_signature=False, content_commitment=False, key_encipherment=False,
    data_encipherment=False, key_agreement=False, key_cert_sign=True,
    crl_sign=True, encipher_only=False, decipher_only=False,
)
LEAF_KEY_USAGE = x509.KeyUsage(
    digital_signature=True, content_commitment=False, key_encipherment=False,
    data_encipherment=False, key_agreement=False, key_cert_sign=False,
    crl_sign=False, encipher_only=False, decipher_only=False,
)


def leaf_extensions(dns: str = "forged.example") -> list[tuple[x509.ExtensionType, bool]]:
    return [
        (x509.BasicConstraints(ca=False, path_length=None), True),
        (LEAF_KEY_USAGE, True),
        (x509.SubjectAlternativeName([x509.DNSName(dns)]), False),
    ]


def ca_extensions(path_length: int | None = 0) -> list[tuple[x509.ExtensionType, bool]]:
    return [
        (x509.BasicConstraints(ca=True, path_length=path_length), True),
        (CA_KEY_USAGE, True),
    ]


# --------------------------------------------------------------------------
# The happy path
# --------------------------------------------------------------------------


def test_valid_chain_passes(hierarchy: Hierarchy) -> None:
    result = validate_chain(hierarchy.leaf, [hierarchy.intermediate], [hierarchy.root])
    assert result.valid is True
    assert result.failures == []
    assert result.chain_length == 3


def test_algorithms_used_is_reported_per_link(hierarchy: Hierarchy) -> None:
    result = validate_chain(hierarchy.leaf, [hierarchy.intermediate], [hierarchy.root])
    assert result.algorithms_used == [hierarchy.algorithm] * 3


def test_extra_unused_intermediates_are_ignored(hierarchy: Hierarchy) -> None:
    """A caller normally passes every intermediate it has, not just the right one."""
    other = build_hierarchy(hierarchy.algorithm, name_prefix="Unrelated")
    result = validate_chain(
        hierarchy.leaf,
        [other.intermediate, hierarchy.intermediate, other.root],
        [hierarchy.root],
    )
    assert result.valid is True, result.failures
    assert result.chain_length == 3


def test_intermediate_order_does_not_matter(algorithm: str) -> None:
    """Path building must not assume the caller sorted the intermediates.

    Needs a genuinely deep chain to be meaningful: reversing a single-element
    list proves nothing, so this builds root -> sub1 -> sub2 -> leaf and feeds
    the two intermediates in both orders.
    """
    from pqpki import CertificateAuthority

    root_ca = CertificateAuthority.create_root("Deep Root", algorithm, path_length=2)

    sub1_key = root_ca.algorithm.generate_key()
    sub1_cert = root_ca.issue_intermediate(
        generate_csr("Deep Sub One", sub1_key), validity_days=365, path_length=1
    )
    sub1_ca = CertificateAuthority(sub1_cert, sub1_key)

    sub2_key = root_ca.algorithm.generate_key()
    sub2_cert = sub1_ca.issue_intermediate(
        generate_csr("Deep Sub Two", sub2_key), validity_days=365, path_length=0
    )
    sub2_ca = CertificateAuthority(sub2_cert, sub2_key)

    leaf_key = root_ca.algorithm.generate_key()
    leaf = sub2_ca.issue_end_entity(
        generate_csr("deep-leaf.example", leaf_key, san_dns=["deep-leaf.example"]),
        validity_days=30,
    )

    for order in ([sub1_cert, sub2_cert], [sub2_cert, sub1_cert]):
        result = validate_chain(leaf, order, [root_ca.certificate])
        assert result.valid is True, result.failures
        assert result.chain_length == 4


def test_direct_root_to_leaf_chain_is_two_links(algorithm: str) -> None:
    from pqpki import CertificateAuthority

    root_ca = CertificateAuthority.create_root("Short Root", algorithm)
    key = root_ca.algorithm.generate_key()
    csr = generate_csr("short.example", key, san_dns=["short.example"])
    leaf = root_ca.issue_end_entity(csr, validity_days=30)

    result = validate_chain(leaf, [], [root_ca.certificate])
    assert result.valid is True, result.failures
    assert result.chain_length == 2


# --------------------------------------------------------------------------
# Input handling
# --------------------------------------------------------------------------


def test_empty_trust_roots_is_a_caller_error(hierarchy: Hierarchy) -> None:
    """A config bug must not be disguised as a bad certificate."""
    with pytest.raises(ValidationInputError, match="no trust roots"):
        validate_chain(hierarchy.leaf, [hierarchy.intermediate], [])


def test_naive_at_time_is_treated_as_utc(hierarchy: Hierarchy) -> None:
    # Naive *UTC*, not naive local: the validator documents that it reads a
    # naive value as UTC, so feeding it local time would be testing the
    # machine's timezone offset rather than the documented behaviour.
    naive = datetime.datetime.now(UTC).replace(microsecond=0, tzinfo=None)
    result = validate_chain(
        hierarchy.leaf, [hierarchy.intermediate], [hierarchy.root], at_time=naive
    )
    assert result.valid is True, result.failures


# --------------------------------------------------------------------------
# Name chaining
# --------------------------------------------------------------------------


def test_missing_intermediate_breaks_name_chaining(hierarchy: Hierarchy) -> None:
    result = validate_chain(hierarchy.leaf, [], [hierarchy.root])
    assert_failed_with(result, FailureCode.NAME_CHAINING)


def test_chain_to_an_untrusted_root_is_rejected(hierarchy: Hierarchy) -> None:
    """Passing the root as an intermediate must not make it trusted."""
    result = validate_chain(
        hierarchy.leaf,
        [hierarchy.intermediate, hierarchy.root],
        [build_hierarchy(hierarchy.algorithm, name_prefix="Other").root],
    )
    assert_failed_with(result, FailureCode.NO_TRUST_ANCHOR)


def test_leaf_from_a_different_hierarchy_is_rejected(hierarchy: Hierarchy) -> None:
    stranger = build_hierarchy(hierarchy.algorithm, name_prefix="Stranger")
    result = validate_chain(
        stranger.leaf, [hierarchy.intermediate], [hierarchy.root]
    )
    assert result.valid is False


# --------------------------------------------------------------------------
# Signatures
# --------------------------------------------------------------------------


def test_flipped_byte_in_the_tbs_region_fails_the_signature(
    hierarchy: Hierarchy,
) -> None:
    """One byte changed inside the signed region, DER still well-formed."""
    marker, replacement = "flip-marker-here", b"flip-marker-gone"
    key = hierarchy.spec.generate_key()
    csr = generate_csr(marker, key, san_dns=["flip.example"])
    leaf = hierarchy.intermediate_ca.issue_end_entity(csr, validity_days=30)

    der = leaf.public_bytes(serialization.Encoding.DER)
    tampered = x509.load_der_x509_certificate(
        derutil.flip_bytes(der, marker.encode(), replacement)
    )

    # It really did parse and really did change.
    (cn,) = tampered.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    assert cn.value == replacement.decode()

    result = validate_chain(tampered, [hierarchy.intermediate], [hierarchy.root])
    assert_failed_with(result, FailureCode.SIGNATURE)


def test_signature_swapped_from_another_certificate_is_rejected(
    hierarchy: Hierarchy,
) -> None:
    """A valid signature over different data must not validate."""
    donor = build_hierarchy(hierarchy.algorithm)
    victim_der = hierarchy.leaf.public_bytes(serialization.Encoding.DER)
    donor_der = donor.leaf.public_bytes(serialization.Encoding.DER)

    spliced = x509.load_der_x509_certificate(
        derutil.splice_signature_value(victim_der, donor_der)
    )
    assert spliced.signature == donor.leaf.signature
    assert spliced.tbs_certificate_bytes == hierarchy.leaf.tbs_certificate_bytes

    result = validate_chain(spliced, [hierarchy.intermediate], [hierarchy.root])
    assert_failed_with(result, FailureCode.SIGNATURE)


def test_certificate_signed_by_the_wrong_ca_is_rejected(hierarchy: Hierarchy) -> None:
    """Names chain correctly but the key is wrong -- a cross-signing mistake."""
    impostor = build_hierarchy(hierarchy.algorithm)
    key = hierarchy.spec.generate_key()
    forged = forge_certificate(
        hierarchy.intermediate,  # claims this issuer name...
        impostor.intermediate_ca.private_key,  # ...but is signed by another key
        "impostor.example",
        key,
        leaf_extensions("impostor.example"),
    )
    result = validate_chain(forged, [hierarchy.intermediate], [hierarchy.root])
    assert_failed_with(result, FailureCode.SIGNATURE)


# --------------------------------------------------------------------------
# Validity windows
# --------------------------------------------------------------------------


def test_expired_leaf_is_rejected(hierarchy: Hierarchy) -> None:
    after_expiry = hierarchy.leaf.not_valid_after_utc + datetime.timedelta(days=1)
    result = validate_chain(
        hierarchy.leaf,
        [hierarchy.intermediate],
        [hierarchy.root],
        at_time=after_expiry,
    )
    assert_failed_with(result, FailureCode.EXPIRED)


def test_not_yet_valid_leaf_is_rejected(hierarchy: Hierarchy) -> None:
    before_issue = hierarchy.leaf.not_valid_before_utc - datetime.timedelta(days=1)
    result = validate_chain(
        hierarchy.leaf,
        [hierarchy.intermediate],
        [hierarchy.root],
        at_time=before_issue,
    )
    assert_failed_with(result, FailureCode.NOT_YET_VALID)


def test_genuinely_expired_certificate_is_rejected_at_the_current_time(
    hierarchy: Hierarchy,
) -> None:
    """Not just an at_time trick: a certificate whose window really has passed."""
    key = hierarchy.spec.generate_key()
    expired = forge_certificate(
        hierarchy.intermediate,
        hierarchy.intermediate_ca.private_key,
        "expired.example",
        key,
        leaf_extensions("expired.example"),
        not_before=_now() - datetime.timedelta(days=400),
        days=30,
    )
    result = validate_chain(expired, [hierarchy.intermediate], [hierarchy.root])
    assert_failed_with(result, FailureCode.EXPIRED)


def test_expiry_of_an_intermediate_is_caught(hierarchy: Hierarchy) -> None:
    """Validity is checked at every link, not just the leaf."""
    after = hierarchy.intermediate.not_valid_after_utc + datetime.timedelta(days=1)
    result = validate_chain(
        hierarchy.leaf, [hierarchy.intermediate], [hierarchy.root], at_time=after
    )
    assert_failed_with(result, FailureCode.EXPIRED)


def test_at_time_inside_the_window_passes(hierarchy: Hierarchy) -> None:
    midpoint = hierarchy.leaf.not_valid_before_utc + datetime.timedelta(days=1)
    result = validate_chain(
        hierarchy.leaf, [hierarchy.intermediate], [hierarchy.root], at_time=midpoint
    )
    assert result.valid is True, result.failures


# --------------------------------------------------------------------------
# Basic constraints
# --------------------------------------------------------------------------


def test_ca_false_certificate_used_as_an_issuer_is_rejected(
    hierarchy: Hierarchy,
) -> None:
    """The case your CA refuses to create, so it must be forged."""
    impostor_key = hierarchy.spec.generate_key()
    impostor_leaf = forge_certificate(
        hierarchy.intermediate,
        hierarchy.intermediate_ca.private_key,
        "notaca.example",
        impostor_key,
        leaf_extensions("notaca.example"),
    )

    victim_key = hierarchy.spec.generate_key()
    victim = forge_certificate(
        impostor_leaf,  # an end-entity certificate acting as an issuer
        impostor_key,
        "victim.example",
        victim_key,
        leaf_extensions("victim.example"),
    )

    result = validate_chain(
        victim, [impostor_leaf, hierarchy.intermediate], [hierarchy.root]
    )
    assert_failed_with(result, FailureCode.NOT_A_CA)


def test_issuer_without_basic_constraints_is_rejected(hierarchy: Hierarchy) -> None:
    naked_key = hierarchy.spec.generate_key()
    naked = forge_certificate(
        hierarchy.intermediate,
        hierarchy.intermediate_ca.private_key,
        "naked.example",
        naked_key,
        [(CA_KEY_USAGE, True)],  # KeyUsage but no BasicConstraints
    )
    child_key = hierarchy.spec.generate_key()
    child = forge_certificate(
        naked, naked_key, "child.example", child_key, leaf_extensions("child.example")
    )

    result = validate_chain(child, [naked, hierarchy.intermediate], [hierarchy.root])
    assert_failed_with(result, FailureCode.BASIC_CONSTRAINTS_MISSING)


def test_non_critical_basic_constraints_on_a_ca_is_reported(
    hierarchy: Hierarchy,
) -> None:
    sloppy_key = hierarchy.spec.generate_key()
    sloppy = forge_certificate(
        hierarchy.intermediate,
        hierarchy.intermediate_ca.private_key,
        "sloppy.example",
        sloppy_key,
        [
            (x509.BasicConstraints(ca=True, path_length=0), False),  # not critical
            (CA_KEY_USAGE, True),
        ],
    )
    child_key = hierarchy.spec.generate_key()
    child = forge_certificate(
        sloppy, sloppy_key, "child2.example", child_key, leaf_extensions("child2.example")
    )

    result = validate_chain(child, [sloppy, hierarchy.intermediate], [hierarchy.root])
    assert_failed_with(result, FailureCode.BASIC_CONSTRAINTS_NOT_CRITICAL)


# --------------------------------------------------------------------------
# Path length
# --------------------------------------------------------------------------


def test_path_length_violation_is_rejected(hierarchy: Hierarchy) -> None:
    """The real hierarchy's intermediate has pathlen 0; forge a CA under it."""
    sub_key = hierarchy.spec.generate_key()
    sub_ca = forge_certificate(
        hierarchy.intermediate,
        hierarchy.intermediate_ca.private_key,
        "subca.example",
        sub_key,
        ca_extensions(path_length=0),
    )
    leaf_key = hierarchy.spec.generate_key()
    leaf = forge_certificate(
        sub_ca, sub_key, "deep.example", leaf_key, leaf_extensions("deep.example")
    )

    result = validate_chain(
        leaf, [sub_ca, hierarchy.intermediate], [hierarchy.root]
    )
    assert_failed_with(result, FailureCode.PATH_LENGTH)
    assert result.chain_length == 4


def test_path_length_exactly_at_the_limit_is_allowed(algorithm: str) -> None:
    """pathlen=1 must permit exactly one intermediate below it."""
    from pqpki import CertificateAuthority

    root_ca = CertificateAuthority.create_root("PL Root", algorithm, path_length=1)
    sub_key = root_ca.algorithm.generate_key()
    sub_csr = generate_csr("pl-sub.example", sub_key)
    sub_cert = root_ca.issue_intermediate(sub_csr, validity_days=365, path_length=0)
    sub_ca = CertificateAuthority(sub_cert, sub_key)

    leaf_key = root_ca.algorithm.generate_key()
    leaf_csr = generate_csr("pl-leaf.example", leaf_key, san_dns=["pl-leaf.example"])
    leaf = sub_ca.issue_end_entity(leaf_csr, validity_days=30)

    result = validate_chain(leaf, [sub_cert], [root_ca.certificate])
    assert result.valid is True, result.failures


# --------------------------------------------------------------------------
# Key usage
# --------------------------------------------------------------------------


def test_issuer_without_cert_sign_is_rejected(hierarchy: Hierarchy) -> None:
    bad_key = hierarchy.spec.generate_key()
    bad_ca = forge_certificate(
        hierarchy.intermediate,
        hierarchy.intermediate_ca.private_key,
        "nocertsign.example",
        bad_key,
        [
            (x509.BasicConstraints(ca=True, path_length=0), True),
            (LEAF_KEY_USAGE, True),  # digitalSignature only, no keyCertSign
        ],
    )
    child_key = hierarchy.spec.generate_key()
    child = forge_certificate(
        bad_ca, bad_key, "child3.example", child_key, leaf_extensions("child3.example")
    )

    result = validate_chain(child, [bad_ca, hierarchy.intermediate], [hierarchy.root])
    assert_failed_with(result, FailureCode.KEY_USAGE_CERT_SIGN)


def test_issuer_without_key_usage_at_all_is_reported(hierarchy: Hierarchy) -> None:
    bare_key = hierarchy.spec.generate_key()
    bare_ca = forge_certificate(
        hierarchy.intermediate,
        hierarchy.intermediate_ca.private_key,
        "noku.example",
        bare_key,
        [(x509.BasicConstraints(ca=True, path_length=0), True)],
    )
    child_key = hierarchy.spec.generate_key()
    child = forge_certificate(
        bare_ca, bare_key, "child4.example", child_key, leaf_extensions("child4.example")
    )

    result = validate_chain(child, [bare_ca, hierarchy.intermediate], [hierarchy.root])
    assert_failed_with(result, FailureCode.KEY_USAGE_MISSING)


def test_leaf_without_digital_signature_is_rejected(hierarchy: Hierarchy) -> None:
    key = hierarchy.spec.generate_key()
    leaf = forge_certificate(
        hierarchy.intermediate,
        hierarchy.intermediate_ca.private_key,
        "nodigsig.example",
        key,
        [
            (x509.BasicConstraints(ca=False, path_length=None), True),
            (
                x509.KeyUsage(
                    digital_signature=False, content_commitment=True,
                    key_encipherment=False, data_encipherment=False,
                    key_agreement=False, key_cert_sign=False, crl_sign=False,
                    encipher_only=False, decipher_only=False,
                ),
                True,
            ),
            (x509.SubjectAlternativeName([x509.DNSName("nodigsig.example")]), False),
        ],
    )
    result = validate_chain(leaf, [hierarchy.intermediate], [hierarchy.root])
    assert_failed_with(result, FailureCode.KEY_USAGE_DIGITAL_SIGNATURE)


# --------------------------------------------------------------------------
# Revocation
# --------------------------------------------------------------------------


def test_revoked_leaf_is_rejected(fresh_hierarchy: Hierarchy) -> None:
    ca = fresh_hierarchy.intermediate_ca
    ca.revoke(fresh_hierarchy.leaf.serial_number, x509.ReasonFlags.key_compromise)
    crl = ca.publish_crl()

    result = validate_chain(
        fresh_hierarchy.leaf,
        [fresh_hierarchy.intermediate],
        [fresh_hierarchy.root],
        crls=[crl],
    )
    assert_failed_with(result, FailureCode.REVOKED)
    assert "keyCompromise" in " ".join(result.failures)


def test_unrevoked_leaf_passes_with_a_crl_present(fresh_hierarchy: Hierarchy) -> None:
    """The empty-CRL path: a CRL listing nothing must not fail open or closed."""
    crl = fresh_hierarchy.intermediate_ca.publish_crl()
    assert len(crl) == 0  # falsy, which is exactly the trap

    result = validate_chain(
        fresh_hierarchy.leaf,
        [fresh_hierarchy.intermediate],
        [fresh_hierarchy.root],
        crls=[crl],
    )
    assert result.valid is True, result.failures


def test_revocation_is_not_checked_when_no_crls_are_supplied(
    fresh_hierarchy: Hierarchy,
) -> None:
    ca = fresh_hierarchy.intermediate_ca
    ca.revoke(fresh_hierarchy.leaf.serial_number, x509.ReasonFlags.key_compromise)
    ca.publish_crl()

    result = validate_chain(
        fresh_hierarchy.leaf, [fresh_hierarchy.intermediate], [fresh_hierarchy.root]
    )
    assert result.valid is True, result.failures


def test_revoked_intermediate_is_caught(fresh_hierarchy: Hierarchy) -> None:
    """Revocation is checked at every link, not only the leaf."""
    root_ca = fresh_hierarchy.root_ca
    root_ca.revoke(
        fresh_hierarchy.intermediate.serial_number, x509.ReasonFlags.cessation_of_operation
    )
    crl = root_ca.publish_crl()

    result = validate_chain(
        fresh_hierarchy.leaf,
        [fresh_hierarchy.intermediate],
        [fresh_hierarchy.root],
        crls=[crl],
    )
    assert_failed_with(result, FailureCode.REVOKED)


def test_crl_from_the_wrong_issuer_is_ignored(fresh_hierarchy: Hierarchy) -> None:
    """A CRL has authority only over its own issuer's certificates."""
    stranger = build_hierarchy(
        fresh_hierarchy.algorithm, name_prefix="Stranger"
    )
    stranger.intermediate_ca.revoke(
        fresh_hierarchy.leaf.serial_number, x509.ReasonFlags.key_compromise
    )
    foreign_crl = stranger.intermediate_ca.publish_crl()

    result = validate_chain(
        fresh_hierarchy.leaf,
        [fresh_hierarchy.intermediate],
        [fresh_hierarchy.root],
        crls=[foreign_crl],
    )
    assert result.valid is True, result.failures


def test_stale_crl_is_reported_as_a_problem(fresh_hierarchy: Hierarchy) -> None:
    """Past nextUpdate, a CRL means 'unknown', not 'nothing was revoked'."""
    crl = fresh_hierarchy.intermediate_ca.publish_crl(validity_days=1)
    later = crl.next_update_utc + datetime.timedelta(days=1)

    result = validate_chain(
        fresh_hierarchy.leaf,
        [fresh_hierarchy.intermediate],
        [fresh_hierarchy.root],
        at_time=later,
        crls=[crl],
    )
    assert FailureCode.CRL_PROBLEM in codes(result)


def test_crl_with_a_forged_signature_is_not_believed(
    fresh_hierarchy: Hierarchy,
) -> None:
    """An attacker who could forge a CRL could revoke anything."""
    impostor = build_hierarchy(fresh_hierarchy.algorithm)
    # Sign a CRL with the wrong key but claim the real issuer's name.
    spec = fresh_hierarchy.spec
    now = _now()
    forged = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(fresh_hierarchy.intermediate.subject)
        .last_update(now)
        .next_update(now + datetime.timedelta(days=7))
        .add_revoked_certificate(
            x509.RevokedCertificateBuilder()
            .serial_number(fresh_hierarchy.leaf.serial_number)
            .revocation_date(now)
            .build()
        )
        .sign(impostor.intermediate_ca.private_key, *spec.sign_args())
    )

    result = validate_chain(
        fresh_hierarchy.leaf,
        [fresh_hierarchy.intermediate],
        [fresh_hierarchy.root],
        crls=[forged],
    )
    # The CRL is rejected, so the revocation it claims is not honoured...
    assert FailureCode.CRL_PROBLEM in codes(result)
    assert FailureCode.REVOKED not in codes(result)


# --------------------------------------------------------------------------
# Multiple simultaneous failures
# --------------------------------------------------------------------------


def test_all_failures_are_reported_not_just_the_first(
    fresh_hierarchy: Hierarchy,
) -> None:
    """An operator debugging a broken deployment wants every reason at once."""
    ca = fresh_hierarchy.intermediate_ca
    ca.revoke(fresh_hierarchy.leaf.serial_number, x509.ReasonFlags.key_compromise)
    crl = ca.publish_crl(validity_days=3650)

    after_expiry = fresh_hierarchy.leaf.not_valid_after_utc + datetime.timedelta(days=1)
    result = validate_chain(
        fresh_hierarchy.leaf,
        [fresh_hierarchy.intermediate],
        [fresh_hierarchy.root],
        at_time=after_expiry,
        crls=[crl],
    )
    assert {FailureCode.EXPIRED, FailureCode.REVOKED} <= codes(result)


# --------------------------------------------------------------------------
# Instrumentation
# --------------------------------------------------------------------------


def test_collector_receives_a_validate_chain_event(hierarchy: Hierarchy) -> None:
    events: list[MetricEvent] = []
    validate_chain(
        hierarchy.leaf,
        [hierarchy.intermediate],
        [hierarchy.root],
        collector=events.append,
    )
    (event,) = events
    assert event.operation == "validate_chain"
    assert event.algorithm == hierarchy.algorithm
    assert event.duration_s >= 0.0
    # Validation produces no artifact, so there is no size to report.
    assert event.artifact_bytes is None


# --------------------------------------------------------------------------
# Cross-check against the library's own verifier
# --------------------------------------------------------------------------


def _library_accepts(hierarchy: Hierarchy, leaf: x509.Certificate, at_time) -> bool:
    verifier = (
        PolicyBuilder()
        .store(Store([hierarchy.root]))
        .time(at_time)
        .build_server_verifier(x509.DNSName(LEAF_DNS_NAME))
    )
    try:
        verifier.verify(leaf, [hierarchy.intermediate])
        return True
    except Exception:
        return False


def test_agrees_with_the_library_verifier_on_a_good_chain(
    hierarchy: Hierarchy,
) -> None:
    at_time = hierarchy.leaf.not_valid_before_utc + datetime.timedelta(minutes=1)
    ours = validate_chain(
        hierarchy.leaf, [hierarchy.intermediate], [hierarchy.root], at_time=at_time
    )
    assert ours.valid is True, ours.failures
    assert _library_accepts(hierarchy, hierarchy.leaf, at_time) is True


def test_agrees_with_the_library_verifier_on_expiry(hierarchy: Hierarchy) -> None:
    at_time = hierarchy.leaf.not_valid_after_utc + datetime.timedelta(days=1)
    ours = validate_chain(
        hierarchy.leaf, [hierarchy.intermediate], [hierarchy.root], at_time=at_time
    )
    assert ours.valid is False
    assert _library_accepts(hierarchy, hierarchy.leaf, at_time) is False


def test_agrees_with_the_library_verifier_on_a_tampered_chain(
    hierarchy: Hierarchy,
) -> None:
    donor = build_hierarchy(hierarchy.algorithm)
    spliced = x509.load_der_x509_certificate(
        derutil.splice_signature_value(
            hierarchy.leaf.public_bytes(serialization.Encoding.DER),
            donor.leaf.public_bytes(serialization.Encoding.DER),
        )
    )
    at_time = hierarchy.leaf.not_valid_before_utc + datetime.timedelta(minutes=1)
    ours = validate_chain(
        spliced, [hierarchy.intermediate], [hierarchy.root], at_time=at_time
    )
    assert ours.valid is False
    assert _library_accepts(hierarchy, spliced, at_time) is False
