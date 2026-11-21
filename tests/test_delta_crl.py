"""Delta CRLs and CRL distribution points.

Two features, tested together because they are two halves of the same story: a
certificate carries pointers saying where its CRL and its delta CRL live, and
the delta CRL is the document those pointers lead to.

The security-relevant assertion in this file is that a delta CRL is never
believed on its own. A delta lists only what changed since a named base, so
reading one as a complete CRL would make every serial that appears only in the
base look unrevoked -- strictly worse than having no CRL at all. There are
tests here for exactly that, and they matter more than the size ones.
"""

from __future__ import annotations

import datetime

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from pqpki import CertificateAuthority, FailureCode, generate_csr, validate_chain
from pqpki.errors import CAStateError
from pqpki.revocation import (
    check_revocation,
    crl_number,
    delta_base_number,
    is_delta_crl,
)

DER = serialization.Encoding.DER

CRL_URL = "http://crl.pqpki.example/latest.crl"
DELTA_URL = "http://crl.pqpki.example/delta.crl"


def _now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


@pytest.fixture
def advertising_ca(algorithm) -> CertificateAuthority:
    """A root CA that advertises both a CRL and a delta CRL location."""
    return CertificateAuthority.create_root(
        "pqpki Delta Root",
        algorithm,
        validity_days=3650,
        crl_url=CRL_URL,
        delta_crl_url=DELTA_URL,
    )


@pytest.fixture
def advertised_leaf(advertising_ca) -> x509.Certificate:
    key = advertising_ca.algorithm.generate_key()
    csr = generate_csr("pqpki Delta Leaf", key, san_dns=["delta.example"])
    return advertising_ca.issue_end_entity(csr, validity_days=90)


# --------------------------------------------------------------------------
# Distribution point extensions
# --------------------------------------------------------------------------


def test_issued_certificate_carries_crl_distribution_points(advertised_leaf) -> None:
    extension = advertised_leaf.extensions.get_extension_for_class(
        x509.CRLDistributionPoints
    )
    assert extension.value[0].full_name[0].value == CRL_URL


def test_issued_certificate_carries_freshest_crl(advertised_leaf) -> None:
    extension = advertised_leaf.extensions.get_extension_for_class(x509.FreshestCRL)
    assert extension.value[0].full_name[0].value == DELTA_URL


@pytest.mark.parametrize(
    "extension_class", [x509.CRLDistributionPoints, x509.FreshestCRL]
)
def test_distribution_extensions_are_not_critical(
    advertised_leaf, extension_class
) -> None:
    """RFC 5280 requires both to be non-critical."""
    assert not advertised_leaf.extensions.get_extension_for_class(
        extension_class
    ).critical


def test_distribution_point_names_no_crl_issuer(advertised_leaf) -> None:
    """A crl_issuer would claim an indirect CRL, which this CA does not publish."""
    point = advertised_leaf.extensions.get_extension_for_class(
        x509.CRLDistributionPoints
    ).value[0]
    assert point.crl_issuer is None
    assert point.relative_name is None


def test_distribution_point_names_no_reasons(advertised_leaf) -> None:
    """A reasons field would claim the CRL is partitioned by reason code."""
    point = advertised_leaf.extensions.get_extension_for_class(
        x509.CRLDistributionPoints
    ).value[0]
    assert point.reasons is None


def test_no_distribution_points_when_no_url_is_configured(hierarchy) -> None:
    """The extensions appear only when the CA was told where it publishes."""
    with pytest.raises(x509.ExtensionNotFound):
        hierarchy.leaf.extensions.get_extension_for_class(x509.CRLDistributionPoints)
    with pytest.raises(x509.ExtensionNotFound):
        hierarchy.leaf.extensions.get_extension_for_class(x509.FreshestCRL)


def test_root_certificate_has_no_distribution_points(advertising_ca) -> None:
    """A trust anchor has no issuer above it, so nothing could revoke it."""
    with pytest.raises(x509.ExtensionNotFound):
        advertising_ca.certificate.extensions.get_extension_for_class(
            x509.CRLDistributionPoints
        )


def test_intermediates_also_carry_distribution_points(advertising_ca) -> None:
    key = advertising_ca.algorithm.generate_key()
    csr = generate_csr("pqpki Delta Intermediate", key)
    intermediate = advertising_ca.issue_intermediate(csr, validity_days=365)
    extension = intermediate.extensions.get_extension_for_class(
        x509.CRLDistributionPoints
    )
    assert extension.value[0].full_name[0].value == CRL_URL


def test_distribution_points_do_not_break_validation(
    advertising_ca, advertised_leaf
) -> None:
    result = validate_chain(advertised_leaf, [], [advertising_ca.certificate])
    assert result.valid, result.failures


def test_complete_crl_advertises_the_delta_location(advertising_ca) -> None:
    """A client holding the base needs to know deltas exist."""
    crl = advertising_ca.publish_crl()
    extension = crl.extensions.get_extension_for_class(x509.FreshestCRL)
    assert extension.value[0].full_name[0].value == DELTA_URL


# --------------------------------------------------------------------------
# Delta CRL structure
# --------------------------------------------------------------------------


def test_delta_requires_a_base_first(advertising_ca) -> None:
    with pytest.raises(CAStateError, match="before a complete CRL"):
        advertising_ca.publish_delta_crl()


def test_delta_carries_a_critical_delta_crl_indicator(advertising_ca) -> None:
    """Critical on purpose: a client that cannot read it must reject it."""
    advertising_ca.publish_crl()
    delta = advertising_ca.publish_delta_crl()
    extension = delta.extensions.get_extension_for_class(x509.DeltaCRLIndicator)
    assert extension.critical


def test_delta_indicator_names_the_base_crl_number(advertising_ca) -> None:
    base = advertising_ca.publish_crl()
    delta = advertising_ca.publish_delta_crl()
    assert delta_base_number(delta) == crl_number(base)


def test_delta_and_base_share_one_number_sequence(advertising_ca) -> None:
    base = advertising_ca.publish_crl()
    delta = advertising_ca.publish_delta_crl()
    assert crl_number(delta) == crl_number(base) + 1


def test_is_delta_crl_distinguishes_the_two(advertising_ca) -> None:
    base = advertising_ca.publish_crl()
    delta = advertising_ca.publish_delta_crl()
    assert not is_delta_crl(base)
    assert is_delta_crl(delta)


def test_delta_lists_only_revocations_since_the_base(advertising_ca) -> None:
    advertising_ca.revoke(1, x509.ReasonFlags.superseded)
    advertising_ca.revoke(2, x509.ReasonFlags.superseded)
    advertising_ca.publish_crl()

    advertising_ca.revoke(3, x509.ReasonFlags.key_compromise)
    delta = advertising_ca.publish_delta_crl()
    assert [entry.serial_number for entry in delta] == [3]


def test_delta_is_empty_when_nothing_changed(advertising_ca) -> None:
    advertising_ca.revoke(1, x509.ReasonFlags.superseded)
    advertising_ca.publish_crl()
    assert len(list(advertising_ca.publish_delta_crl())) == 0


def test_a_new_base_resets_what_the_delta_reports(advertising_ca) -> None:
    advertising_ca.revoke(1, x509.ReasonFlags.superseded)
    advertising_ca.publish_crl()
    advertising_ca.revoke(2, x509.ReasonFlags.superseded)
    advertising_ca.publish_delta_crl()

    second_base = advertising_ca.publish_crl()
    advertising_ca.revoke(3, x509.ReasonFlags.superseded)
    second_delta = advertising_ca.publish_delta_crl()

    assert delta_base_number(second_delta) == crl_number(second_base)
    assert [entry.serial_number for entry in second_delta] == [3]


def test_base_crl_still_lists_everything(advertising_ca) -> None:
    advertising_ca.revoke(1, x509.ReasonFlags.superseded)
    advertising_ca.publish_crl()
    advertising_ca.revoke(2, x509.ReasonFlags.superseded)
    advertising_ca.publish_delta_crl()

    republished = advertising_ca.publish_crl()
    assert sorted(entry.serial_number for entry in republished) == [1, 2]


def test_delta_is_signed_by_the_ca(advertising_ca) -> None:
    advertising_ca.publish_crl()
    delta = advertising_ca.publish_delta_crl()
    assert delta.is_signature_valid(advertising_ca.certificate.public_key())


def test_delta_is_smaller_than_a_base_with_a_real_backlog(advertising_ca) -> None:
    """The reason delta CRLs exist, for every algorithm."""
    for serial in range(1, 201):
        advertising_ca.revoke(serial, x509.ReasonFlags.superseded)
    base = advertising_ca.publish_crl()

    advertising_ca.revoke(500, x509.ReasonFlags.key_compromise)
    delta = advertising_ca.publish_delta_crl()

    assert len(delta.public_bytes(DER)) < len(base.public_bytes(DER))


# --------------------------------------------------------------------------
# Relying-party behaviour: a delta is never evidence on its own
# --------------------------------------------------------------------------


def test_delta_alone_does_not_count_as_checked(advertising_ca, advertised_leaf) -> None:
    advertising_ca.publish_crl()
    advertising_ca.revoke(advertised_leaf.serial_number, x509.ReasonFlags.key_compromise)
    delta = advertising_ca.publish_delta_crl()

    status = check_revocation(
        advertised_leaf, advertising_ca.certificate, [delta], _now()
    )
    assert not status.checked
    assert not status.revoked


def test_delta_alone_is_reported_as_a_problem(advertising_ca, advertised_leaf) -> None:
    advertising_ca.publish_crl()
    delta = advertising_ca.publish_delta_crl()

    status = check_revocation(
        advertised_leaf, advertising_ca.certificate, [delta], _now()
    )
    assert any("without its base" in problem for problem in status.problems)


def test_delta_with_its_base_reports_the_revocation(
    advertising_ca, advertised_leaf
) -> None:
    base = advertising_ca.publish_crl()
    advertising_ca.revoke(advertised_leaf.serial_number, x509.ReasonFlags.key_compromise)
    delta = advertising_ca.publish_delta_crl()

    status = check_revocation(
        advertised_leaf, advertising_ca.certificate, [base, delta], _now()
    )
    assert status.revoked
    assert status.checked
    assert status.reason is x509.ReasonFlags.key_compromise


def test_base_alone_misses_a_revocation_the_delta_carries(
    advertising_ca, advertised_leaf
) -> None:
    """Shows the delta is doing real work, not duplicating the base."""
    base = advertising_ca.publish_crl()
    advertising_ca.revoke(advertised_leaf.serial_number, x509.ReasonFlags.key_compromise)
    advertising_ca.publish_delta_crl()

    status = check_revocation(
        advertised_leaf, advertising_ca.certificate, [base], _now()
    )
    assert status.checked
    assert not status.revoked


def test_a_delta_for_an_unknown_base_is_rejected(
    advertising_ca, advertised_leaf
) -> None:
    """Supplying a stale base must not silently license a newer delta."""
    stale_base = advertising_ca.publish_crl()
    advertising_ca.publish_crl()  # a second base, which the delta will name
    advertising_ca.revoke(advertised_leaf.serial_number, x509.ReasonFlags.key_compromise)
    delta = advertising_ca.publish_delta_crl()

    status = check_revocation(
        advertised_leaf, advertising_ca.certificate, [stale_base, delta], _now()
    )
    assert not status.revoked
    assert any("without its base" in problem for problem in status.problems)


def test_validate_chain_reports_a_delta_without_its_base(
    advertising_ca, advertised_leaf
) -> None:
    advertising_ca.publish_crl()
    delta = advertising_ca.publish_delta_crl()

    result = validate_chain(
        advertised_leaf, [], [advertising_ca.certificate], crls=[delta]
    )
    assert not result.valid
    assert any(f.startswith(FailureCode.CRL_PROBLEM) for f in result.failures)


def test_validate_chain_rejects_a_certificate_revoked_by_a_delta(
    advertising_ca, advertised_leaf
) -> None:
    base = advertising_ca.publish_crl()
    advertising_ca.revoke(advertised_leaf.serial_number, x509.ReasonFlags.key_compromise)
    delta = advertising_ca.publish_delta_crl()

    result = validate_chain(
        advertised_leaf, [], [advertising_ca.certificate], crls=[base, delta]
    )
    assert not result.valid
    assert any(f.startswith(FailureCode.REVOKED) for f in result.failures)


def test_remove_from_crl_in_a_delta_withdraws_a_revocation(
    advertising_ca, advertised_leaf
) -> None:
    """A delta may un-revoke, which is the one case where its entry is not bad.

    This CA never issues such an entry, so the delta is hand-built -- the point
    is that the relying-party half reads someone else's correctly.
    """
    advertising_ca.revoke(advertised_leaf.serial_number, x509.ReasonFlags.certificate_hold)
    base = advertising_ca.publish_crl()

    now = _now().replace(microsecond=0)
    entry = (
        x509.RevokedCertificateBuilder()
        .serial_number(advertised_leaf.serial_number)
        .revocation_date(now)
        .add_extension(
            x509.CRLReason(x509.ReasonFlags.remove_from_crl), critical=False
        )
        .build()
    )
    delta = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(advertising_ca.certificate.subject)
        .last_update(now)
        .next_update(now + datetime.timedelta(days=1))
        .add_extension(x509.CRLNumber(crl_number(base) + 1), critical=False)
        .add_extension(x509.DeltaCRLIndicator(crl_number(base)), critical=True)
        .add_revoked_certificate(entry)
        .sign(advertising_ca.private_key, *advertising_ca.algorithm.sign_args())
    )

    held = check_revocation(
        advertised_leaf, advertising_ca.certificate, [base], _now()
    )
    assert held.revoked

    released = check_revocation(
        advertised_leaf, advertising_ca.certificate, [base, delta], _now()
    )
    assert not released.revoked
    assert released.checked
