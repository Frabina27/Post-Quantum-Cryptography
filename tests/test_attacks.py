"""The exported attack vectors, and the tests that they are real attacks.

These tests have an unusual job. :mod:`pqpki.attacks` exists so that the
security-testing module can attack this PKI without reimplementing certificate
surgery, which means the attack set itself is a deliverable and can be wrong in
two directions:

* An attack that does not actually attack anything -- a "tampered" certificate
  identical to the original -- would pass forever while testing nothing. So
  there are tests here that the malformed artifacts really do differ from the
  good ones.
* An attack the PKI fails to repel is a genuine vulnerability. So the headline
  test runs every attack against every algorithm and requires all of them to
  be defended.

The second is the one that matters; the first is what stops it from being
vacuous.
"""

from __future__ import annotations

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from pqpki import validate_chain
from pqpki.attacks import (
    AttackOutcome,
    ChainAttack,
    IssuanceAttack,
    chain_attacks,
    issuance_attacks,
    main,
    run_all,
)
from pqpki.errors import PQPKIError, UnknownAlgorithmError

DER = serialization.Encoding.DER
FAST_ALGORITHM = "ecdsa-p256"


@pytest.fixture(scope="module")
def fast_chain_attacks() -> list[ChainAttack]:
    """Chain attacks for one algorithm, built once -- they cost many keys."""
    return chain_attacks(FAST_ALGORITHM)


@pytest.fixture(scope="module")
def fast_issuance_attacks() -> list[IssuanceAttack]:
    return issuance_attacks(FAST_ALGORITHM)


# --------------------------------------------------------------------------
# The headline claim
# --------------------------------------------------------------------------


def test_every_attack_is_repelled_for_every_algorithm(algorithm) -> None:
    """A failure here is a vulnerability, not a broken test."""
    failed = [o for o in run_all(algorithm) if not o.defended]
    assert not failed, "\n".join(f"{o.name}: {o.detail}" for o in failed)


def test_the_attack_set_is_not_empty(algorithm) -> None:
    """Guards against a refactor that silently drops every case."""
    assert len(run_all(algorithm)) >= 15


def test_the_same_attacks_exist_for_every_algorithm(algorithm) -> None:
    """A classical-only attack set would hide a post-quantum gap."""
    names = {o.name for o in run_all(algorithm)}
    reference = {o.name for o in run_all(FAST_ALGORITHM)}
    assert names == reference


# --------------------------------------------------------------------------
# Each attack, individually, with its name in the test id
# --------------------------------------------------------------------------


def test_each_chain_attack_is_rejected_for_the_right_reason(
    fast_chain_attacks,
) -> None:
    for attack in fast_chain_attacks:
        outcome = attack.run()
        assert outcome.defended, f"{attack.name}: {outcome.detail}"


def test_each_issuance_attack_is_refused(fast_issuance_attacks) -> None:
    for attack in fast_issuance_attacks:
        outcome = attack.run()
        assert outcome.defended, f"{attack.name}: {outcome.detail}"


def test_chain_attack_names_are_unique(fast_chain_attacks) -> None:
    names = [attack.name for attack in fast_chain_attacks]
    assert len(names) == len(set(names))


def test_issuance_attack_names_are_unique(fast_issuance_attacks) -> None:
    names = [attack.name for attack in fast_issuance_attacks]
    assert len(names) == len(set(names))


def test_every_attack_has_a_description(fast_chain_attacks, fast_issuance_attacks) -> None:
    """The descriptions are what the other module prints, so they must exist."""
    for attack in [*fast_chain_attacks, *fast_issuance_attacks]:
        assert attack.description
        assert not attack.description.endswith(".")


def test_issuance_attacks_expect_package_errors(fast_issuance_attacks) -> None:
    """A refusal must be one of this package's errors, not an incidental crash."""
    for attack in fast_issuance_attacks:
        assert issubclass(attack.expected_error, PQPKIError)


# --------------------------------------------------------------------------
# The attacks are real: the artifacts genuinely differ from good ones
# --------------------------------------------------------------------------


def test_the_tampered_certificate_differs_from_a_genuine_one(
    fast_chain_attacks,
) -> None:
    """A 'tampered' certificate identical to the original tests nothing."""
    attack = _by_name(fast_chain_attacks, "tampered-signed-bytes")
    assert attack.leaf.public_bytes(DER) != attack.intermediates[0].public_bytes(DER)
    # The tamper changed the subject, so the signature cannot still match.
    assert not _signature_matches(attack.leaf, attack.intermediates[0])


def test_the_tampered_certificate_still_parses(fast_chain_attacks) -> None:
    """Otherwise the test would exercise the DER parser, not the validator."""
    attack = _by_name(fast_chain_attacks, "tampered-signed-bytes")
    reparsed = x509.load_der_x509_certificate(attack.leaf.public_bytes(DER))
    assert reparsed.serial_number == attack.leaf.serial_number


def test_the_impostor_has_the_same_name_as_the_real_issuer(
    fast_chain_attacks,
) -> None:
    """If the names differed, this would test name chaining instead."""
    attack = _by_name(fast_chain_attacks, "impostor-issuer-same-name")
    assert attack.leaf.issuer == attack.intermediates[0].subject


def test_the_impostor_key_differs_from_the_real_one(fast_chain_attacks) -> None:
    attack = _by_name(fast_chain_attacks, "impostor-issuer-same-name")
    spki = serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    assert attack.leaf.public_key().public_bytes(*spki) != attack.intermediates[
        0
    ].public_key().public_bytes(*spki)


def test_the_forged_crl_names_the_real_issuer(fast_chain_attacks) -> None:
    attack = _by_name(fast_chain_attacks, "forged-crl")
    assert attack.crls is not None
    assert attack.crls[0].issuer == attack.intermediates[0].subject


def test_the_forged_crl_signature_really_is_wrong(fast_chain_attacks) -> None:
    attack = _by_name(fast_chain_attacks, "forged-crl")
    assert attack.crls is not None
    assert not attack.crls[0].is_signature_valid(
        attack.intermediates[0].public_key()
    )


def test_the_end_entity_issuer_asserts_ca_false(fast_chain_attacks) -> None:
    attack = _by_name(fast_chain_attacks, "end-entity-used-as-ca")
    issuer = attack.intermediates[0]
    constraints = issuer.extensions.get_extension_for_class(x509.BasicConstraints)
    assert not constraints.value.ca


def test_the_end_entity_issuer_signature_is_genuine(fast_chain_attacks) -> None:
    """The attack is about authority, not forgery: the signature is real."""
    attack = _by_name(fast_chain_attacks, "end-entity-used-as-ca")
    assert _signature_matches(attack.leaf, attack.intermediates[0])


def test_the_weak_ca_asserts_ca_true_but_withholds_cert_sign(
    fast_chain_attacks,
) -> None:
    attack = _by_name(fast_chain_attacks, "ca-without-key-cert-sign")
    issuer = attack.intermediates[0]
    assert issuer.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
    usage = issuer.extensions.get_extension_for_class(x509.KeyUsage).value
    assert not usage.key_cert_sign


def test_the_orphan_delta_is_actually_a_delta(fast_chain_attacks) -> None:
    from pqpki.revocation import is_delta_crl

    attack = _by_name(fast_chain_attacks, "orphan-delta-crl")
    assert attack.crls is not None
    assert is_delta_crl(attack.crls[0])


def test_the_orphan_delta_would_otherwise_hide_a_revocation(
    fast_chain_attacks,
) -> None:
    """The leaf really is revoked; the delta just cannot prove it alone."""
    attack = _by_name(fast_chain_attacks, "orphan-delta-crl")
    assert attack.crls is not None
    assert (
        attack.crls[0].get_revoked_certificate_by_serial_number(
            attack.leaf.serial_number
        )
        is None
    )


def test_the_revoked_attack_chain_is_otherwise_valid(fast_chain_attacks) -> None:
    """Revocation must be the only thing wrong, or the test proves nothing."""
    attack = _by_name(fast_chain_attacks, "revoked-certificate")
    without_crls = validate_chain(
        attack.leaf, attack.intermediates, attack.trust_roots
    )
    assert without_crls.valid, without_crls.failures


def test_the_expired_attack_chain_is_valid_at_the_right_time(
    fast_chain_attacks,
) -> None:
    attack = _by_name(fast_chain_attacks, "expired-certificate")
    assert validate_chain(attack.leaf, attack.intermediates, attack.trust_roots).valid


# --------------------------------------------------------------------------
# Outcome reporting
# --------------------------------------------------------------------------


def test_an_attack_that_succeeds_is_reported_as_undefended(
    fast_chain_attacks,
) -> None:
    """A deliberately wrong expectation must produce defended=False.

    Without this, a bug that made every outcome defended would pass the whole
    file.
    """
    good = _by_name(fast_chain_attacks, "revoked-certificate")
    mislabelled = ChainAttack(
        name=good.name,
        description=good.description,
        expected_code="not-a-real-failure-code",
        leaf=good.leaf,
        intermediates=good.intermediates,
        trust_roots=good.trust_roots,
        crls=good.crls,
        at_time=good.at_time,
    )
    outcome = mislabelled.run()
    assert not outcome.defended
    assert "rather than the expected" in outcome.detail


def test_a_chain_that_validates_is_reported_as_undefended(
    fast_chain_attacks,
) -> None:
    good = _by_name(fast_chain_attacks, "revoked-certificate")
    not_an_attack = ChainAttack(
        name="actually-fine",
        description="a chain with nothing wrong with it",
        expected_code="revoked",
        leaf=good.leaf,
        intermediates=good.intermediates,
        trust_roots=good.trust_roots,
        crls=None,
    )
    outcome = not_an_attack.run()
    assert not outcome.defended
    assert "ACCEPTED" in outcome.detail


def test_an_allowed_issuance_is_reported_as_undefended() -> None:
    from pqpki.errors import IssuanceError

    permitted = IssuanceAttack(
        name="not-really-forbidden",
        description="an operation that is actually allowed",
        expected_error=IssuanceError,
        attempt=lambda: "this succeeds",
    )
    outcome = permitted.run()
    assert not outcome.defended
    assert "ALLOWED" in outcome.detail


def test_the_wrong_error_type_is_reported_as_undefended() -> None:
    from pqpki.errors import IssuanceError

    wrong = IssuanceAttack(
        name="wrong-error",
        description="an operation that fails for an unrelated reason",
        expected_error=IssuanceError,
        attempt=lambda: 1 / 0,
    )
    outcome = wrong.run()
    assert not outcome.defended
    assert "ZeroDivisionError" in outcome.detail


def test_outcomes_are_immutable() -> None:
    outcome = AttackOutcome("n", "d", defended=True, detail="x")
    with pytest.raises(Exception):
        outcome.defended = False  # type: ignore[misc]


# --------------------------------------------------------------------------
# Command-line interface, which is how the other module may invoke this
# --------------------------------------------------------------------------


def test_main_returns_zero_when_every_attack_is_repelled(capsys) -> None:
    assert main(["--algorithm", FAST_ALGORITHM]) == 0
    assert "attacks repelled" in capsys.readouterr().out


def test_main_prints_a_pass_line_per_attack(capsys) -> None:
    main(["--algorithm", FAST_ALGORITHM])
    output = capsys.readouterr().out
    assert output.count("[PASS]") >= 15
    assert "[FAIL]" not in output


def test_main_verbose_includes_descriptions(capsys) -> None:
    main(["--algorithm", FAST_ALGORITHM, "--verbose"])
    output = capsys.readouterr().out
    assert "->" in output


def test_main_rejects_an_unknown_algorithm() -> None:
    with pytest.raises(SystemExit):
        main(["--algorithm", "rot13"])


def test_chain_attacks_rejects_an_unknown_algorithm() -> None:
    with pytest.raises(UnknownAlgorithmError):
        chain_attacks("rot13")


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------


def _by_name(attacks: list[ChainAttack], name: str) -> ChainAttack:
    for attack in attacks:
        if attack.name == name:
            return attack
    raise AssertionError(f"no attack named {name!r}; got {[a.name for a in attacks]}")


def _signature_matches(cert: x509.Certificate, issuer: x509.Certificate) -> bool:
    """Whether ``cert``'s signature verifies against ``issuer``'s key."""
    from cryptography.exceptions import InvalidSignature

    from pqpki.algorithms import spec_for_key

    spec = spec_for_key(issuer.public_key())
    try:
        spec.verify_signature(
            issuer.public_key(), cert.signature, cert.tbs_certificate_bytes
        )
    except InvalidSignature:
        return False
    return True
