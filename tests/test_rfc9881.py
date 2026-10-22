"""RFC 9881 conformance, asserted against the DER rather than the library.

RFC 9881 ("Use of ML-DSA in X.509 Certificates") makes claims about bytes. The
central one is that an ML-DSA ``AlgorithmIdentifier`` carries **no**
``parameters`` field -- not an explicit NULL, which is what RSA uses and what a
naive implementation would copy. ``pyca`` reports both cases identically as
``signature_algorithm_parameters is None``, so these tests read the encoding
directly via :mod:`derutil`.

The three families encode differently, and all three are correct:

===========  ====================  =========================
family       signature parameters  SPKI parameters
===========  ====================  =========================
ML-DSA       absent (RFC 9881)     absent (RFC 9881)
ECDSA        absent                present -- the curve OID
RSA          NULL (RFC 4055)       NULL (RFC 4055)
===========  ====================  =========================

Asserting all three rather than just ML-DSA is the point: "absent" is not a
universal rule, it is specific to ML-DSA, and a test that only looked at
ML-DSA would pass just as well against an implementation that wrongly dropped
RSA's NULL.
"""

from __future__ import annotations

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization

import derutil
from conftest import Hierarchy
from pqpki import generate_csr, validate_chain
from pqpki.algorithms import get_algorithm

ML_DSA_OIDS = {
    "ml-dsa-44": "2.16.840.1.101.3.4.3.17",
    "ml-dsa-65": "2.16.840.1.101.3.4.3.18",
    "ml-dsa-87": "2.16.840.1.101.3.4.3.19",
}

#: Raw ML-DSA signature sizes from FIPS 204, used to confirm these are the
#: pure algorithms rather than a pre-hash variant or a different parameter set.
ML_DSA_SIGNATURE_SIZES = {"ml-dsa-44": 2420, "ml-dsa-65": 3309, "ml-dsa-87": 4627}


def _der(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.DER)


# --------------------------------------------------------------------------
# OIDs
# --------------------------------------------------------------------------


@pytest.mark.parametrize(("name", "expected"), sorted(ML_DSA_OIDS.items()))
def test_ml_dsa_oid_in_the_encoding(name: str, expected: str) -> None:
    """The OID must be right in the DER, not merely in our registry."""
    from conftest import build_hierarchy

    der = _der(build_hierarchy(name).leaf)
    assert derutil.algorithm_oid(derutil.outer_algorithm_identifier(der)) == expected
    assert derutil.algorithm_oid(derutil.tbs_algorithm_identifier(der)) == expected
    assert (
        derutil.algorithm_oid(
            derutil.subject_public_key_algorithm_identifier(der)
        )
        == expected
    )


# --------------------------------------------------------------------------
# The parameters field
# --------------------------------------------------------------------------


def _expected_parameters(algorithm: str) -> tuple[bytes | None, str]:
    """Return (expected signature parameters, expected SPKI parameter kind)."""
    spec = get_algorithm(algorithm)
    if spec.is_post_quantum:
        return None, "absent"
    if spec.hash_algorithm is not None and algorithm.startswith("rsa"):
        return derutil.DER_NULL, "null"
    return None, "present"


def test_signature_algorithm_parameters(hierarchy: Hierarchy) -> None:
    """RFC 9881: absent for ML-DSA. RFC 4055: NULL for RSA."""
    expected, _ = _expected_parameters(hierarchy.algorithm)
    for cert in hierarchy.chain:
        algid = derutil.outer_algorithm_identifier(_der(cert))
        actual = derutil.parameters(algid)
        if expected is None:
            assert actual is None, (
                f"{hierarchy.algorithm}: signatureAlgorithm carries a "
                f"parameters field ({actual.raw.hex()}) where RFC 9881 "
                f"requires it to be absent"
            )
        else:
            assert actual is not None and actual.raw == expected


def test_subject_public_key_parameters(hierarchy: Hierarchy) -> None:
    """The SPKI identifier is covered by RFC 9881 too, not just the signature."""
    _, kind = _expected_parameters(hierarchy.algorithm)
    algid = derutil.subject_public_key_algorithm_identifier(_der(hierarchy.leaf))
    actual = derutil.parameters(algid)

    if kind == "absent":
        assert actual is None
    elif kind == "null":
        assert actual is not None and actual.raw == derutil.DER_NULL
    else:
        # ECDSA: the named curve, which must be there and must not be NULL.
        assert actual is not None and actual.raw != derutil.DER_NULL


@pytest.mark.parametrize("name", sorted(ML_DSA_OIDS))
def test_ml_dsa_never_carries_null_parameters_anywhere(name: str) -> None:
    """The single assertion RFC 9881 conformance most depends on."""
    from conftest import build_hierarchy

    hierarchy = build_hierarchy(name)
    crl = hierarchy.intermediate_ca.publish_crl()
    csr = generate_csr("conformance.example", hierarchy.leaf_key)

    encodings = [_der(cert) for cert in hierarchy.chain]
    encodings.append(crl.public_bytes(serialization.Encoding.DER))

    for der in encodings:
        assert derutil.parameters(derutil.outer_algorithm_identifier(der)) is None
        assert derutil.parameters(derutil.tbs_algorithm_identifier(der)) is None

    csr_der = csr.public_bytes(serialization.Encoding.DER)
    assert derutil.parameters(derutil.outer_algorithm_identifier(csr_der)) is None
    assert (
        derutil.parameters(
            derutil.csr_subject_public_key_algorithm_identifier(csr_der)
        )
        is None
    )


# --------------------------------------------------------------------------
# Outer signatureAlgorithm must equal inner TBSCertificate.signature
# --------------------------------------------------------------------------


def test_outer_and_inner_algorithm_identifiers_are_identical(
    hierarchy: Hierarchy,
) -> None:
    """RFC 5280 4.1.1.2: the two must match, byte for byte.

    The inner one is inside the signed region and the outer one is not, so a
    mismatch is how a substitution attack on the algorithm identifier would
    look.
    """
    for cert in hierarchy.chain:
        der = _der(cert)
        outer = derutil.outer_algorithm_identifier(der)
        inner = derutil.tbs_algorithm_identifier(der)
        assert outer.raw == inner.raw
        assert derutil.algorithm_oid(outer) == hierarchy.spec.oid


def test_crl_outer_and_inner_algorithm_identifiers_match(
    hierarchy: Hierarchy,
) -> None:
    """CRLs carry the same duplicated field and the same requirement."""
    crl = hierarchy.intermediate_ca.publish_crl()
    der = crl.public_bytes(serialization.Encoding.DER)
    assert (
        derutil.outer_algorithm_identifier(der).raw
        == derutil.tbs_algorithm_identifier(der).raw
    )
    assert crl.signature_algorithm_oid.dotted_string == hierarchy.spec.oid


# --------------------------------------------------------------------------
# Negative: an AlgorithmIdentifier carrying NULL parameters
# --------------------------------------------------------------------------


def _require_absent_parameters(hierarchy: Hierarchy) -> bytes:
    """Skip families where NULL parameters are correct, and return the DER.

    RSA legitimately carries NULL in its signature AlgorithmIdentifier per RFC
    4055, so there is no violation to inject: splicing a NULL into an
    identifier that already has one reproduces the original bytes exactly. The
    injection tests are meaningful only where absence is the rule, which is
    ML-DSA (RFC 9881) and ECDSA.
    """
    der = _der(hierarchy.leaf)
    if derutil.has_parameters(derutil.outer_algorithm_identifier(der)):
        pytest.skip(
            f"{hierarchy.algorithm} correctly carries NULL parameters already, "
            f"so a NULL cannot be injected as a violation"
        )
    return der


def test_null_parameters_are_detectable_in_the_encoding(
    hierarchy: Hierarchy,
) -> None:
    """Confirm the conformance check can actually see a violation.

    Without this, the absence assertions above could be passing because the
    helper never detects anything.
    """
    der = _require_absent_parameters(hierarchy)
    tampered = derutil.splice_outer_parameters(der, derutil.DER_NULL)

    algid = derutil.outer_algorithm_identifier(tampered)
    assert derutil.has_parameters(algid) is True
    assert derutil.parameters(algid).raw == derutil.DER_NULL
    # The inner identifier is untouched, so the two no longer agree.
    assert algid.raw != derutil.tbs_algorithm_identifier(tampered).raw


def test_certificate_with_null_parameters_is_rejected(hierarchy: Hierarchy) -> None:
    """A spliced NULL must not survive into a usable certificate.

    Only the *outer* identifier is modified, which is deliberately the hard
    case: it sits outside the signed region, so the signature over the body
    remains intact and a validator cannot catch this by signature check alone.
    """
    tampered = derutil.splice_outer_parameters(_require_absent_parameters(hierarchy))

    with pytest.raises(ValueError) as excinfo:
        x509.load_der_x509_certificate(tampered)

    # pyca refuses at parse time, so the bad encoding never reaches validation.
    assert "signature_alg" in str(excinfo.value) or "ExtraData" in str(excinfo.value)


# --------------------------------------------------------------------------
# Pure ML-DSA, not pre-hash, empty context
# --------------------------------------------------------------------------


@pytest.mark.parametrize("name", sorted(ML_DSA_SIGNATURE_SIZES))
def test_signature_size_matches_pure_ml_dsa(name: str) -> None:
    """A pre-hash variant would have a different OID and a different size."""
    from conftest import build_hierarchy

    hierarchy = build_hierarchy(name)
    assert len(hierarchy.leaf.signature) == ML_DSA_SIGNATURE_SIZES[name]


@pytest.mark.parametrize("name", sorted(ML_DSA_OIDS))
def test_signature_verifies_with_empty_context(name: str) -> None:
    """X.509 signing context is empty, so a plain verify must succeed.

    ``pyca``'s ``verify(signature, data)`` uses an empty context. If anything
    in the signing path had set one, this would fail.
    """
    from conftest import build_hierarchy

    hierarchy = build_hierarchy(name)
    issuer_key = hierarchy.intermediate.public_key()
    issuer_key.verify(
        hierarchy.leaf.signature, hierarchy.leaf.tbs_certificate_bytes
    )


# --------------------------------------------------------------------------
# Phase 3 acceptance: the PQ path is the classical path
# --------------------------------------------------------------------------


def test_post_quantum_chain_validates_through_the_same_code(
    hierarchy: Hierarchy,
) -> None:
    """The Phase 3 criterion, asserted for every algorithm at once.

    This test does not know or care whether ``hierarchy`` is classical or
    post-quantum. If switching algorithm required a different code path, this
    would fail for one family or the other.
    """
    result = validate_chain(
        hierarchy.leaf, [hierarchy.intermediate], [hierarchy.root]
    )
    assert result.valid, result.failures
    assert result.chain_length == 3
    assert set(result.algorithms_used) == {hierarchy.algorithm}


def test_both_families_are_actually_represented() -> None:
    """Guard against the parameterization quietly losing one family."""
    from conftest import ALL_ALGORITHMS

    specs = [get_algorithm(name) for name in ALL_ALGORITHMS]
    assert any(spec.is_post_quantum for spec in specs)
    assert any(not spec.is_post_quantum for spec in specs)
