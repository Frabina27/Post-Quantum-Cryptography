"""
Known-answer tests: the hybrid KEM against the published specifications.

- X25519 profile vs X-Wing, draft-connolly-cfrg-xwing-kem-11, Appendix C.
- P-256 profile vs id-MLKEM768-ECDH-P256-SHA3-256,
  draft-ietf-lamps-pq-composite-kem-23, Appendix G.
- Combiner intermediate values for both, from the same LAMPS draft, Appendix F.

The vectors live in kat/*.json (hex). X-Wing's deterministic encapsulation
needs ML-KEM Encaps_internal(ek, m), which `cryptography` does not expose, so
that one test uses the team's own FIPS 203 implementation in Kyber/mlkem.py.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

_MODULE_DIR = Path(__file__).resolve().parent
_KYBER_DIR = _MODULE_DIR.parent / "Kyber"
for p in (_MODULE_DIR, _KYBER_DIR):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, x25519

import hybrid_kem
from hybrid_kem import (
    PROFILE_P256_MLKEM768,
    PROFILE_X25519_MLKEM768,
    HybridCiphertext,
    HybridKEMPrivateKey,
    HybridKEMPublicKey,
    combine_secrets,
    decapsulate,
    encapsulate,
)


def _load(name: str) -> dict[str, bytes]:
    raw = json.loads((_MODULE_DIR / "kat" / name).read_text())
    return {k: bytes.fromhex(v) for k, v in raw.items() if k != "source"}


XWING = _load("xwing.json")
P256 = _load("composite_mlkem768_p256.json")


# ----------------------------------------------------------------------------
# Combiner intermediate values (LAMPS Composite ML-KEM, Appendix F)
# ----------------------------------------------------------------------------


@pytest.mark.parametrize(
    "profile, ss_m, ss_t, ct_t, pk_t, expected",
    [
        pytest.param(
            PROFILE_P256_MLKEM768,
            "ca48920ded22e063f98a79a4091508678b7042cab63f78c571ff392e82612d43",
            "ef1c92443aaf987000e3470d34332b4c53ff0cdd4554b6bf377bf7bdb677d3d0",
            "041d155f6d3078d7e2cd4f9f758947029795dd9ab6d6e92d81d19171270cdefcd4"
            "abb682edbb22faf961ce75fc688109931bfa24468f646b97eca4d57d5f5e7610",
            "04ba2bfbf7b91182eb1fad54a2940c8b1dfd53de55fa3c02d199a3159ff73d38d2"
            "9aa94f32e3e82bcc99b165320297149455997d7c3ea5ac97cd987d3e80396a3e",
            "d6c69aa6e986b620a2777d8cf1fb6be1b2255d6efae0566deb34c882b38846ee",
            id="MLKEM768-ECDH-P256",
        ),
        pytest.param(
            PROFILE_X25519_MLKEM768,
            "461b74b074818906edcd2fd976008caca5247f496670ae86e34abe35e62a7ae1",
            "4c62bd6d6f76294f3c14d7e79dbf56e4bf82cb1fb803accfaf2a59c1663a8843",
            "0ec7210a4aa22bb75af9243f95a6ccf857e872efbe5e77e8e917b56178fa473f",
            "1e9d4f72d56cef589864e102c6d6fa86cd3ac5163839556f7555ad083f37b03b",
            "21ee673fdeac21dd78ef13bc8432a50c0ac31893cbe97d14c0e82f5fe4a28d98",
            id="MLKEM768-X25519",
        ),
    ],
)
def test_combiner_intermediate_values(profile, ss_m, ss_t, ct_t, pk_t, expected):
    h = bytes.fromhex
    assert combine_secrets(profile, h(ss_m), h(ss_t), h(ct_t), h(pk_t)) == h(expected)


# ----------------------------------------------------------------------------
# X-Wing (X25519 profile)
# ----------------------------------------------------------------------------


def test_xwing_key_derivation_from_seed():
    priv = HybridKEMPrivateKey.from_xwing_seed(XWING["seed"])
    assert priv.public_key().to_composite_bytes() == XWING["pk"]


def test_xwing_decapsulation():
    priv = HybridKEMPrivateKey.from_xwing_seed(XWING["seed"])
    ct = HybridCiphertext.from_composite_bytes(PROFILE_X25519_MLKEM768, XWING["ct"])
    assert decapsulate(priv, ct) == XWING["ss"]


def test_xwing_derandomized_encapsulation():
    """EncapsulateDerand(pk, eseed) must give exactly the vector's ct and ss."""
    from mlkem import MLKEM_Encaps_internal  # team FIPS 203 implementation

    pub = HybridKEMPublicKey.from_composite_bytes(PROFILE_X25519_MLKEM768, XWING["pk"])
    eseed = XWING["eseed"]

    ss_m, ct_m = MLKEM_Encaps_internal(pub.pq_bytes, eseed[:32], "ML-KEM-768")
    eph = x25519.X25519PrivateKey.from_private_bytes(eseed[32:64])
    ct_x = eph.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    ss_x = eph.exchange(x25519.X25519PublicKey.from_public_bytes(pub.classical_bytes))

    ct = HybridCiphertext(PROFILE_X25519_MLKEM768, ct_x, ct_m)
    assert ct.to_composite_bytes() == XWING["ct"]
    assert combine_secrets(PROFILE_X25519_MLKEM768, ss_m, ss_x, ct_x, pub.classical_bytes) == XWING["ss"]


def test_xwing_encapsulate_to_vector_key_roundtrips():
    """Randomized encapsulation to the spec's key decapsulates with the spec's private key."""
    pub = HybridKEMPublicKey.from_composite_bytes(PROFILE_X25519_MLKEM768, XWING["pk"])
    ct, ss = encapsulate(pub)
    assert len(ct.to_composite_bytes()) == 1120
    assert decapsulate(HybridKEMPrivateKey.from_xwing_seed(XWING["seed"]), ct) == ss


def test_generate_keypair_x25519_has_xwing_sizes():
    """Freshly generated X25519 keys have the X-Wing encapsulation key size."""
    pub, _ = hybrid_kem.generate_keypair(PROFILE_X25519_MLKEM768)
    assert len(pub.to_composite_bytes()) == 1216


def test_xwing_seed_length_enforced():
    with pytest.raises(ValueError, match="32 bytes"):
        HybridKEMPrivateKey.from_xwing_seed(XWING["seed"][:-1])


# ----------------------------------------------------------------------------
# LAMPS Composite ML-KEM, id-MLKEM768-ECDH-P256-SHA3-256 (P-256 profile)
# ----------------------------------------------------------------------------


def test_p256_private_key_import_matches_public_key():
    priv = HybridKEMPrivateKey.from_composite_bytes(PROFILE_P256_MLKEM768, P256["dk"])
    assert priv.public_key().to_composite_bytes() == P256["ek"]


def test_p256_private_key_export_is_byte_exact():
    priv = HybridKEMPrivateKey.from_composite_bytes(PROFILE_P256_MLKEM768, P256["dk"])
    assert priv.to_composite_bytes() == P256["dk"]


def test_p256_decapsulation():
    priv = HybridKEMPrivateKey.from_composite_bytes(PROFILE_P256_MLKEM768, P256["dk"])
    ct = HybridCiphertext.from_composite_bytes(PROFILE_P256_MLKEM768, P256["c"])
    assert decapsulate(priv, ct) == P256["k"]


def test_p256_encapsulate_to_vector_key_roundtrips():
    pub = HybridKEMPublicKey.from_composite_bytes(PROFILE_P256_MLKEM768, P256["ek"])
    ct, ss = encapsulate(pub)
    assert len(ct.to_composite_bytes()) == 1153
    priv = HybridKEMPrivateKey.from_composite_bytes(PROFILE_P256_MLKEM768, P256["dk"])
    assert decapsulate(priv, ct) == ss


def test_p256_ecprivatekey_with_public_key_field_rejected():
    """The spec forbids the optional publicKey field, so OpenSSL's usual encoding is refused."""
    openssl_der = ec.generate_private_key(ec.SECP256R1()).private_bytes(
        serialization.Encoding.DER,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )
    with pytest.raises(ValueError, match="RFC 5915"):
        HybridKEMPrivateKey.from_composite_bytes(PROFILE_P256_MLKEM768, P256["dk"][:64] + openssl_der)


# ----------------------------------------------------------------------------
# Composite encodings round trip and are strict (both profiles)
# ----------------------------------------------------------------------------


@pytest.mark.parametrize("profile", [PROFILE_X25519_MLKEM768, PROFILE_P256_MLKEM768])
def test_composite_encodings_roundtrip(profile):
    pub, priv = hybrid_kem.generate_keypair(profile)
    ct, ss = encapsulate(pub)

    assert HybridKEMPublicKey.from_composite_bytes(profile, pub.to_composite_bytes()) == pub
    assert HybridCiphertext.from_composite_bytes(profile, ct.to_composite_bytes()) == ct
    restored = HybridKEMPrivateKey.from_composite_bytes(profile, priv.to_composite_bytes())
    assert restored.public_key() == pub
    assert decapsulate(restored, ct) == ss


@pytest.mark.parametrize("profile", [PROFILE_X25519_MLKEM768, PROFILE_P256_MLKEM768])
def test_composite_encodings_reject_wrong_length(profile):
    pub, priv = hybrid_kem.generate_keypair(profile)
    ct, _ = encapsulate(pub)
    with pytest.raises(ValueError):
        HybridKEMPublicKey.from_composite_bytes(profile, pub.to_composite_bytes()[:-1])
    with pytest.raises(ValueError):
        HybridCiphertext.from_composite_bytes(profile, ct.to_composite_bytes() + b"\x00")
    with pytest.raises(ValueError):
        HybridKEMPrivateKey.from_composite_bytes(profile, priv.to_composite_bytes()[:-1])
