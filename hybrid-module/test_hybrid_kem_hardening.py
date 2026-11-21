"""
Hardening tests for the Hybrid KEM (v3, standard SHA3-256 combiner).

Covers: what the combiner binds, strict parsing of every encoding, envelope
bounds checks, AAD binding, and rejection of malformed classical inputs.
Known-answer tests against the specs live in test_hybrid_kem_kat.py; the
functional and tampering tests live in test_hybrid.py.
"""

from __future__ import annotations

import sys
from dataclasses import replace
from pathlib import Path

_MODULE_DIR = Path(__file__).resolve().parent
if str(_MODULE_DIR) not in sys.path:
    sys.path.insert(0, str(_MODULE_DIR))

import pytest
from cryptography.hazmat.primitives.asymmetric import ec, mlkem

import hybrid_kem
from hybrid_kem import (
    PROFILE_P256_MLKEM768,
    PROFILE_X25519_MLKEM768,
    DecapsulationError,
    DecryptionError,
    HybridCiphertext,
    HybridEncryptedMessage,
    HybridKEMPrivateKey,
    HybridKEMPublicKey,
    decapsulate,
    decrypt_message,
    encapsulate,
    encrypt_message,
    generate_keypair,
)

PROFILES = [PROFILE_X25519_MLKEM768, PROFILE_P256_MLKEM768]


# ----------------------------------------------------------------------------
# Round trips over both profiles and the full wire encoding
# ----------------------------------------------------------------------------


@pytest.mark.parametrize("profile", PROFILES)
def test_envelope_wire_roundtrip(profile):
    """Encrypt, serialize the whole envelope, parse it back, decrypt."""
    pub, priv = generate_keypair(profile)
    restored_pub = HybridKEMPublicKey.from_bytes(pub.to_bytes())

    enc = encrypt_message(restored_pub, b"payload", associated_data=b"ctx")
    parsed = HybridEncryptedMessage.from_bytes(enc.to_bytes())

    assert parsed == enc
    assert decrypt_message(priv, parsed, associated_data=b"ctx") == b"payload"


@pytest.mark.parametrize("profile", PROFILES)
def test_encapsulation_is_randomized(profile):
    """Two encapsulations to the same key give different ciphertexts and keys."""
    pub, _ = generate_keypair(profile)
    ct1, k1 = encapsulate(pub)
    ct2, k2 = encapsulate(pub)
    assert ct1 != ct2
    assert k1 != k2


# ----------------------------------------------------------------------------
# KDF transcript binding
# ----------------------------------------------------------------------------


def _flip_last(data: bytes) -> bytes:
    return data[:-1] + bytes([data[-1] ^ 0x01])


_SS_M, _SS_T = b"\x11" * 32, b"\x22" * 32


@pytest.mark.parametrize("profile", PROFILES)
@pytest.mark.parametrize("field", ["classical_ct", "classical_pk"])
def test_combiner_binds_classical_ciphertext_and_key(profile, field):
    """Same secrets, but a changed ct_T or pk_T gives a different key (ECDH alone is not IND-CCA)."""
    n = hybrid_kem._CLASSICAL_PUB_LEN[profile]
    args = {"classical_ct": b"\x33" * n, "classical_pk": b"\x44" * n}
    baseline = hybrid_kem.combine_secrets(profile, _SS_M, _SS_T, **args)
    args[field] = _flip_last(args[field])
    assert hybrid_kem.combine_secrets(profile, _SS_M, _SS_T, **args) != baseline


def test_combiner_is_order_sensitive_in_secrets():
    """Swapping the two secrets must not give the same key (ss_M comes first)."""
    ct_pk = dict(classical_ct=b"\x33" * 32, classical_pk=b"\x44" * 32)
    assert hybrid_kem.combine_secrets(
        PROFILE_X25519_MLKEM768, _SS_M, _SS_T, **ct_pk
    ) != hybrid_kem.combine_secrets(PROFILE_X25519_MLKEM768, _SS_T, _SS_M, **ct_pk)


def test_combiner_labels_are_domain_separated():
    """Profiles use distinct spec labels, so identical inputs never collide across profiles."""
    labels = hybrid_kem.COMBINER_LABELS
    assert labels[PROFILE_X25519_MLKEM768] == bytes.fromhex("5c2e2f2f5e5c")
    assert labels[PROFILE_P256_MLKEM768] == b"MLKEM768-P256"


@pytest.mark.parametrize(
    "kwargs",
    [
        dict(pq_ss=b"\x00" * 31, classical_ss=_SS_T, classical_ct=b"\x00" * 32, classical_pk=b"\x00" * 32),
        dict(pq_ss=_SS_M, classical_ss=_SS_T, classical_ct=b"\x00" * 33, classical_pk=b"\x00" * 32),
        dict(pq_ss=_SS_M, classical_ss=_SS_T, classical_ct=b"\x00" * 32, classical_pk=b"\x00" * 65),
    ],
)
def test_combiner_rejects_wrong_input_lengths(kwargs):
    """Fixed-length inputs are what make the plain concatenation unambiguous."""
    with pytest.raises(ValueError):
        hybrid_kem.combine_secrets(PROFILE_X25519_MLKEM768, **kwargs)


@pytest.mark.parametrize("profile", PROFILES)
def test_tampered_mlkem_ciphertext_changes_key(profile):
    """ct_M is bound through ss_M: ML-KEM implicit rejection yields an unrelated key."""
    pub, priv = generate_keypair(profile)
    ct, key = encapsulate(pub)
    bad = replace(ct, pq_ciphertext_bytes=_flip_last(ct.pq_ciphertext_bytes))
    assert decapsulate(priv, bad) != key


# ----------------------------------------------------------------------------
# Strict parsing
# ----------------------------------------------------------------------------


@pytest.mark.parametrize("bad_profile_byte", [0, 3, 0xFF])
def test_unknown_profile_byte_rejected(bad_profile_byte):
    """Unknown profile identifiers must be rejected, not silently mapped to P-256."""
    pub, _ = generate_keypair(PROFILE_X25519_MLKEM768)
    ct, _ = encapsulate(pub)

    for obj, magic in ((pub, hybrid_kem._MAGIC_PUB), (ct, hybrid_kem._MAGIC_CT)):
        data = bytearray(obj.to_bytes())
        data[len(magic)] = bad_profile_byte
        with pytest.raises(ValueError, match="Unknown profile"):
            type(obj).from_bytes(bytes(data))


def test_unknown_profile_rejected_on_serialize():
    bogus = HybridKEMPublicKey(profile="rsa_mlkem768", classical_bytes=b"x", pq_bytes=b"y")  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="Unsupported profile"):
        bogus.to_bytes()


@pytest.mark.parametrize("profile", PROFILES)
def test_wrong_component_lengths_rejected(profile):
    """Headers whose lengths don't match the profile's fixed sizes are rejected."""
    pub, _ = generate_keypair(profile)
    ct, _ = encapsulate(pub)

    bad_objects = [
        replace(pub, classical_bytes=pub.classical_bytes[:-1]),
        replace(pub, pq_bytes=pub.pq_bytes + b"\x00"),
        replace(ct, classical_ephemeral_pub_bytes=ct.classical_ephemeral_pub_bytes + b"\x00"),
        replace(ct, pq_ciphertext_bytes=ct.pq_ciphertext_bytes[:-1]),
    ]
    for obj in bad_objects:
        with pytest.raises(ValueError, match="must be"):
            type(obj).from_bytes(obj.to_bytes())


def test_trailing_bytes_rejected():
    pub, _ = generate_keypair(PROFILE_X25519_MLKEM768)
    with pytest.raises(ValueError, match="Length mismatch"):
        HybridKEMPublicKey.from_bytes(pub.to_bytes() + b"\x00")


@pytest.mark.parametrize("old_magic", [b"HKCT1", b"HKCT2"])
def test_old_ciphertext_magic_rejected(old_magic):
    """A ciphertext from an older combiner must fail to parse instead of deriving a wrong key."""
    pub, _ = generate_keypair(PROFILE_X25519_MLKEM768)
    ct, _ = encapsulate(pub)
    old = old_magic + ct.to_bytes()[len(hybrid_kem._MAGIC_CT):]
    with pytest.raises(ValueError, match="magic"):
        HybridCiphertext.from_bytes(old)


def test_envelope_truncation_rejected():
    pub, _ = generate_keypair(PROFILE_X25519_MLKEM768)
    data = encrypt_message(pub, b"").to_bytes()  # empty plaintext: payload is just the 16 B tag

    for cut in (1, 16, 17, len(data) - 3):
        with pytest.raises(ValueError):
            HybridEncryptedMessage.from_bytes(data[:-cut])
    with pytest.raises(ValueError):
        HybridEncryptedMessage.from_bytes(data[:3])


def test_envelope_bad_nonce_length_rejected():
    pub, priv = generate_keypair(PROFILE_X25519_MLKEM768)
    enc = encrypt_message(pub, b"msg")

    short = replace(enc, nonce=enc.nonce[:-1])
    with pytest.raises(ValueError, match="nonce"):
        HybridEncryptedMessage.from_bytes(short.to_bytes())
    with pytest.raises(DecryptionError, match="nonce"):
        decrypt_message(priv, short)


# ----------------------------------------------------------------------------
# Decapsulation / decryption failures
# ----------------------------------------------------------------------------


@pytest.mark.parametrize("profile", PROFILES)
def test_tampered_classical_ephemeral_key_rejected(profile):
    """Altering the ECDH half of the ciphertext must break decryption."""
    pub, priv = generate_keypair(profile)
    enc = encrypt_message(pub, b"secret")
    ct = enc.hybrid_ciphertext
    bad_ct = replace(ct, classical_ephemeral_pub_bytes=_flip_last(ct.classical_ephemeral_pub_bytes))

    # X25519: still a valid point, so a different key -> GCM failure.
    # P-256: usually no longer on the curve -> decapsulation failure.
    with pytest.raises((DecapsulationError, DecryptionError)):
        decrypt_message(priv, replace(enc, hybrid_ciphertext=bad_ct))


def test_x25519_low_order_point_rejected():
    """An all-zero X25519 ephemeral key (low-order point) must not be accepted."""
    pub, priv = generate_keypair(PROFILE_X25519_MLKEM768)
    ct, _ = encapsulate(pub)
    with pytest.raises(DecapsulationError, match="Classical ECDH"):
        decapsulate(priv, replace(ct, classical_ephemeral_pub_bytes=b"\x00" * 32))


def test_p256_off_curve_point_rejected():
    pub, priv = generate_keypair(PROFILE_P256_MLKEM768)
    ct, _ = encapsulate(pub)
    off_curve = b"\x04" + b"\x00" * 31 + b"\x01" + b"\x00" * 31 + b"\x01"
    with pytest.raises(DecapsulationError, match="Classical ECDH"):
        decapsulate(priv, replace(ct, classical_ephemeral_pub_bytes=off_curve))


def test_profile_mismatch_rejected():
    x_pub, _ = generate_keypair(PROFILE_X25519_MLKEM768)
    _, p_priv = generate_keypair(PROFILE_P256_MLKEM768)
    ct, _ = encapsulate(x_pub)
    with pytest.raises(DecapsulationError, match="Profile mismatch"):
        decapsulate(p_priv, ct)


@pytest.mark.parametrize("profile", PROFILES)
def test_wrong_recipient_rejected(profile):
    pub, _ = generate_keypair(profile)
    _, other_priv = generate_keypair(profile)
    enc = encrypt_message(pub, b"for someone else")
    with pytest.raises(DecryptionError):
        decrypt_message(other_priv, enc)


def test_wrong_associated_data_rejected():
    pub, priv = generate_keypair(PROFILE_X25519_MLKEM768)
    enc = encrypt_message(pub, b"msg", associated_data=b"order-42")
    with pytest.raises(DecryptionError):
        decrypt_message(priv, enc, associated_data=b"order-43")


def test_ciphertext_swap_between_messages_rejected():
    """The KEM header of one message cannot be paired with another message's payload."""
    pub, priv = generate_keypair(PROFILE_X25519_MLKEM768)
    enc_a = encrypt_message(pub, b"message A")
    enc_b = encrypt_message(pub, b"message B")
    with pytest.raises(DecryptionError):
        decrypt_message(priv, replace(enc_a, hybrid_ciphertext=enc_b.hybrid_ciphertext))


def test_private_key_rejects_mismatched_classical_key():
    with pytest.raises(TypeError):
        HybridKEMPrivateKey(
            profile=PROFILE_X25519_MLKEM768,
            classical_key=ec.generate_private_key(ec.SECP256R1()),
            pq_key=mlkem.MLKEM768PrivateKey.generate(),
        )
    with pytest.raises(TypeError):
        HybridKEMPrivateKey(
            profile=PROFILE_P256_MLKEM768,
            classical_key=ec.generate_private_key(ec.SECP384R1()),
            pq_key=mlkem.MLKEM768PrivateKey.generate(),
        )
