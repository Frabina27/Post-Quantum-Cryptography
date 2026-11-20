"""
Hardening tests for the Hybrid KEM (v2 combiner).

Covers: transcript binding in the KDF, strict parsing of every encoding,
envelope bounds checks, AAD binding, and rejection of malformed classical
inputs. The functional and tampering tests live in test_hybrid.py.
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


@pytest.mark.parametrize(
    "mutate",
    [
        pytest.param(lambda ct, pk: (replace(ct, pq_ciphertext_bytes=_flip_last(ct.pq_ciphertext_bytes)), pk), id="pq_ct"),
        pytest.param(lambda ct, pk: (replace(ct, classical_ephemeral_pub_bytes=_flip_last(ct.classical_ephemeral_pub_bytes)), pk), id="classical_ct"),
        pytest.param(lambda ct, pk: (ct, replace(pk, pq_bytes=_flip_last(pk.pq_bytes))), id="pq_pk"),
        pytest.param(lambda ct, pk: (ct, replace(pk, classical_bytes=_flip_last(pk.classical_bytes))), id="classical_pk"),
    ],
)
def test_kdf_binds_every_transcript_field(mutate):
    """Same shared secrets, but any changed ciphertext or key field gives a different key."""
    pub, _ = generate_keypair(PROFILE_X25519_MLKEM768)
    ct, _ = encapsulate(pub)
    pq_ss, classical_ss = b"\x11" * 32, b"\x22" * 32

    def derive(c, p):
        return hybrid_kem._combine_secrets(
            profile=PROFILE_X25519_MLKEM768,
            pq_ss=pq_ss,
            classical_ss=classical_ss,
            ciphertext=c,
            recipient_public_key=p,
        )

    baseline = derive(ct, pub)
    assert derive(*mutate(ct, pub)) != baseline


def test_kdf_is_order_sensitive_in_secrets():
    """Swapping the two secrets must not give the same key (ss_pq comes first)."""
    pub, _ = generate_keypair(PROFILE_X25519_MLKEM768)
    ct, _ = encapsulate(pub)
    a, b = b"\x01" * 32, b"\x02" * 32
    common = dict(profile=PROFILE_X25519_MLKEM768, ciphertext=ct, recipient_public_key=pub)
    assert hybrid_kem._combine_secrets(pq_ss=a, classical_ss=b, **common) != hybrid_kem._combine_secrets(
        pq_ss=b, classical_ss=a, **common
    )


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


def test_v1_ciphertext_magic_rejected():
    """A v1 (old combiner) ciphertext must fail to parse instead of deriving a wrong key."""
    pub, _ = generate_keypair(PROFILE_X25519_MLKEM768)
    ct, _ = encapsulate(pub)
    v1 = b"HKCT1" + ct.to_bytes()[len(hybrid_kem._MAGIC_CT):]
    with pytest.raises(ValueError, match="magic"):
        HybridCiphertext.from_bytes(v1)


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
