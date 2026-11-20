"""
Hybrid Key Encapsulation Mechanism (KEM) Module.
Combines Classical Key Agreement (X25519 or ECDH P-256) with Post-Quantum KEM (ML-KEM-768).

Standard Alignment:
- Construction follows the same shape as IETF draft-ietf-tls-ecdhe-mlkem
  (X25519MLKEM768) and X-Wing: the ML-KEM shared secret comes first, then the
  ECDH shared secret. The wire format is this project's own, so it is NOT
  byte-compatible with TLS or X-Wing.
- Conforms to NIST FIPS 203 for ML-KEM-768.
- Uses an RFC 5869 / NIST SP 800-56C style HKDF-SHA256 combiner.
- Uses AES-256-GCM for authenticated symmetric payload encryption.

Combiner (v2):
    IKM  = ss_pq || ss_classical
    info = "hybrid-kem-v2" || profile_id
           || lp(ct_pq) || lp(ct_classical) || lp(pk_pq) || lp(pk_classical)
    K    = HKDF-SHA256(salt=None, IKM, info, L=32)
where lp(x) is a 4-byte big-endian length followed by x, and ct_classical is
the sender's ephemeral ECDH public key.

Why the transcript is bound: ECDH on its own is not an IND-CCA KEM. Feeding
the ephemeral key and the recipient's static key into the KDF (as X-Wing
does) is what lets the combined key stay secure when only the classical
half holds. Binding the ML-KEM ciphertext and key too is the "kitchen sink"
approach. It makes the combiner generic instead of relying on ML-KEM's
ciphertext-binding property.

Security Guarantee:
The combined shared secret stays secure as long as AT LEAST ONE of the
constituent primitives (classical or post-quantum) remains uncompromised.
"""

from __future__ import annotations

import os
import struct
from dataclasses import dataclass
from typing import Literal

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, mlkem, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


ProfileType = Literal["x25519_mlkem768", "p256_mlkem768"]

PROFILE_X25519_MLKEM768: ProfileType = "x25519_mlkem768"
PROFILE_P256_MLKEM768: ProfileType = "p256_mlkem768"

_MAGIC_PUB = b"HKPUB1"
# Bumped from HKCT1: v2 changed the combiner, so a v1 ciphertext would
# silently derive a different key. A distinct magic makes that a clear error.
_MAGIC_CT = b"HKCT2"
_KDF_LABEL = b"hybrid-kem-v2"

_PROFILE_TO_BYTE: dict[str, int] = {
    PROFILE_X25519_MLKEM768: 1,
    PROFILE_P256_MLKEM768: 2,
}
_BYTE_TO_PROFILE: dict[int, ProfileType] = {v: k for k, v in _PROFILE_TO_BYTE.items()}  # type: ignore[misc]

# Encoded lengths per profile: X25519 raw = 32 B, P-256 uncompressed point = 65 B.
_CLASSICAL_PUB_LEN: dict[str, int] = {
    PROFILE_X25519_MLKEM768: 32,
    PROFILE_P256_MLKEM768: 65,
}
_MLKEM768_PUB_LEN = 1184
_MLKEM768_CT_LEN = 1088

_AESGCM_NONCE_LEN = 12
_AESGCM_TAG_LEN = 16


class HybridKEMError(Exception):
    """Base exception for Hybrid KEM errors."""


class DecapsulationError(HybridKEMError):
    """Raised when decapsulation or shared-secret derivation fails."""


class DecryptionError(HybridKEMError):
    """Raised when authenticated payload decryption fails (e.g. tampering)."""


# ----------------------------------------------------------------------------
# Encoding helpers
# ----------------------------------------------------------------------------


def _lp(data: bytes) -> bytes:
    """Length-prefix (4-byte big-endian) so concatenated fields are unambiguous."""
    return struct.pack(">I", len(data)) + data


def _profile_to_byte(profile: str) -> int:
    try:
        return _PROFILE_TO_BYTE[profile]
    except KeyError:
        raise ValueError(f"Unsupported profile: {profile!r}") from None


def _byte_to_profile(p_byte: int) -> ProfileType:
    try:
        return _BYTE_TO_PROFILE[p_byte]
    except KeyError:
        raise ValueError(f"Unknown profile identifier: {p_byte}") from None


def _encode_pair(magic: bytes, profile: str, first: bytes, second: bytes) -> bytes:
    """[magic] [profile 1B] [len_first 2B] [len_second 2B] [first] [second]"""
    return (
        magic
        + struct.pack(">BHH", _profile_to_byte(profile), len(first), len(second))
        + first
        + second
    )


def _decode_pair(
    magic: bytes, data: bytes, type_name: str, pq_len: int
) -> tuple[ProfileType, bytes, bytes]:
    """Strict inverse of _encode_pair: checks magic, profile, and exact lengths."""
    if not data.startswith(magic):
        raise ValueError(f"Invalid {type_name} magic header")
    header_len = len(magic) + 5
    if len(data) < header_len:
        raise ValueError(f"Truncated {type_name} data")

    p_byte, len_c, len_pq = struct.unpack(">BHH", data[len(magic):header_len])
    profile = _byte_to_profile(p_byte)

    if len_c != _CLASSICAL_PUB_LEN[profile]:
        raise ValueError(
            f"{type_name}: classical component must be {_CLASSICAL_PUB_LEN[profile]} bytes "
            f"for {profile}, got {len_c}"
        )
    if len_pq != pq_len:
        raise ValueError(f"{type_name}: ML-KEM component must be {pq_len} bytes, got {len_pq}")

    c_end = header_len + len_c
    pq_end = c_end + len_pq
    if len(data) != pq_end:
        raise ValueError(f"Length mismatch: expected {pq_end} bytes, got {len(data)}")

    return profile, data[header_len:c_end], data[c_end:pq_end]


# ----------------------------------------------------------------------------
# Key and ciphertext containers
# ----------------------------------------------------------------------------


@dataclass(frozen=True)
class HybridKEMPublicKey:
    """
    Composite Public Key holding classical public key and ML-KEM public key.
    """
    profile: ProfileType
    classical_bytes: bytes
    pq_bytes: bytes

    def to_bytes(self) -> bytes:
        """
        Serialize into standard binary format:
        [Magic 6B] [Profile 1B] [len_classical 2B] [len_pq 2B] [classical_bytes] [pq_bytes]
        """
        return _encode_pair(_MAGIC_PUB, self.profile, self.classical_bytes, self.pq_bytes)

    @classmethod
    def from_bytes(cls, data: bytes) -> HybridKEMPublicKey:
        """Deserialize from binary format. Rejects unknown profiles and wrong sizes."""
        profile, classical, pq = _decode_pair(
            _MAGIC_PUB, data, "HybridKEMPublicKey", _MLKEM768_PUB_LEN
        )
        return cls(profile=profile, classical_bytes=classical, pq_bytes=pq)

    @property
    def total_bytes(self) -> int:
        return len(self.to_bytes())


class HybridKEMPrivateKey:
    """
    Composite Private Key holding classical private key and ML-KEM private key.
    """
    def __init__(
        self,
        profile: ProfileType,
        classical_key: x25519.X25519PrivateKey | ec.EllipticCurvePrivateKey,
        pq_key: mlkem.MLKEM768PrivateKey,
    ):
        if profile == PROFILE_X25519_MLKEM768:
            if not isinstance(classical_key, x25519.X25519PrivateKey):
                raise TypeError("x25519_mlkem768 requires an X25519 private key")
        elif profile == PROFILE_P256_MLKEM768:
            if not (
                isinstance(classical_key, ec.EllipticCurvePrivateKey)
                and isinstance(classical_key.curve, ec.SECP256R1)
            ):
                raise TypeError("p256_mlkem768 requires a SECP256R1 private key")
        else:
            raise ValueError(f"Unsupported profile: {profile!r}")

        self.profile = profile
        self.classical_key = classical_key
        self.pq_key = pq_key
        # Cached: decapsulation needs the recipient's public key for the KDF transcript.
        self._public_key = self._derive_public_key()

    def _derive_public_key(self) -> HybridKEMPublicKey:
        if isinstance(self.classical_key, x25519.X25519PrivateKey):
            c_pub_bytes = self.classical_key.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            )
        else:
            c_pub_bytes = self.classical_key.public_key().public_bytes(
                serialization.Encoding.X962,
                serialization.PublicFormat.UncompressedPoint,
            )
        return HybridKEMPublicKey(
            profile=self.profile,
            classical_bytes=c_pub_bytes,
            pq_bytes=self.pq_key.public_key().public_bytes_raw(),
        )

    def public_key(self) -> HybridKEMPublicKey:
        """Return the corresponding HybridKEMPublicKey."""
        return self._public_key

    def to_pkcs8_der(self) -> tuple[bytes, bytes]:
        """Export (classical_der, pq_der) private keys in standard PKCS#8 DER."""
        c_der = self.classical_key.private_bytes(
            serialization.Encoding.DER,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        pq_der = self.pq_key.private_bytes(
            serialization.Encoding.DER,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        return c_der, pq_der


@dataclass(frozen=True)
class HybridCiphertext:
    """
    Composite Ciphertext containing:
    - Classical ephemeral public key (for ECDH agreement)
    - ML-KEM ciphertext (encapsulated lattice secret)
    """
    profile: ProfileType
    classical_ephemeral_pub_bytes: bytes
    pq_ciphertext_bytes: bytes

    def to_bytes(self) -> bytes:
        return _encode_pair(
            _MAGIC_CT, self.profile, self.classical_ephemeral_pub_bytes, self.pq_ciphertext_bytes
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> HybridCiphertext:
        profile, classical, pq = _decode_pair(
            _MAGIC_CT, data, "HybridCiphertext", _MLKEM768_CT_LEN
        )
        return cls(
            profile=profile,
            classical_ephemeral_pub_bytes=classical,
            pq_ciphertext_bytes=pq,
        )

    @property
    def total_bytes(self) -> int:
        return len(self.to_bytes())


@dataclass(frozen=True)
class HybridEncryptedMessage:
    """
    Complete hybrid envelope for payload encryption.
    Contains HybridCiphertext (for key exchange) + AES-GCM nonce + ciphertext with auth tag.
    """
    hybrid_ciphertext: HybridCiphertext
    nonce: bytes
    encrypted_payload: bytes

    def to_bytes(self) -> bytes:
        ct_bytes = self.hybrid_ciphertext.to_bytes()
        return (
            struct.pack(">HH", len(ct_bytes), len(self.nonce))
            + ct_bytes
            + self.nonce
            + self.encrypted_payload
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> HybridEncryptedMessage:
        if len(data) < 4:
            raise ValueError("Truncated HybridEncryptedMessage")
        len_ct, len_nonce = struct.unpack(">HH", data[:4])
        if len_nonce != _AESGCM_NONCE_LEN:
            raise ValueError(f"AES-GCM nonce must be {_AESGCM_NONCE_LEN} bytes, got {len_nonce}")

        payload_start = 4 + len_ct + len_nonce
        if len(data) < payload_start + _AESGCM_TAG_LEN:
            raise ValueError("Truncated HybridEncryptedMessage")

        ct_bytes = data[4:4 + len_ct]
        nonce = data[4 + len_ct:payload_start]
        encrypted_payload = data[payload_start:]

        return cls(
            hybrid_ciphertext=HybridCiphertext.from_bytes(ct_bytes),
            nonce=nonce,
            encrypted_payload=encrypted_payload,
        )


# ----------------------------------------------------------------------------
# KEM operations
# ----------------------------------------------------------------------------


def generate_keypair(profile: ProfileType = PROFILE_X25519_MLKEM768) -> tuple[HybridKEMPublicKey, HybridKEMPrivateKey]:
    """
    Generate a hybrid keypair containing classical and ML-KEM-768 keys.
    """
    if profile == PROFILE_X25519_MLKEM768:
        classical_key = x25519.X25519PrivateKey.generate()
    elif profile == PROFILE_P256_MLKEM768:
        classical_key = ec.generate_private_key(ec.SECP256R1())
    else:
        raise ValueError(f"Unsupported profile: {profile}")

    pq_key = mlkem.MLKEM768PrivateKey.generate()
    priv = HybridKEMPrivateKey(profile=profile, classical_key=classical_key, pq_key=pq_key)
    return priv.public_key(), priv


def _combine_secrets(
    *,
    profile: ProfileType,
    pq_ss: bytes,
    classical_ss: bytes,
    ciphertext: HybridCiphertext,
    recipient_public_key: HybridKEMPublicKey,
) -> bytes:
    """
    Cryptographic Combiner (HKDF-SHA256), see the module docstring.

    The secrets are the HKDF input keying material. The full transcript
    (both ciphertexts and both recipient keys, length-prefixed) goes into
    `info`, so changing any field gives an unrelated key.
    """
    info = (
        _KDF_LABEL
        + bytes([_profile_to_byte(profile)])
        + _lp(ciphertext.pq_ciphertext_bytes)
        + _lp(ciphertext.classical_ephemeral_pub_bytes)
        + _lp(recipient_public_key.pq_bytes)
        + _lp(recipient_public_key.classical_bytes)
    )
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info)
    return hkdf.derive(pq_ss + classical_ss)


def encapsulate(public_key: HybridKEMPublicKey) -> tuple[HybridCiphertext, bytes]:
    """
    Encapsulate a shared secret towards a recipient's HybridKEMPublicKey.

    Returns:
        (HybridCiphertext, shared_secret_32bytes)
    """
    # 1. Classical Ephemeral Key Exchange
    if public_key.profile == PROFILE_X25519_MLKEM768:
        peer_c_pub = x25519.X25519PublicKey.from_public_bytes(public_key.classical_bytes)
        eph_priv = x25519.X25519PrivateKey.generate()
        eph_pub_bytes = eph_priv.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        # cryptography rejects low-order points (all-zero output) with ValueError.
        classical_ss = eph_priv.exchange(peer_c_pub)
    elif public_key.profile == PROFILE_P256_MLKEM768:
        # from_encoded_point validates that the point lies on the curve.
        peer_c_pub = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(), public_key.classical_bytes
        )
        eph_priv = ec.generate_private_key(ec.SECP256R1())
        eph_pub_bytes = eph_priv.public_key().public_bytes(
            serialization.Encoding.X962,
            serialization.PublicFormat.UncompressedPoint,
        )
        classical_ss = eph_priv.exchange(ec.ECDH(), peer_c_pub)
    else:
        raise ValueError(f"Unknown profile: {public_key.profile}")

    # 2. Post-Quantum Encapsulation (ML-KEM-768)
    pq_pub = mlkem.MLKEM768PublicKey.from_public_bytes(public_key.pq_bytes)
    pq_ss, pq_ct_bytes = pq_pub.encapsulate()

    ciphertext = HybridCiphertext(
        profile=public_key.profile,
        classical_ephemeral_pub_bytes=eph_pub_bytes,
        pq_ciphertext_bytes=pq_ct_bytes,
    )

    # 3. Combine secrets, bound to the full transcript
    combined_secret = _combine_secrets(
        profile=public_key.profile,
        pq_ss=pq_ss,
        classical_ss=classical_ss,
        ciphertext=ciphertext,
        recipient_public_key=public_key,
    )
    return ciphertext, combined_secret


def decapsulate(private_key: HybridKEMPrivateKey, ciphertext: HybridCiphertext) -> bytes:
    """
    Decapsulate a shared secret using the recipient's HybridKEMPrivateKey.

    Returns:
        shared_secret_32bytes

    Raises:
        DecapsulationError: If mathematical decapsulation or parsing fails.
    """
    if private_key.profile != ciphertext.profile:
        raise DecapsulationError(
            f"Profile mismatch: private key {private_key.profile} != ciphertext {ciphertext.profile}"
        )

    # 1. Classical Ephemeral ECDH Decapsulation
    try:
        if private_key.profile == PROFILE_X25519_MLKEM768:
            assert isinstance(private_key.classical_key, x25519.X25519PrivateKey)
            eph_pub = x25519.X25519PublicKey.from_public_bytes(
                ciphertext.classical_ephemeral_pub_bytes
            )
            classical_ss = private_key.classical_key.exchange(eph_pub)
        elif private_key.profile == PROFILE_P256_MLKEM768:
            assert isinstance(private_key.classical_key, ec.EllipticCurvePrivateKey)
            eph_pub = ec.EllipticCurvePublicKey.from_encoded_point(
                ec.SECP256R1(), ciphertext.classical_ephemeral_pub_bytes
            )
            classical_ss = private_key.classical_key.exchange(ec.ECDH(), eph_pub)
        else:
            raise DecapsulationError(f"Unsupported profile: {private_key.profile}")
    except Exception as exc:
        raise DecapsulationError(f"Classical ECDH exchange failed: {exc}") from exc

    # 2. Post-Quantum ML-KEM Decapsulation
    try:
        pq_ss = private_key.pq_key.decapsulate(ciphertext.pq_ciphertext_bytes)
    except Exception as exc:
        raise DecapsulationError(f"ML-KEM decapsulation failed: {exc}") from exc

    # 3. Re-combine secrets over the same transcript the sender used
    return _combine_secrets(
        profile=private_key.profile,
        pq_ss=pq_ss,
        classical_ss=classical_ss,
        ciphertext=ciphertext,
        recipient_public_key=private_key.public_key(),
    )


# ----------------------------------------------------------------------------
# KEM + AES-256-GCM envelope
# ----------------------------------------------------------------------------


def _envelope_aad(hybrid_ct: HybridCiphertext, associated_data: bytes) -> bytes:
    """Authenticate the KEM header together with the caller's associated data."""
    return _lp(hybrid_ct.to_bytes()) + associated_data


def encrypt_message(
    recipient_public_key: HybridKEMPublicKey,
    plaintext: bytes,
    associated_data: bytes = b"",
) -> HybridEncryptedMessage:
    """
    Encrypt application plaintext using Hybrid KEM + AES-256-GCM.
    """
    hybrid_ct, symmetric_key = encapsulate(recipient_public_key)
    nonce = os.urandom(_AESGCM_NONCE_LEN)  # 96-bit nonce; the key is fresh per message
    aesgcm = AESGCM(symmetric_key)
    encrypted_payload = aesgcm.encrypt(
        nonce, plaintext, _envelope_aad(hybrid_ct, associated_data)
    )

    return HybridEncryptedMessage(
        hybrid_ciphertext=hybrid_ct,
        nonce=nonce,
        encrypted_payload=encrypted_payload,
    )


def decrypt_message(
    recipient_private_key: HybridKEMPrivateKey,
    encrypted_message: HybridEncryptedMessage,
    associated_data: bytes = b"",
) -> bytes:
    """
    Decrypt application ciphertext using Hybrid KEM + AES-256-GCM.

    Raises:
        DecapsulationError: If KEM decapsulation fails.
        DecryptionError: If AES-GCM authentication fails (tampering/wrong key).
    """
    symmetric_key = decapsulate(recipient_private_key, encrypted_message.hybrid_ciphertext)
    if len(encrypted_message.nonce) != _AESGCM_NONCE_LEN:
        raise DecryptionError(
            f"AES-GCM nonce must be {_AESGCM_NONCE_LEN} bytes, got {len(encrypted_message.nonce)}"
        )
    aesgcm = AESGCM(symmetric_key)
    try:
        return aesgcm.decrypt(
            encrypted_message.nonce,
            encrypted_message.encrypted_payload,
            _envelope_aad(encrypted_message.hybrid_ciphertext, associated_data),
        )
    except Exception as exc:
        raise DecryptionError(f"AES-GCM decryption failed (tampering or wrong key): {exc}") from exc
