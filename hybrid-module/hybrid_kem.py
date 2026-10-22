"""
Hybrid Key Encapsulation Mechanism (KEM) Module.
Combines Classical Key Agreement (X25519 or ECDH P-256) with Post-Quantum KEM (ML-KEM-768).

Standard Alignment:
- Modeled after IETF draft-ietf-tls-hybrid-design (X25519MLKEM768).
- Conforms to NIST FIPS 203 for ML-KEM-768.
- Uses RFC 5869 / NIST SP 800-56C compliant HKDF-SHA256 combiner.
- Uses AES-256-GCM for authenticated symmetric payload encryption.

Security Guarantee:
Dual-PRF Combiner Theorem: The combined shared secret is cryptographically secure
as long as AT LEAST ONE of the constituent primitives (classical or post-quantum)
remains uncompromised.
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
_MAGIC_CT = b"HKCT1"
_HKDF_INFO = b"hybrid-kem-v1-kdf"


class HybridKEMError(Exception):
    """Base exception for Hybrid KEM errors."""


class DecapsulationError(HybridKEMError):
    """Raised when decapsulation or shared-secret derivation fails."""


class DecryptionError(HybridKEMError):
    """Raised when authenticated payload decryption fails (e.g. tampering)."""


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
        [Magic 6B] [Profile 1B] [len_classical 2B] [classical_bytes] [len_pq 2B] [pq_bytes]
        """
        p_byte = 1 if self.profile == PROFILE_X25519_MLKEM768 else 2
        return (
            _MAGIC_PUB
            + struct.pack(">BHH", p_byte, len(self.classical_bytes), len(self.pq_bytes))
            + self.classical_bytes
            + self.pq_bytes
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> HybridKEMPublicKey:
        """Deserialize from binary format."""
        if not data.startswith(_MAGIC_PUB):
            raise ValueError("Invalid HybridKEMPublicKey magic header")
        header_len = len(_MAGIC_PUB) + 5
        if len(data) < header_len:
            raise ValueError("Truncated HybridKEMPublicKey data")

        p_byte, len_c, len_pq = struct.unpack(">BHH", data[len(_MAGIC_PUB):header_len])
        profile: ProfileType = PROFILE_X25519_MLKEM768 if p_byte == 1 else PROFILE_P256_MLKEM768

        c_end = header_len + len_c
        pq_end = c_end + len_pq
        if len(data) != pq_end:
            raise ValueError(f"Length mismatch: expected {pq_end} bytes, got {len(data)}")

        classical_bytes = data[header_len:c_end]
        pq_bytes = data[c_end:pq_end]
        return cls(profile=profile, classical_bytes=classical_bytes, pq_bytes=pq_bytes)

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
        self.profile = profile
        self.classical_key = classical_key
        self.pq_key = pq_key

    def public_key(self) -> HybridKEMPublicKey:
        """Derive the corresponding HybridKEMPublicKey."""
        if self.profile == PROFILE_X25519_MLKEM768:
            assert isinstance(self.classical_key, x25519.X25519PrivateKey)
            c_pub_bytes = self.classical_key.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            )
        else:
            assert isinstance(self.classical_key, ec.EllipticCurvePrivateKey)
            c_pub_bytes = self.classical_key.public_key().public_bytes(
                serialization.Encoding.X962,
                serialization.PublicFormat.UncompressedPoint,
            )

        pq_pub_bytes = self.pq_key.public_key().public_bytes_raw()
        return HybridKEMPublicKey(
            profile=self.profile,
            classical_bytes=c_pub_bytes,
            pq_bytes=pq_pub_bytes,
        )

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
        p_byte = 1 if self.profile == PROFILE_X25519_MLKEM768 else 2
        return (
            _MAGIC_CT
            + struct.pack(
                ">BHH",
                p_byte,
                len(self.classical_ephemeral_pub_bytes),
                len(self.pq_ciphertext_bytes),
            )
            + self.classical_ephemeral_pub_bytes
            + self.pq_ciphertext_bytes
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> HybridCiphertext:
        if not data.startswith(_MAGIC_CT):
            raise ValueError("Invalid HybridCiphertext magic header")
        header_len = len(_MAGIC_CT) + 5
        if len(data) < header_len:
            raise ValueError("Truncated HybridCiphertext data")

        p_byte, len_c, len_pq = struct.unpack(">BHH", data[len(_MAGIC_CT):header_len])
        profile: ProfileType = PROFILE_X25519_MLKEM768 if p_byte == 1 else PROFILE_P256_MLKEM768

        c_end = header_len + len_c
        pq_end = c_end + len_pq
        if len(data) != pq_end:
            raise ValueError(f"Length mismatch: expected {pq_end} bytes, got {len(data)}")

        classical_ephemeral = data[header_len:c_end]
        pq_ct = data[c_end:pq_end]
        return cls(
            profile=profile,
            classical_ephemeral_pub_bytes=classical_ephemeral,
            pq_ciphertext_bytes=pq_ct,
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
        offset = 4
        ct_bytes = data[offset:offset + len_ct]
        offset += len_ct
        nonce = data[offset:offset + len_nonce]
        offset += len_nonce
        encrypted_payload = data[offset:]

        hybrid_ct = HybridCiphertext.from_bytes(ct_bytes)
        return cls(
            hybrid_ciphertext=hybrid_ct,
            nonce=nonce,
            encrypted_payload=encrypted_payload,
        )


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


def _combine_secrets(classical_ss: bytes, pq_ss: bytes, profile: ProfileType) -> bytes:
    """
    Cryptographic Combiner (HKDF-SHA256):
    Derives 256-bit symmetric key from SS_classical || SS_pq.
    """
    info = _HKDF_INFO + b"-" + profile.encode("ascii")
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=info,
    )
    return hkdf.derive(classical_ss + pq_ss)


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
        classical_ss = eph_priv.exchange(peer_c_pub)
    elif public_key.profile == PROFILE_P256_MLKEM768:
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

    # 3. Combine Secrets via HKDF
    combined_secret = _combine_secrets(classical_ss, pq_ss, public_key.profile)

    ciphertext = HybridCiphertext(
        profile=public_key.profile,
        classical_ephemeral_pub_bytes=eph_pub_bytes,
        pq_ciphertext_bytes=pq_ct_bytes,
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

    # 3. Re-combine Secrets via HKDF
    return _combine_secrets(classical_ss, pq_ss, private_key.profile)


def encrypt_message(
    recipient_public_key: HybridKEMPublicKey,
    plaintext: bytes,
    associated_data: bytes = b"",
) -> HybridEncryptedMessage:
    """
    Encrypt application plaintext using Hybrid KEM + AES-256-GCM.
    """
    hybrid_ct, symmetric_key = encapsulate(recipient_public_key)
    nonce = os.urandom(12)  # 96-bit nonce for AES-GCM
    aesgcm = AESGCM(symmetric_key)
    encrypted_payload = aesgcm.encrypt(nonce, plaintext, associated_data)

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
    aesgcm = AESGCM(symmetric_key)
    try:
        plaintext = aesgcm.decrypt(
            encrypted_message.nonce,
            encrypted_message.encrypted_payload,
            associated_data,
        )
        return plaintext
    except Exception as exc:
        raise DecryptionError(f"AES-GCM decryption failed (tampering or wrong key): {exc}") from exc
