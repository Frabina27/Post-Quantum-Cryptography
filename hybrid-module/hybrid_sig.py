"""
Hybrid Composite Digital Signature Module.
Combines Classical Digital Signatures (ECDSA P-256 or RSA-PSS) with Post-Quantum Signatures (ML-DSA-65).

Standard Alignment:
- Modeled after RFC 9758 (Composite Signatures for Use in Internet PKI).
- Conforms to NIST FIPS 186-5 for ECDSA/RSA and NIST FIPS 204 for ML-DSA.
- Strict AND verification semantic: verification succeeds if and only if
  BOTH classical and post-quantum signatures verify against the same message.

Security Guarantee:
Dual-Signature Security: The combined digital signature remains unforgeable
as long as AT LEAST ONE of the underlying signature schemes (classical or post-quantum)
remains secure against existential forgery under chosen-message attacks (EUF-CMA).
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Literal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, mldsa, padding, rsa


ProfileType = Literal["ecdsa_mldsa65", "rsa_mldsa65"]

PROFILE_ECDSA_MLDSA65: ProfileType = "ecdsa_mldsa65"
PROFILE_RSA_MLDSA65: ProfileType = "rsa_mldsa65"

_MAGIC_SIG_PUB = b"HSPUB1"
_MAGIC_SIG = b"HSSIG1"


class HybridSignatureError(Exception):
    """Base exception for hybrid signature errors."""


@dataclass(frozen=True)
class HybridSigPublicKey:
    """
    Composite Public Key holding:
    - Classical verification key (ECDSA SubjectPublicKeyInfo or RSA SubjectPublicKeyInfo)
    - ML-DSA-65 verification key (raw 1952 bytes)
    """
    profile: ProfileType
    classical_pub_bytes: bytes
    pq_pub_bytes: bytes

    def to_bytes(self) -> bytes:
        p_byte = 1 if self.profile == PROFILE_ECDSA_MLDSA65 else 2
        return (
            _MAGIC_SIG_PUB
            + struct.pack(">BHH", p_byte, len(self.classical_pub_bytes), len(self.pq_pub_bytes))
            + self.classical_pub_bytes
            + self.pq_pub_bytes
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> HybridSigPublicKey:
        if not data.startswith(_MAGIC_SIG_PUB):
            raise ValueError("Invalid HybridSigPublicKey magic header")
        header_len = len(_MAGIC_SIG_PUB) + 5
        if len(data) < header_len:
            raise ValueError("Truncated HybridSigPublicKey data")

        p_byte, len_c, len_pq = struct.unpack(">BHH", data[len(_MAGIC_SIG_PUB):header_len])
        profile: ProfileType = PROFILE_ECDSA_MLDSA65 if p_byte == 1 else PROFILE_RSA_MLDSA65

        c_end = header_len + len_c
        pq_end = c_end + len_pq
        if len(data) != pq_end:
            raise ValueError(f"Length mismatch: expected {pq_end} bytes, got {len(data)}")

        classical_bytes = data[header_len:c_end]
        pq_bytes = data[c_end:pq_end]
        return cls(profile=profile, classical_pub_bytes=classical_bytes, pq_pub_bytes=pq_bytes)

    @property
    def total_bytes(self) -> int:
        return len(self.to_bytes())


class HybridSigPrivateKey:
    """
    Composite Private Key holding classical signing key and ML-DSA-65 signing key.
    """
    def __init__(
        self,
        profile: ProfileType,
        classical_key: ec.EllipticCurvePrivateKey | rsa.RSAPrivateKey,
        pq_key: mldsa.MLDSA65PrivateKey,
    ):
        self.profile = profile
        self.classical_key = classical_key
        self.pq_key = pq_key

    def public_key(self) -> HybridSigPublicKey:
        """Derive composite public key."""
        c_pub_der = self.classical_key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        pq_pub_bytes = self.pq_key.public_key().public_bytes_raw()
        return HybridSigPublicKey(
            profile=self.profile,
            classical_pub_bytes=c_pub_der,
            pq_pub_bytes=pq_pub_bytes,
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
class HybridSignature:
    """
    Composite Signature holding both classical and post-quantum signatures.
    """
    profile: ProfileType
    classical_sig_bytes: bytes
    pq_sig_bytes: bytes

    def to_bytes(self) -> bytes:
        p_byte = 1 if self.profile == PROFILE_ECDSA_MLDSA65 else 2
        return (
            _MAGIC_SIG
            + struct.pack(">BHH", p_byte, len(self.classical_sig_bytes), len(self.pq_sig_bytes))
            + self.classical_sig_bytes
            + self.pq_sig_bytes
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> HybridSignature:
        if not data.startswith(_MAGIC_SIG):
            raise ValueError("Invalid HybridSignature magic header")
        header_len = len(_MAGIC_SIG) + 5
        if len(data) < header_len:
            raise ValueError("Truncated HybridSignature data")

        p_byte, len_c, len_pq = struct.unpack(">BHH", data[len(_MAGIC_SIG):header_len])
        profile: ProfileType = PROFILE_ECDSA_MLDSA65 if p_byte == 1 else PROFILE_RSA_MLDSA65

        c_end = header_len + len_c
        pq_end = c_end + len_pq
        if len(data) != pq_end:
            raise ValueError(f"Length mismatch: expected {pq_end} bytes, got {len(data)}")

        classical_sig = data[header_len:c_end]
        pq_sig = data[c_end:pq_end]
        return cls(profile=profile, classical_sig_bytes=classical_sig, pq_sig_bytes=pq_sig)

    @property
    def total_bytes(self) -> int:
        return len(self.to_bytes())


def generate_keypair(profile: ProfileType = PROFILE_ECDSA_MLDSA65) -> tuple[HybridSigPublicKey, HybridSigPrivateKey]:
    """Generate composite signing keypair."""
    if profile == PROFILE_ECDSA_MLDSA65:
        classical_key = ec.generate_private_key(ec.SECP256R1())
    elif profile == PROFILE_RSA_MLDSA65:
        classical_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    else:
        raise ValueError(f"Unsupported profile: {profile}")

    pq_key = mldsa.MLDSA65PrivateKey.generate()
    priv = HybridSigPrivateKey(profile=profile, classical_key=classical_key, pq_key=pq_key)
    return priv.public_key(), priv


def sign(private_key: HybridSigPrivateKey, message: bytes) -> HybridSignature:
    """
    Sign a message with both classical and post-quantum keys.
    """
    # 1. Classical signature
    if private_key.profile == PROFILE_ECDSA_MLDSA65:
        assert isinstance(private_key.classical_key, ec.EllipticCurvePrivateKey)
        c_sig = private_key.classical_key.sign(message, ec.ECDSA(hashes.SHA256()))
    elif private_key.profile == PROFILE_RSA_MLDSA65:
        assert isinstance(private_key.classical_key, rsa.RSAPrivateKey)
        c_sig = private_key.classical_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
    else:
        raise ValueError(f"Unsupported profile: {private_key.profile}")

    # 2. Post-Quantum signature (ML-DSA-65)
    pq_sig = private_key.pq_key.sign(message)

    return HybridSignature(
        profile=private_key.profile,
        classical_sig_bytes=c_sig,
        pq_sig_bytes=pq_sig,
    )


def verify_detailed(
    public_key: HybridSigPublicKey,
    message: bytes,
    signature: HybridSignature,
) -> dict[str, bool]:
    """
    Detailed verification returning status of both constituents.
    Useful for Security Testing (Teammate 9) and diagnostic debugging.
    """
    if public_key.profile != signature.profile:
        return {"classical_valid": False, "pq_valid": False, "composite_valid": False}

    # 1. Classical verification
    classical_valid = False
    try:
        c_pub = serialization.load_der_public_key(public_key.classical_pub_bytes)
        if public_key.profile == PROFILE_ECDSA_MLDSA65:
            assert isinstance(c_pub, ec.EllipticCurvePublicKey)
            c_pub.verify(signature.classical_sig_bytes, message, ec.ECDSA(hashes.SHA256()))
            classical_valid = True
        elif public_key.profile == PROFILE_RSA_MLDSA65:
            assert isinstance(c_pub, rsa.RSAPublicKey)
            c_pub.verify(
                signature.classical_sig_bytes,
                message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )
            classical_valid = True
    except (InvalidSignature, ValueError, TypeError):
        classical_valid = False

    # 2. Post-Quantum verification
    pq_valid = False
    try:
        pq_pub = mldsa.MLDSA65PublicKey.from_public_bytes(public_key.pq_pub_bytes)
        pq_pub.verify(signature.pq_sig_bytes, message)
        pq_valid = True
    except (InvalidSignature, ValueError, TypeError):
        pq_valid = False

    return {
        "classical_valid": classical_valid,
        "pq_valid": pq_valid,
        "composite_valid": (classical_valid and pq_valid),
    }


def verify(
    public_key: HybridSigPublicKey,
    message: bytes,
    signature: HybridSignature,
) -> bool:
    """
    Verify hybrid composite signature.
    Returns True IF AND ONLY IF both classical and PQ signatures are valid.
    """
    details = verify_detailed(public_key, message, signature)
    return details["composite_valid"]
