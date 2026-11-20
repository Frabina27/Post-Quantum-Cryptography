"""
Hybrid Key Encapsulation Mechanism (KEM) Module.
Combines Classical Key Agreement (X25519 or ECDH P-256) with Post-Quantum KEM (ML-KEM-768).

Standard Alignment (both profiles are byte-exact against the specs' test vectors):
- PROFILE_X25519_MLKEM768 is X-Wing (draft-connolly-cfrg-xwing-kem-11), which
  is the same as id-MLKEM768-X25519-SHA3-256 in the LAMPS Composite ML-KEM
  draft (draft-ietf-lamps-pq-composite-kem-23).
- PROFILE_P256_MLKEM768 is id-MLKEM768-ECDH-P256-SHA3-256 from the same LAMPS
  Composite ML-KEM draft.
- ML-KEM-768 conforms to NIST FIPS 203. The ECDH shared secret is the
  x-coordinate Z of SP 800-56A Rev 3, and X25519 follows RFC 7748.
- The combiner is a single SHA3-256 call, an SP 800-56C one-step KDF.
- The application payload is encrypted with AES-256-GCM.

KEM Combiner (both profiles, LAMPS Composite ML-KEM Section 3.4):
    ss = SHA3-256(ss_M || ss_T || ct_T || pk_T || Label)
where ss_M is the ML-KEM shared secret, ss_T the ECDH shared secret, ct_T the
sender's ephemeral ECDH public key, pk_T the recipient's static ECDH public
key, and Label is
    X25519: 5c2e2f2f5e5c  (the 6-byte X-Wing label "\\.//^\\")
    P-256:  "MLKEM768-P256"
All inputs are fixed-length per profile, so the concatenation is unambiguous.

Why ML-KEM comes first: both specs put ss_M first in SHA3-256. The TLS draft
draft-ietf-tls-ecdhe-mlkem puts the ECDH secret first for SecP256r1MLKEM768.
That draft only concatenates the secrets for the TLS key schedule and defines
no standalone KEM combiner, so it is not the reference for this module.

Why ct_T and pk_T are hashed but ct_M and pk_M are not: ECDH on its own is not
an IND-CCA KEM, so the ephemeral and static ECDH keys must be bound into the
KDF. ML-KEM is IND-CCA and ciphertext-binding (C2PRI), so its ciphertext and
key are already bound through ss_M. This is the argument both specs rely on
(see the X-Wing paper, and LAMPS Composite ML-KEM Section 9.2).

Security Guarantee:
The combined shared secret is IND-CCA secure as long as AT LEAST ONE of
ML-KEM-768 or the ECDH component (under the strong Diffie-Hellman assumption)
remains unbroken.
"""

from __future__ import annotations

import hashlib
import os
import struct
from dataclasses import dataclass
from typing import Literal

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, mlkem, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


ProfileType = Literal["x25519_mlkem768", "p256_mlkem768"]

PROFILE_X25519_MLKEM768: ProfileType = "x25519_mlkem768"
PROFILE_P256_MLKEM768: ProfileType = "p256_mlkem768"

_MAGIC_PUB = b"HKPUB1"
# Bumped on every combiner change (v1 HKDF, v2 HKDF+transcript, v3 standard
# SHA3-256). An older ciphertext would silently derive a different key, so a
# distinct magic turns that into a clear parse error.
_MAGIC_CT = b"HKCT3"

# KEM Combiner Labels from the specs (see module docstring).
COMBINER_LABELS: dict[str, bytes] = {
    PROFILE_X25519_MLKEM768: bytes.fromhex("5c2e2f2f5e5c"),  # X-Wing label
    PROFILE_P256_MLKEM768: b"MLKEM768-P256",
}

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
_MLKEM_SEED_LEN = 64   # d || z, FIPS 203
_XWING_SEED_LEN = 32

# RFC 5915 ECPrivateKey for P-256 with the namedCurve parameter and WITHOUT
# the optional publicKey field, as LAMPS Composite ML-KEM Section 4 requires:
#   SEQUENCE { INTEGER 1, OCTET STRING (32) d, [0] OID secp256r1 }
_P256_ECPRIVKEY_PREFIX = bytes.fromhex("30310201010420")
_P256_ECPRIVKEY_SUFFIX = bytes.fromhex("a00a06082a8648ce3d030107")
_P256_ECPRIVKEY_LEN = len(_P256_ECPRIVKEY_PREFIX) + 32 + len(_P256_ECPRIVKEY_SUFFIX)

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


def _check_profile(profile: str) -> ProfileType:
    if profile not in _PROFILE_TO_BYTE:
        raise ValueError(f"Unsupported profile: {profile!r}")
    return profile  # type: ignore[return-value]


def _profile_to_byte(profile: str) -> int:
    return _PROFILE_TO_BYTE[_check_profile(profile)]


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


def _split_composite(
    profile: str, data: bytes, pq_len: int, type_name: str
) -> tuple[bytes, bytes]:
    """Split a spec-format value (ML-KEM part first, then the classical part)."""
    profile = _check_profile(profile)
    expected = pq_len + _CLASSICAL_PUB_LEN[profile]
    if len(data) != expected:
        raise ValueError(f"{type_name} for {profile} must be {expected} bytes, got {len(data)}")
    return data[:pq_len], data[pq_len:]


def _x25519_raw(key: x25519.X25519PrivateKey | x25519.X25519PublicKey) -> bytes:
    if isinstance(key, x25519.X25519PrivateKey):
        key = key.public_key()
    return key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def _p256_point(key: ec.EllipticCurvePrivateKey | ec.EllipticCurvePublicKey) -> bytes:
    if isinstance(key, ec.EllipticCurvePrivateKey):
        key = key.public_key()
    return key.public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
    )


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
        Serialize into this project's framed format, which carries the profile:
        [Magic 6B] [Profile 1B] [len_classical 2B] [len_pq 2B] [classical_bytes] [pq_bytes]
        """
        return _encode_pair(_MAGIC_PUB, self.profile, self.classical_bytes, self.pq_bytes)

    @classmethod
    def from_bytes(cls, data: bytes) -> HybridKEMPublicKey:
        """Deserialize from the framed format. Rejects unknown profiles and wrong sizes."""
        profile, classical, pq = _decode_pair(
            _MAGIC_PUB, data, "HybridKEMPublicKey", _MLKEM768_PUB_LEN
        )
        return cls(profile=profile, classical_bytes=classical, pq_bytes=pq)

    def to_composite_bytes(self) -> bytes:
        """Spec encoding pk_M || pk_T (1216 B for X-Wing, 1249 B for P-256)."""
        return self.pq_bytes + self.classical_bytes

    @classmethod
    def from_composite_bytes(cls, profile: ProfileType, data: bytes) -> HybridKEMPublicKey:
        """Parse the spec encoding pk_M || pk_T for the given profile."""
        pq, classical = _split_composite(profile, data, _MLKEM768_PUB_LEN, "Public key")
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
        # Cached: decapsulation needs pk_T for the combiner.
        self._public_key = self._derive_public_key()

    def _derive_public_key(self) -> HybridKEMPublicKey:
        if isinstance(self.classical_key, x25519.X25519PrivateKey):
            c_pub_bytes = _x25519_raw(self.classical_key)
        else:
            c_pub_bytes = _p256_point(self.classical_key)
        return HybridKEMPublicKey(
            profile=self.profile,
            classical_bytes=c_pub_bytes,
            pq_bytes=self.pq_key.public_key().public_bytes_raw(),
        )

    def public_key(self) -> HybridKEMPublicKey:
        """Return the corresponding HybridKEMPublicKey."""
        return self._public_key

    # -- Spec key formats ---------------------------------------------------

    @classmethod
    def from_xwing_seed(cls, seed: bytes) -> HybridKEMPrivateKey:
        """
        X-Wing key derivation (draft-connolly-cfrg-xwing-kem Section 5.2):
        SHAKE256(seed, 96 B) -> ML-KEM (d || z) and the X25519 scalar.
        """
        if len(seed) != _XWING_SEED_LEN:
            raise ValueError(f"X-Wing seed must be {_XWING_SEED_LEN} bytes, got {len(seed)}")
        expanded = hashlib.shake_256(seed).digest(96)
        return cls(
            profile=PROFILE_X25519_MLKEM768,
            classical_key=x25519.X25519PrivateKey.from_private_bytes(expanded[64:96]),
            pq_key=mlkem.MLKEM768PrivateKey.from_seed_bytes(expanded[:64]),
        )

    def to_composite_bytes(self) -> bytes:
        """
        LAMPS Composite ML-KEM private key, mlkemSeed (64 B) || tradSK:
        a raw 32-byte scalar for X25519, or an RFC 5915 ECPrivateKey without
        publicKey (51 B) for P-256.
        """
        mlkem_seed = self.pq_key.private_bytes_raw()
        if isinstance(self.classical_key, x25519.X25519PrivateKey):
            trad = self.classical_key.private_bytes(
                serialization.Encoding.Raw,
                serialization.PrivateFormat.Raw,
                serialization.NoEncryption(),
            )
        else:
            scalar = self.classical_key.private_numbers().private_value.to_bytes(32, "big")
            trad = _P256_ECPRIVKEY_PREFIX + scalar + _P256_ECPRIVKEY_SUFFIX
        return mlkem_seed + trad

    @classmethod
    def from_composite_bytes(cls, profile: ProfileType, data: bytes) -> HybridKEMPrivateKey:
        """Parse a LAMPS Composite ML-KEM private key (see to_composite_bytes)."""
        profile = _check_profile(profile)
        mlkem_seed, trad = data[:_MLKEM_SEED_LEN], data[_MLKEM_SEED_LEN:]
        if len(mlkem_seed) != _MLKEM_SEED_LEN:
            raise ValueError("Truncated composite private key")

        classical_key: x25519.X25519PrivateKey | ec.EllipticCurvePrivateKey
        if profile == PROFILE_X25519_MLKEM768:
            if len(trad) != 32:
                raise ValueError(f"X25519 private key must be 32 bytes, got {len(trad)}")
            classical_key = x25519.X25519PrivateKey.from_private_bytes(trad)
        else:
            if (
                len(trad) != _P256_ECPRIVKEY_LEN
                or not trad.startswith(_P256_ECPRIVKEY_PREFIX)
                or not trad.endswith(_P256_ECPRIVKEY_SUFFIX)
            ):
                raise ValueError("P-256 private key must be a 51-byte RFC 5915 ECPrivateKey "
                                 "with namedCurve secp256r1 and no publicKey field")
            scalar = int.from_bytes(trad[len(_P256_ECPRIVKEY_PREFIX):-len(_P256_ECPRIVKEY_SUFFIX)], "big")
            classical_key = ec.derive_private_key(scalar, ec.SECP256R1())  # rejects 0 and >= n

        return cls(
            profile=profile,
            classical_key=classical_key,
            pq_key=mlkem.MLKEM768PrivateKey.from_seed_bytes(mlkem_seed),
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
    - Classical ephemeral public key (ct_T, for ECDH agreement)
    - ML-KEM ciphertext (ct_M, encapsulated lattice secret)
    """
    profile: ProfileType
    classical_ephemeral_pub_bytes: bytes
    pq_ciphertext_bytes: bytes

    def to_bytes(self) -> bytes:
        """Framed format (carries the profile), see HybridKEMPublicKey.to_bytes."""
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

    def to_composite_bytes(self) -> bytes:
        """Spec encoding ct_M || ct_T (1120 B for X-Wing, 1153 B for P-256)."""
        return self.pq_ciphertext_bytes + self.classical_ephemeral_pub_bytes

    @classmethod
    def from_composite_bytes(cls, profile: ProfileType, data: bytes) -> HybridCiphertext:
        """Parse the spec encoding ct_M || ct_T for the given profile."""
        pq, classical = _split_composite(profile, data, _MLKEM768_CT_LEN, "Ciphertext")
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
    Generate a hybrid keypair.

    For X25519 this is X-Wing's GenerateKeyPair (a random 32-byte seed
    expanded with SHAKE256). For P-256 the two components are generated
    independently, as LAMPS Composite ML-KEM Section 3.1 specifies.
    """
    if profile == PROFILE_X25519_MLKEM768:
        priv = HybridKEMPrivateKey.from_xwing_seed(os.urandom(_XWING_SEED_LEN))
    elif profile == PROFILE_P256_MLKEM768:
        priv = HybridKEMPrivateKey(
            profile=profile,
            classical_key=ec.generate_private_key(ec.SECP256R1()),
            pq_key=mlkem.MLKEM768PrivateKey.generate(),
        )
    else:
        raise ValueError(f"Unsupported profile: {profile}")
    return priv.public_key(), priv


def combine_secrets(
    profile: ProfileType,
    pq_ss: bytes,
    classical_ss: bytes,
    classical_ct: bytes,
    classical_pk: bytes,
) -> bytes:
    """
    KEM Combiner: SHA3-256(ss_M || ss_T || ct_T || pk_T || Label).

    Exposed so known-answer tests can check it against the specs'
    intermediate values. Inputs must have the profile's fixed lengths.
    """
    profile = _check_profile(profile)
    c_len = _CLASSICAL_PUB_LEN[profile]
    if len(pq_ss) != 32 or len(classical_ss) != 32:
        raise ValueError("Shared secrets must be 32 bytes")
    if len(classical_ct) != c_len or len(classical_pk) != c_len:
        raise ValueError(f"Classical ciphertext and public key must be {c_len} bytes for {profile}")
    return hashlib.sha3_256(
        pq_ss + classical_ss + classical_ct + classical_pk + COMBINER_LABELS[profile]
    ).digest()


def encapsulate(public_key: HybridKEMPublicKey) -> tuple[HybridCiphertext, bytes]:
    """
    Encapsulate a shared secret towards a recipient's HybridKEMPublicKey.

    Returns:
        (HybridCiphertext, shared_secret_32bytes)
    """
    # 1. Classical DHKEM: ephemeral key pair, ct_T = ephemeral public key
    if public_key.profile == PROFILE_X25519_MLKEM768:
        peer_c_pub = x25519.X25519PublicKey.from_public_bytes(public_key.classical_bytes)
        eph_priv = x25519.X25519PrivateKey.generate()
        eph_pub_bytes = _x25519_raw(eph_priv)
        # cryptography rejects low-order points (all-zero output) with ValueError.
        classical_ss = eph_priv.exchange(peer_c_pub)
    elif public_key.profile == PROFILE_P256_MLKEM768:
        # from_encoded_point validates that the point lies on the curve.
        peer_c_pub = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(), public_key.classical_bytes
        )
        eph_priv = ec.generate_private_key(ec.SECP256R1())
        eph_pub_bytes = _p256_point(eph_priv)
        classical_ss = eph_priv.exchange(ec.ECDH(), peer_c_pub)
    else:
        raise ValueError(f"Unknown profile: {public_key.profile}")

    # 2. ML-KEM-768. from_public_bytes performs the FIPS 203 Section 7.2
    #    encapsulation key check that X-Wing requires.
    pq_pub = mlkem.MLKEM768PublicKey.from_public_bytes(public_key.pq_bytes)
    pq_ss, pq_ct_bytes = pq_pub.encapsulate()

    ciphertext = HybridCiphertext(
        profile=public_key.profile,
        classical_ephemeral_pub_bytes=eph_pub_bytes,
        pq_ciphertext_bytes=pq_ct_bytes,
    )

    # 3. Standard combiner
    combined_secret = combine_secrets(
        public_key.profile, pq_ss, classical_ss, eph_pub_bytes, public_key.classical_bytes
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

    # 1. Classical DHKEM decapsulation
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

    # 2. ML-KEM-768 decapsulation (implicit rejection on a bad ciphertext)
    try:
        pq_ss = private_key.pq_key.decapsulate(ciphertext.pq_ciphertext_bytes)
    except Exception as exc:
        raise DecapsulationError(f"ML-KEM decapsulation failed: {exc}") from exc

    # 3. Standard combiner, with pk_T taken from the recipient's own key
    return combine_secrets(
        private_key.profile,
        pq_ss,
        classical_ss,
        ciphertext.classical_ephemeral_pub_bytes,
        private_key.public_key().classical_bytes,
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
