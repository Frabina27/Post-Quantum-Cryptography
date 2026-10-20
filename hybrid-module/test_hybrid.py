"""
Comprehensive Test Suite for Hybrid Classical + PQC System.
Tests functionality, serialization, cryptographic correctness, and security tampering rejection.
"""

from __future__ import annotations

import sys
from pathlib import Path

# Ensure hybrid-module directory is on sys.path
_MODULE_DIR = Path(__file__).resolve().parent
if str(_MODULE_DIR) not in sys.path:
    sys.path.insert(0, str(_MODULE_DIR))

import pytest

from hybrid_kem import (
    PROFILE_P256_MLKEM768,
    PROFILE_X25519_MLKEM768,
    DecapsulationError,
    DecryptionError,
    HybridCiphertext,
    HybridKEMPublicKey,
    decapsulate,
    decrypt_message,
    encapsulate,
    encrypt_message,
    generate_keypair as gen_kem_keys,
)
from hybrid_pki import HybridCertificateAuthority, MigrationPolicy
from hybrid_sig import (
    PROFILE_ECDSA_MLDSA65,
    PROFILE_RSA_MLDSA65,
    HybridSigPublicKey,
    HybridSignature,
    generate_keypair as gen_sig_keys,
    sign as hybrid_sign,
    verify as hybrid_verify,
    verify_detailed,
)


# ============================================================================
# Hybrid KEM Tests
# ============================================================================


def test_hybrid_kem_x25519_mlkem768_roundtrip():
    """Verify X25519 + ML-KEM-768 shared-secret negotiation."""
    pub, priv = gen_kem_keys(PROFILE_X25519_MLKEM768)
    ct, sender_ss = encapsulate(pub)
    recipient_ss = decapsulate(priv, ct)

    assert sender_ss == recipient_ss
    assert len(sender_ss) == 32
    assert ct.profile == PROFILE_X25519_MLKEM768


def test_hybrid_kem_p256_mlkem768_roundtrip():
    """Verify ECDH-P256 + ML-KEM-768 shared-secret negotiation."""
    pub, priv = gen_kem_keys(PROFILE_P256_MLKEM768)
    ct, sender_ss = encapsulate(pub)
    recipient_ss = decapsulate(priv, ct)

    assert sender_ss == recipient_ss
    assert len(sender_ss) == 32
    assert ct.profile == PROFILE_P256_MLKEM768


def test_hybrid_kem_serialization():
    """Verify binary serialization and deserialization of public keys and ciphertexts."""
    pub, _ = gen_kem_keys(PROFILE_X25519_MLKEM768)
    pub_bytes = pub.to_bytes()
    restored_pub = HybridKEMPublicKey.from_bytes(pub_bytes)
    assert restored_pub == pub

    ct, _ = encapsulate(pub)
    ct_bytes = ct.to_bytes()
    restored_ct = HybridCiphertext.from_bytes(ct_bytes)
    assert restored_ct == ct


def test_hybrid_payload_encryption_aes_gcm():
    """Verify end-to-end payload encryption and decryption with associated authenticated data."""
    pub, priv = gen_kem_keys(PROFILE_X25519_MLKEM768)
    message = b"Confidential PKI Private Key Material or Enterprise Secret"
    aad = b"header-metadata-id-491"

    enc_msg = encrypt_message(pub, message, associated_data=aad)
    decrypted = decrypt_message(priv, enc_msg, associated_data=aad)

    assert decrypted == message


# ============================================================================
# Hybrid Signature Tests
# ============================================================================


def test_hybrid_signature_ecdsa_mldsa65():
    """Verify ECDSA-P256 + ML-DSA-65 composite signing and verification."""
    pub, priv = gen_sig_keys(PROFILE_ECDSA_MLDSA65)
    msg = b"Transaction ID 908123: Authorize root CA certificate rotation"

    sig = hybrid_sign(priv, msg)
    assert hybrid_verify(pub, msg, sig) is True

    # Details check
    details = verify_detailed(pub, msg, sig)
    assert details["classical_valid"] is True
    assert details["pq_valid"] is True
    assert details["composite_valid"] is True


def test_hybrid_signature_rsa_mldsa65():
    """Verify RSA-2048 + ML-DSA-65 composite signing and verification."""
    pub, priv = gen_sig_keys(PROFILE_RSA_MLDSA65)
    msg = b"RSA compatible enterprise certificate signing request"

    sig = hybrid_sign(priv, msg)
    assert hybrid_verify(pub, msg, sig) is True


def test_hybrid_sig_serialization():
    """Verify serialization and deserialization of signature public keys and signatures."""
    pub, priv = gen_sig_keys(PROFILE_ECDSA_MLDSA65)
    pub_bytes = pub.to_bytes()
    restored_pub = HybridSigPublicKey.from_bytes(pub_bytes)
    assert restored_pub == pub

    msg = b"Serialization check"
    sig = hybrid_sign(priv, msg)
    sig_bytes = sig.to_bytes()
    restored_sig = HybridSignature.from_bytes(sig_bytes)
    assert restored_sig == sig
    assert hybrid_verify(restored_pub, msg, restored_sig) is True


# ============================================================================
# Security & Tampering Negative Tests (Designed for Teammate 9)
# ============================================================================


def test_security_tampered_message_rejected():
    """Altering the message must cause signature verification to fail."""
    pub, priv = gen_sig_keys(PROFILE_ECDSA_MLDSA65)
    msg = b"Original Authentic Message"
    sig = hybrid_sign(priv, msg)

    tampered_msg = b"Original Authentic Message!"
    assert hybrid_verify(pub, tampered_msg, sig) is False


def test_security_tampered_classical_signature_rejected():
    """Flipping a bit in the classical signature component must invalidate the composite signature."""
    pub, priv = gen_sig_keys(PROFILE_ECDSA_MLDSA65)
    msg = b"Important Document"
    sig = hybrid_sign(priv, msg)

    # Flip 1 bit in classical signature
    tampered_c_sig = bytearray(sig.classical_sig_bytes)
    tampered_c_sig[5] ^= 0x01
    bad_sig = HybridSignature(
        profile=sig.profile,
        classical_sig_bytes=bytes(tampered_c_sig),
        pq_sig_bytes=sig.pq_sig_bytes,
    )

    details = verify_detailed(pub, msg, bad_sig)
    assert details["classical_valid"] is False
    assert details["pq_valid"] is True
    assert details["composite_valid"] is False
    assert hybrid_verify(pub, msg, bad_sig) is False


def test_security_tampered_pq_signature_rejected():
    """Flipping a bit in the ML-DSA signature component must invalidate the composite signature."""
    pub, priv = gen_sig_keys(PROFILE_ECDSA_MLDSA65)
    msg = b"Important Document"
    sig = hybrid_sign(priv, msg)

    # Flip 1 bit in ML-DSA signature
    tampered_pq_sig = bytearray(sig.pq_sig_bytes)
    tampered_pq_sig[20] ^= 0x01
    bad_sig = HybridSignature(
        profile=sig.profile,
        classical_sig_bytes=sig.classical_sig_bytes,
        pq_sig_bytes=bytes(tampered_pq_sig),
    )

    details = verify_detailed(pub, msg, bad_sig)
    assert details["classical_valid"] is True
    assert details["pq_valid"] is False
    assert details["composite_valid"] is False
    assert hybrid_verify(pub, msg, bad_sig) is False


def test_security_wrong_public_key_rejected():
    """Verifying against a different signer's public key must be rejected."""
    _, priv = gen_sig_keys(PROFILE_ECDSA_MLDSA65)
    wrong_pub, _ = gen_sig_keys(PROFILE_ECDSA_MLDSA65)
    msg = b"Protected data"
    sig = hybrid_sign(priv, msg)

    assert hybrid_verify(wrong_pub, msg, sig) is False


def test_security_tampered_kem_ciphertext_rejected():
    """Tampering with ML-KEM ciphertext must cause decapsulation or payload decryption failure."""
    pub, priv = gen_kem_keys(PROFILE_X25519_MLKEM768)
    msg = b"Top Secret Payload"
    enc = encrypt_message(pub, msg)

    # Corrupt 1 byte in ML-KEM ciphertext
    bad_pq_ct = bytearray(enc.hybrid_ciphertext.pq_ciphertext_bytes)
    bad_pq_ct[15] ^= 0x01

    tampered_hybrid_ct = HybridCiphertext(
        profile=enc.hybrid_ciphertext.profile,
        classical_ephemeral_pub_bytes=enc.hybrid_ciphertext.classical_ephemeral_pub_bytes,
        pq_ciphertext_bytes=bytes(bad_pq_ct),
    )
    tampered_enc = enc.__class__(
        hybrid_ciphertext=tampered_hybrid_ct,
        nonce=enc.nonce,
        encrypted_payload=enc.encrypted_payload,
    )

    with pytest.raises((DecapsulationError, DecryptionError)):
        decrypt_message(priv, tampered_enc)


def test_security_tampered_gcm_payload_rejected():
    """Tampering with the AES-GCM ciphertext bytes must be caught by AEAD authentication."""
    pub, priv = gen_kem_keys(PROFILE_X25519_MLKEM768)
    msg = b"Payment of $1,000 to Bob"
    enc = encrypt_message(pub, msg)

    # Tamper with encrypted payload
    bad_payload = bytearray(enc.encrypted_payload)
    bad_payload[2] ^= 0xFF

    tampered_enc = enc.__class__(
        hybrid_ciphertext=enc.hybrid_ciphertext,
        nonce=enc.nonce,
        encrypted_payload=bytes(bad_payload),
    )

    with pytest.raises(DecryptionError):
        decrypt_message(priv, tampered_enc)


# ============================================================================
# Hybrid PKI Migration Simulator Tests
# ============================================================================


def test_hybrid_pki_issuance_and_validation():
    """Test full CA issuance and policy-based validation of hybrid identity certificates."""
    ca = HybridCertificateAuthority(ca_name="Corp-Global-Root-CA")
    client_sig_pub, _ = gen_sig_keys(PROFILE_ECDSA_MLDSA65)
    client_kem_pub, _ = gen_kem_keys(PROFILE_X25519_MLKEM768)

    cert = ca.issue_certificate(
        subject_dn="CN=db-prod.internal.corp",
        subject_sig_pub=client_sig_pub,
        subject_kem_pub=client_kem_pub,
    )

    # Strict Hybrid validation
    valid, reason = ca.validate_certificate(cert, policy=MigrationPolicy.HYBRID_STRICT)
    assert valid is True
    assert "both classical & PQ verified" in reason

    # Legacy validation
    valid, reason = ca.validate_certificate(cert, policy=MigrationPolicy.LEGACY_PERMISSIVE)
    assert valid is True

    # PQ Strict validation
    valid, reason = ca.validate_certificate(cert, policy=MigrationPolicy.PQ_STRICT)
    assert valid is True


def test_hybrid_pki_tampered_certificate_rejected():
    """Altering the subject DN in a certificate without resigning must fail validation."""
    ca = HybridCertificateAuthority(ca_name="Corp-Global-Root-CA")
    client_sig_pub, _ = gen_sig_keys(PROFILE_ECDSA_MLDSA65)
    client_kem_pub, _ = gen_kem_keys(PROFILE_X25519_MLKEM768)

    cert = ca.issue_certificate(
        subject_dn="CN=user.corp",
        subject_sig_pub=client_sig_pub,
        subject_kem_pub=client_kem_pub,
    )

    # Attacker tries to elevate privileges to admin
    forged_cert = cert.__class__(
        serial_number=cert.serial_number,
        subject_dn="CN=admin.corp",
        issuer_dn=cert.issuer_dn,
        not_before=cert.not_before,
        not_after=cert.not_after,
        subject_sig_pub_bytes=cert.subject_sig_pub_bytes,
        subject_kem_pub_bytes=cert.subject_kem_pub_bytes,
        ca_signature_bytes=cert.ca_signature_bytes,
    )

    valid, reason = ca.validate_certificate(forged_cert, policy=MigrationPolicy.HYBRID_STRICT)
    assert valid is False
    assert "failed" in reason.lower()
