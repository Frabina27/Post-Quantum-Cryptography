"""
Hybrid PKI & Migration Authority Module.
Simulates an enterprise PKI migration layer where a Certificate Authority (CA)
issues and validates hybrid certificates during transition from classical to post-quantum.

Demonstrates:
1. Dual-Trust Roots: CA possesses composite signing keys (ECDSA + ML-DSA-65).
2. Hybrid Certificates: Contains composite public keys and dual CA signatures.
3. Migration Policies:
   - MIGRATION_PHASE_1_LEGACY: Classical verification required; PQ is optional.
   - MIGRATION_PHASE_2_HYBRID: Strict dual-verification (both classical and PQ required).
   - MIGRATION_PHASE_3_PQ_ONLY: Post-quantum strictly enforced.
"""

from __future__ import annotations

import enum
import hashlib
import json
import time
from dataclasses import asdict, dataclass

try:
    from .hybrid_kem import HybridKEMPublicKey, generate_keypair as gen_kem_keypair
    from .hybrid_sig import (
        HybridSigPrivateKey,
        HybridSigPublicKey,
        HybridSignature,
        generate_keypair as gen_sig_keypair,
        sign as hybrid_sign,
        verify_detailed,
    )
except (ImportError, ValueError):
    from hybrid_kem import HybridKEMPublicKey, generate_keypair as gen_kem_keypair
    from hybrid_sig import (
        HybridSigPrivateKey,
        HybridSigPublicKey,
        HybridSignature,
        generate_keypair as gen_sig_keypair,
        sign as hybrid_sign,
        verify_detailed,
    )


class MigrationPolicy(enum.Enum):
    LEGACY_PERMISSIVE = "legacy_permissive"  # Classical must pass; PQ ignored if present
    HYBRID_STRICT = "hybrid_strict"          # Both classical AND PQ must pass
    PQ_STRICT = "pq_strict"                  # PQ must pass; classical ignored


@dataclass(frozen=True)
class HybridCertificate:
    """
    X.509-like representation of an enterprise hybrid identity certificate.
    """
    serial_number: int
    subject_dn: str
    issuer_dn: str
    not_before: float
    not_after: float
    subject_sig_pub_bytes: str   # hex-encoded
    subject_kem_pub_bytes: str   # hex-encoded
    ca_signature_bytes: str      # hex-encoded composite signature

    def tbs_bytes(self) -> bytes:
        """
        To-Be-Signed (TBS) canonical byte representation.
        """
        payload = {
            "serial_number": self.serial_number,
            "subject_dn": self.subject_dn,
            "issuer_dn": self.issuer_dn,
            "not_before": self.not_before,
            "not_after": self.not_after,
            "subject_sig_pub": self.subject_sig_pub_bytes,
            "subject_kem_pub": self.subject_kem_pub_bytes,
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def fingerprint_sha256(self) -> str:
        return hashlib.sha256(self.tbs_bytes()).hexdigest()


class HybridCertificateAuthority:
    """
    An enterprise Certificate Authority holding a hybrid signing identity.
    """
    def __init__(self, ca_name: str = "Enterprise-Root-Hybrid-CA"):
        self.ca_name = ca_name
        self.ca_sig_pub, self.ca_sig_priv = gen_sig_keypair(profile="ecdsa_mldsa65")
        self._next_serial = 1000

    def issue_certificate(
        self,
        subject_dn: str,
        subject_sig_pub: HybridSigPublicKey,
        subject_kem_pub: HybridKEMPublicKey,
        validity_seconds: int = 86400 * 365,
    ) -> HybridCertificate:
        """
        Issue a hybrid certificate signed by the CA's composite private key.
        """
        serial = self._next_serial
        self._next_serial += 1

        now = time.time()
        not_before = now - 60
        not_after = now + validity_seconds

        temp_cert = HybridCertificate(
            serial_number=serial,
            subject_dn=subject_dn,
            issuer_dn=self.ca_name,
            not_before=not_before,
            not_after=not_after,
            subject_sig_pub_bytes=subject_sig_pub.to_bytes().hex(),
            subject_kem_pub_bytes=subject_kem_pub.to_bytes().hex(),
            ca_signature_bytes="",
        )

        tbs = temp_cert.tbs_bytes()
        composite_sig = hybrid_sign(self.ca_sig_priv, tbs)

        return HybridCertificate(
            serial_number=serial,
            subject_dn=subject_dn,
            issuer_dn=self.ca_name,
            not_before=not_before,
            not_after=not_after,
            subject_sig_pub_bytes=temp_cert.subject_sig_pub_bytes,
            subject_kem_pub_bytes=temp_cert.subject_kem_pub_bytes,
            ca_signature_bytes=composite_sig.to_bytes().hex(),
        )

    def validate_certificate(
        self,
        certificate: HybridCertificate,
        policy: MigrationPolicy = MigrationPolicy.HYBRID_STRICT,
        current_time: float | None = None,
    ) -> tuple[bool, str]:
        """
        Validate a hybrid certificate against the CA public key according to policy.

        Returns:
            (is_valid: bool, reason: str)
        """
        now = time.time() if current_time is None else current_time

        # 1. Temporal Validity
        if now < certificate.not_before:
            return False, "Certificate is not yet valid"
        if now > certificate.not_after:
            return False, "Certificate has expired"

        # 2. Issuer check
        if certificate.issuer_dn != self.ca_name:
            return False, f"Unknown issuer: {certificate.issuer_dn}"

        # 3. Signature verification
        tbs = certificate.tbs_bytes()
        try:
            sig_bytes = bytes.fromhex(certificate.ca_signature_bytes)
            signature = HybridSignature.from_bytes(sig_bytes)
        except Exception as exc:
            return False, f"Malformed CA signature encoding: {exc}"

        verification = verify_detailed(self.ca_sig_pub, tbs, signature)

        if policy == MigrationPolicy.HYBRID_STRICT:
            if not verification["composite_valid"]:
                return (
                    False,
                    f"Hybrid strict policy failed: classical_valid={verification['classical_valid']}, "
                    f"pq_valid={verification['pq_valid']}",
                )
            return True, "Certificate valid under Hybrid Strict Policy (both classical & PQ verified)"

        if policy == MigrationPolicy.LEGACY_PERMISSIVE:
            if not verification["classical_valid"]:
                return False, "Legacy policy failed: classical signature invalid"
            return True, "Certificate valid under Legacy Permissive Policy (classical verified)"

        if policy == MigrationPolicy.PQ_STRICT:
            if not verification["pq_valid"]:
                return False, "PQ strict policy failed: post-quantum signature invalid"
            return True, "Certificate valid under PQ Strict Policy (post-quantum verified)"

        return False, f"Unknown policy: {policy}"
