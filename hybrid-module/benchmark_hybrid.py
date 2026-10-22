"""
Automated Performance Benchmarking for Hybrid Classical + PQC System.
Measures execution time (keygen, encap/decap, sign/verify) and artifact sizes
(public key, private key, ciphertext, signature).

Outputs terminal summary and exports detailed results to CSV in results/hybrid_benchmark.csv.
"""

from __future__ import annotations

import csv
import os
import statistics
import sys
import time
from dataclasses import asdict, dataclass
from pathlib import Path

# Ensure hybrid-module directory is on sys.path
_MODULE_DIR = Path(__file__).resolve().parent
if str(_MODULE_DIR) not in sys.path:
    sys.path.insert(0, str(_MODULE_DIR))

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, mldsa, mlkem, x25519

import hybrid_kem
import hybrid_sig


@dataclass
class BenchmarkRow:
    category: str
    scheme_name: str
    security_type: str  # Classical, Post-Quantum, or Hybrid
    public_key_bytes: int
    private_key_bytes: int
    ciphertext_or_sig_bytes: int
    keygen_ms: float
    primary_op_name: str  # 'Encap' or 'Sign'
    primary_op_ms: float
    secondary_op_name: str  # 'Decap' or 'Verify'
    secondary_op_ms: float


def benchmark_op(func, iterations: int = 100) -> float:
    """Benchmark an operation and return average duration in milliseconds."""
    # Warmup
    for _ in range(max(1, min(10, iterations // 5))):
        func()

    start = time.perf_counter()
    for _ in range(iterations):
        func()
    total_s = time.perf_counter() - start
    return (total_s / iterations) * 1000.0


def run_all_benchmarks(iterations: int = 200) -> list[BenchmarkRow]:
    results: list[BenchmarkRow] = []
    print(f"\n=======================================================")
    print(f"  Hybrid Classical + PQC Performance Benchmark Harness ")
    print(f"  Iterations per operation: {iterations}")
    print(f"=======================================================\n")

    # -------------------------------------------------------------------------
    # 1. Classical KEM (X25519 Key Exchange)
    # -------------------------------------------------------------------------
    print("Measuring Classical (X25519 ECDH) ...")
    x_priv = x25519.X25519PrivateKey.generate()
    x_pub = x_priv.public_key()
    x_pub_bytes = len(x_pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))
    x_priv_bytes = len(
        x_priv.private_bytes(
            serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )
    )

    t_keygen_x = benchmark_op(lambda: x25519.X25519PrivateKey.generate(), iterations)
    peer_priv = x25519.X25519PrivateKey.generate()
    peer_pub = peer_priv.public_key()

    def x_encap():
        eph = x25519.X25519PrivateKey.generate()
        ss = eph.exchange(peer_pub)
        return eph.public_key(), ss

    t_encap_x = benchmark_op(x_encap, iterations)
    eph_pub, _ = x_encap()
    t_decap_x = benchmark_op(lambda: peer_priv.exchange(eph_pub), iterations)

    results.append(
        BenchmarkRow(
            category="Key Exchange / KEM",
            scheme_name="Classical X25519",
            security_type="Classical (128-bit)",
            public_key_bytes=x_pub_bytes,
            private_key_bytes=x_priv_bytes,
            ciphertext_or_sig_bytes=32,  # Ephemeral public key
            keygen_ms=t_keygen_x,
            primary_op_name="ECDH-Encap",
            primary_op_ms=t_encap_x,
            secondary_op_name="ECDH-Decap",
            secondary_op_ms=t_decap_x,
        )
    )

    # -------------------------------------------------------------------------
    # 2. Post-Quantum KEM (ML-KEM-768 / Kyber)
    # -------------------------------------------------------------------------
    print("Measuring Post-Quantum (ML-KEM-768 / FIPS 203) ...")
    kem_priv = mlkem.MLKEM768PrivateKey.generate()
    kem_pub = kem_priv.public_key()
    kem_pub_bytes = len(kem_pub.public_bytes_raw())
    kem_priv_bytes = len(
        kem_priv.private_bytes(
            serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )
    )

    t_keygen_kem = benchmark_op(lambda: mlkem.MLKEM768PrivateKey.generate(), iterations)
    t_encap_kem = benchmark_op(lambda: kem_pub.encapsulate(), iterations)
    _, ct_kem = kem_pub.encapsulate()
    t_decap_kem = benchmark_op(lambda: kem_priv.decapsulate(ct_kem), iterations)

    results.append(
        BenchmarkRow(
            category="Key Exchange / KEM",
            scheme_name="PQ ML-KEM-768",
            security_type="Post-Quantum (Category 3)",
            public_key_bytes=kem_pub_bytes,
            private_key_bytes=kem_priv_bytes,
            ciphertext_or_sig_bytes=len(ct_kem),
            keygen_ms=t_keygen_kem,
            primary_op_name="Encap",
            primary_op_ms=t_encap_kem,
            secondary_op_name="Decap",
            secondary_op_ms=t_decap_kem,
        )
    )

    # -------------------------------------------------------------------------
    # 3. Hybrid KEM (X25519 + ML-KEM-768)
    # -------------------------------------------------------------------------
    print("Measuring Hybrid KEM (X25519 + ML-KEM-768) ...")
    h_kem_pub, h_kem_priv = hybrid_kem.generate_keypair(hybrid_kem.PROFILE_X25519_MLKEM768)
    c_der, pq_der = h_kem_priv.to_pkcs8_der()
    h_priv_bytes = len(c_der) + len(pq_der)
    h_pub_bytes = h_kem_pub.total_bytes

    t_keygen_hkem = benchmark_op(
        lambda: hybrid_kem.generate_keypair(hybrid_kem.PROFILE_X25519_MLKEM768), iterations
    )
    t_encap_hkem = benchmark_op(lambda: hybrid_kem.encapsulate(h_kem_pub), iterations)
    h_ct, _ = hybrid_kem.encapsulate(h_kem_pub)
    t_decap_hkem = benchmark_op(lambda: hybrid_kem.decapsulate(h_kem_priv, h_ct), iterations)

    results.append(
        BenchmarkRow(
            category="Key Exchange / KEM",
            scheme_name="Hybrid X25519 + ML-KEM-768",
            security_type="Hybrid (Dual-Protected)",
            public_key_bytes=h_pub_bytes,
            private_key_bytes=h_priv_bytes,
            ciphertext_or_sig_bytes=h_ct.total_bytes,
            keygen_ms=t_keygen_hkem,
            primary_op_name="Hybrid Encap",
            primary_op_ms=t_encap_hkem,
            secondary_op_name="Hybrid Decap",
            secondary_op_ms=t_decap_hkem,
        )
    )

    # -------------------------------------------------------------------------
    # 4. Classical Signature (ECDSA P-256)
    # -------------------------------------------------------------------------
    print("Measuring Classical Signature (ECDSA P-256) ...")
    test_msg = b"UTD Security Class Benchmark Message for Hybrid Evaluation"
    ec_priv = ec.generate_private_key(ec.SECP256R1())
    ec_pub = ec_priv.public_key()
    ec_pub_bytes = len(
        ec_pub.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    )
    ec_priv_bytes = len(
        ec_priv.private_bytes(
            serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )
    )

    t_keygen_ec = benchmark_op(lambda: ec.generate_private_key(ec.SECP256R1()), iterations)
    t_sign_ec = benchmark_op(lambda: ec_priv.sign(test_msg, ec.ECDSA(hashes.SHA256())), iterations)
    ec_sig = ec_priv.sign(test_msg, ec.ECDSA(hashes.SHA256()))
    t_verify_ec = benchmark_op(
        lambda: ec_pub.verify(ec_sig, test_msg, ec.ECDSA(hashes.SHA256())), iterations
    )

    results.append(
        BenchmarkRow(
            category="Digital Signature",
            scheme_name="Classical ECDSA P-256",
            security_type="Classical (128-bit)",
            public_key_bytes=ec_pub_bytes,
            private_key_bytes=ec_priv_bytes,
            ciphertext_or_sig_bytes=len(ec_sig),
            keygen_ms=t_keygen_ec,
            primary_op_name="Sign",
            primary_op_ms=t_sign_ec,
            secondary_op_name="Verify",
            secondary_op_ms=t_verify_ec,
        )
    )

    # -------------------------------------------------------------------------
    # 5. Post-Quantum Signature (ML-DSA-65 / FIPS 204)
    # -------------------------------------------------------------------------
    print("Measuring Post-Quantum Signature (ML-DSA-65 / Dilithium) ...")
    dsa_priv = mldsa.MLDSA65PrivateKey.generate()
    dsa_pub = dsa_priv.public_key()
    dsa_pub_bytes = len(dsa_pub.public_bytes_raw())
    dsa_priv_bytes = len(
        dsa_priv.private_bytes(
            serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )
    )

    t_keygen_dsa = benchmark_op(lambda: mldsa.MLDSA65PrivateKey.generate(), iterations)
    t_sign_dsa = benchmark_op(lambda: dsa_priv.sign(test_msg), iterations)
    dsa_sig = dsa_priv.sign(test_msg)
    t_verify_dsa = benchmark_op(lambda: dsa_pub.verify(dsa_sig, test_msg), iterations)

    results.append(
        BenchmarkRow(
            category="Digital Signature",
            scheme_name="PQ ML-DSA-65",
            security_type="Post-Quantum (Category 3)",
            public_key_bytes=dsa_pub_bytes,
            private_key_bytes=dsa_priv_bytes,
            ciphertext_or_sig_bytes=len(dsa_sig),
            keygen_ms=t_keygen_dsa,
            primary_op_name="Sign",
            primary_op_ms=t_sign_dsa,
            secondary_op_name="Verify",
            secondary_op_ms=t_verify_dsa,
        )
    )

    # -------------------------------------------------------------------------
    # 6. Hybrid Signature (ECDSA P-256 + ML-DSA-65)
    # -------------------------------------------------------------------------
    print("Measuring Hybrid Signature (ECDSA P-256 + ML-DSA-65) ...")
    h_sig_pub, h_sig_priv = hybrid_sig.generate_keypair(hybrid_sig.PROFILE_ECDSA_MLDSA65)
    c_der, pq_der = h_sig_priv.to_pkcs8_der()
    h_sig_priv_bytes = len(c_der) + len(pq_der)
    h_sig_pub_bytes = h_sig_pub.total_bytes

    t_keygen_hsig = benchmark_op(
        lambda: hybrid_sig.generate_keypair(hybrid_sig.PROFILE_ECDSA_MLDSA65), iterations
    )
    t_sign_hsig = benchmark_op(lambda: hybrid_sig.sign(h_sig_priv, test_msg), iterations)
    h_signature = hybrid_sig.sign(h_sig_priv, test_msg)
    t_verify_hsig = benchmark_op(
        lambda: hybrid_sig.verify(h_sig_pub, test_msg, h_signature), iterations
    )

    results.append(
        BenchmarkRow(
            category="Digital Signature",
            scheme_name="Hybrid ECDSA + ML-DSA-65",
            security_type="Hybrid (Dual-Protected)",
            public_key_bytes=h_sig_pub_bytes,
            private_key_bytes=h_sig_priv_bytes,
            ciphertext_or_sig_bytes=h_signature.total_bytes,
            keygen_ms=t_keygen_hsig,
            primary_op_name="Hybrid Sign",
            primary_op_ms=t_sign_hsig,
            secondary_op_name="Hybrid Verify",
            secondary_op_ms=t_verify_hsig,
        )
    )

    return results


def print_and_export_results(results: list[BenchmarkRow]):
    # Header format
    header = (
        f"{'Scheme':<28} | {'Type':<22} | {'Pub(B)':>7} | {'Priv(B)':>7} | "
        f"{'Payload(B)':>10} | {'Keygen(ms)':>10} | {'Primary(ms)':>11} | {'Secondary(ms)':>13}"
    )
    sep = "-" * len(header)
    print("\n" + sep)
    print("              HYBRID CLASSICAL + PQC BENCHMARK RESULTS")
    print(sep)
    print(header)
    print(sep)

    for r in results:
        line = (
            f"{r.scheme_name:<28} | {r.security_type:<22} | {r.public_key_bytes:>7} | "
            f"{r.private_key_bytes:>7} | {r.ciphertext_or_sig_bytes:>10} | {r.keygen_ms:>10.4f} | "
            f"{r.primary_op_ms:>11.4f} | {r.secondary_op_ms:>13.4f}"
        )
        print(line)
    print(sep + "\n")

    # Export to CSV
    csv_path = _MODULE_DIR / "results" / "hybrid_benchmark.csv"
    csv_path.parent.mkdir(parents=True, exist_ok=True)
    with open(csv_path, mode="w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            "Category",
            "Scheme Name",
            "Security Type",
            "Public Key Bytes",
            "Private Key Bytes",
            "Ciphertext/Sig Bytes",
            "KeyGen Mean ms",
            "Primary Op Name",
            "Primary Op Mean ms",
            "Secondary Op Name",
            "Secondary Op Mean ms",
        ])
        for r in results:
            writer.writerow([
                r.category,
                r.scheme_name,
                r.security_type,
                r.public_key_bytes,
                r.private_key_bytes,
                r.ciphertext_or_sig_bytes,
                f"{r.keygen_ms:.4f}",
                r.primary_op_name,
                f"{r.primary_op_ms:.4f}",
                r.secondary_op_name,
                f"{r.secondary_op_ms:.4f}",
            ])
    print(f"Benchmark results successfully exported to: {csv_path}")


if __name__ == "__main__":
    results = run_all_benchmarks(iterations=200)
    print_and_export_results(results)
