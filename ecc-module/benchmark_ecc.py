"""Measure ECC operations; run separately from the correctness tests."""

import csv
from pathlib import Path
import statistics
import time

from ecc_implemented import ECCImplemented


ITERATIONS = 100
TEST_MESSAGE = b"ECC cryptographic benchmark test message."


def measure_operation(operation, iterations=ITERATIONS):
    measurements = []
    for _ in range(iterations):
        start = time.perf_counter()
        operation()
        measurements.append((time.perf_counter() - start) * 1000)
    return statistics.mean(measurements)


def benchmark_ecc(curve):
    key_generation_ms = measure_operation(lambda: ECCImplemented(curve))
    alice = ECCImplemented(curve)
    bob = ECCImplemented(curve)
    shared_key = alice.derive_shared_key(bob.public_key)
    if shared_key != bob.derive_shared_key(alice.public_key):
        raise RuntimeError(f"{curve}: shared keys do not match")
    signature = alice.sign(TEST_MESSAGE)
    if not alice.verify(TEST_MESSAGE, signature):
        raise RuntimeError(f"{curve}: signature verification failed")

    return {
        "algorithm": "ECC",
        "curve": curve,
        "key_generation_ms": key_generation_ms,
        "alice_key_derivation_ms": measure_operation(
            lambda: alice.derive_shared_key(bob.public_key)
        ),
        "bob_key_derivation_ms": measure_operation(
            lambda: bob.derive_shared_key(alice.public_key)
        ),
        "signing_ms": measure_operation(lambda: alice.sign(TEST_MESSAGE)),
        "verification_ms": measure_operation(lambda: alice.verify(TEST_MESSAGE, signature)),
        "public_key_bytes": alice.get_public_key_size_bytes(),
        "private_key_bytes": alice.get_private_key_size_bytes(),
        "shared_key_bytes": len(alice.derive_shared_key(bob.public_key)),
        "signature_bytes": len(signature),
    }


def main():
    print(f"ECC BENCHMARK RESULTS (mean of {ITERATIONS} iterations)")
    print("Key agreement timings include ECDH and HKDF-SHA256.")
    results = [benchmark_ecc(curve) for curve in ECCImplemented.SUPPORTED_CURVES]
    for result in results:
        print(f"\nECC {result['curve']}\n" + "-" * 45)
        for label, field in (
            ("Key Generation", "key_generation_ms"),
            ("Key Derivation (Alice)", "alice_key_derivation_ms"),
            ("Key Derivation (Bob)", "bob_key_derivation_ms"),
            ("Signing", "signing_ms"),
            ("Verification", "verification_ms"),
        ):
            print(f"{label + ':':25} {result[field]:.4f} ms")
        for label, field in (
            ("Public Key (PEM)", "public_key_bytes"),
            ("Private Key (PEM)", "private_key_bytes"),
            ("Derived Shared Key", "shared_key_bytes"),
            ("Signature (DER sample)", "signature_bytes"),
        ):
            print(f"{label + ':':25} {result[field]} bytes")
    output = Path(__file__).resolve().parent / "results" / "ecc_benchmark.csv"
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", newline="", encoding="utf-8") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=list(results[0]))
        writer.writeheader()
        writer.writerows(results)
    print(f"\nResults saved to: {output}")


if __name__ == "__main__":
    main()
