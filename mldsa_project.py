"""
ML-DSA (Dilithium) implementation and benchmark for a Data & Applications Security project.

Implements:
1. ML-DSA key generation
2. Message signing
3. Signature verification
4. Tampered-message testing
5. Tampered-signature testing
6. Wrong-public-key testing
7. Truncated-signature testing
8. Performance benchmarking
9. Key/signature size measurement
10. CSV export for comparison with RSA/ECC

Dependency:
    pip install liboqs-python

Examples:
    python mldsa_project.py
    python mldsa_project.py --algorithm ML-DSA-65 --iterations 2000
    python mldsa_project.py --all --iterations 1000
"""

from __future__ import annotations

import argparse
import csv
import statistics
import time
from dataclasses import asdict, dataclass
from pathlib import Path

import oqs


SUPPORTED_ALGORITHMS = ("ML-DSA-44", "ML-DSA-65", "ML-DSA-87")
DEFAULT_MESSAGE = b"UTD Data and Applications Security - ML-DSA test message"


@dataclass
class TimingStats:
    mean_ms: float
    median_ms: float
    stdev_ms: float
    ops_per_second: float


@dataclass
class BenchmarkResult:
    algorithm: str
    iterations: int
    public_key_bytes: int
    private_key_bytes: int
    signature_bytes: int

    keygen_mean_ms: float
    keygen_median_ms: float
    keygen_stdev_ms: float
    keygen_ops_per_second: float

    sign_mean_ms: float
    sign_median_ms: float
    sign_stdev_ms: float
    sign_ops_per_second: float

    verify_mean_ms: float
    verify_median_ms: float
    verify_stdev_ms: float
    verify_ops_per_second: float


def ensure_algorithm_available(algorithm: str) -> None:
    """Fail early if the requested ML-DSA parameter set is unavailable."""
    enabled = oqs.get_enabled_sig_mechanisms()
    if algorithm not in enabled:
        raise RuntimeError(
            f"{algorithm} is not enabled in this liboqs build.\n"
            f"Enabled signature algorithms include:\n{enabled}"
        )


def verify_safely(
    verifier: oqs.Signature,
    message: bytes,
    signature: bytes,
    public_key: bytes,
) -> bool:
    """
    Verify a signature.

    Some malformed inputs may be rejected by the Python wrapper itself.
    For tampering tests, either a False return value or an exception means
    the altered input was correctly rejected.
    """
    try:
        return bool(verifier.verify(message, signature, public_key))
    except (RuntimeError, ValueError):
        return False


def functional_security_tests(
    algorithm: str,
    message: bytes = DEFAULT_MESSAGE,
) -> dict[str, bool]:
    """
    Demonstrate correct ML-DSA operation and several negative/tampering tests.

    Returns a dictionary where True means the individual test behaved
    exactly as expected.
    """
    ensure_algorithm_available(algorithm)

    with oqs.Signature(algorithm) as signer, oqs.Signature(algorithm) as verifier:
        # 1) Key generation
        public_key = signer.generate_keypair()
        private_key = signer.export_secret_key()

        # 2) Signing
        signature = signer.sign(message)

        # 3) Normal verification
        valid_original = verify_safely(
            verifier, message, signature, public_key
        )

        # 4) Tamper with the message while keeping the original signature
        tampered_message = message + b" [TAMPERED]"
        tampered_message_accepted = verify_safely(
            verifier, tampered_message, signature, public_key
        )

        # 5) Flip exactly one bit in the signature
        tampered_signature = bytearray(signature)
        tamper_index = len(tampered_signature) // 2
        tampered_signature[tamper_index] ^= 0x01
        tampered_signature = bytes(tampered_signature)

        tampered_signature_accepted = verify_safely(
            verifier, message, tampered_signature, public_key
        )

        # 6) Generate a completely different key pair and try its public key
        with oqs.Signature(algorithm) as other_signer:
            wrong_public_key = other_signer.generate_keypair()

        wrong_key_accepted = verify_safely(
            verifier, message, signature, wrong_public_key
        )

        # 7) Remove one byte from the signature
        truncated_signature = signature[:-1]
        truncated_signature_accepted = verify_safely(
            verifier, message, truncated_signature, public_key
        )

        results = {
            "valid_signature_accepted": valid_original is True,
            "tampered_message_rejected": tampered_message_accepted is False,
            "tampered_signature_rejected": tampered_signature_accepted is False,
            "wrong_public_key_rejected": wrong_key_accepted is False,
            "truncated_signature_rejected": truncated_signature_accepted is False,
        }

        print(f"\n{'=' * 68}")
        print(f"FUNCTIONAL / SECURITY TESTS: {algorithm}")
        print(f"{'=' * 68}")
        print(f"Message size:      {len(message)} bytes")
        print(f"Public key size:   {len(public_key)} bytes")
        print(f"Private key size:  {len(private_key)} bytes")
        print(f"Signature size:    {len(signature)} bytes\n")

        labels = {
            "valid_signature_accepted": "Original signature accepted",
            "tampered_message_rejected": "Tampered message rejected",
            "tampered_signature_rejected": "1-bit-modified signature rejected",
            "wrong_public_key_rejected": "Wrong public key rejected",
            "truncated_signature_rejected": "Truncated signature rejected",
        }

        for name, passed in results.items():
            print(f"{'[PASS]' if passed else '[FAIL]'} {labels[name]}")

        if not all(results.values()):
            raise AssertionError(
                f"One or more {algorithm} functional/security tests failed."
            )

        return results


def summarize_timings(times_ns: list[int]) -> TimingStats:
    """Convert raw nanosecond timings to useful benchmark statistics."""
    times_ms = [t / 1_000_000 for t in times_ns]
    mean_ns = statistics.mean(times_ns)

    return TimingStats(
        mean_ms=statistics.mean(times_ms),
        median_ms=statistics.median(times_ms),
        stdev_ms=statistics.stdev(times_ms) if len(times_ms) > 1 else 0.0,
        ops_per_second=(1_000_000_000 / mean_ns) if mean_ns else float("inf"),
    )


def benchmark_algorithm(
    algorithm: str,
    iterations: int = 1000,
    message: bytes = DEFAULT_MESSAGE,
    warmup: int = 20,
) -> BenchmarkResult:
    """
    Benchmark ML-DSA key generation, signing, and verification.

    Each operation is measured independently using perf_counter_ns().
    """
    ensure_algorithm_available(algorithm)

    if iterations < 2:
        raise ValueError("iterations must be at least 2")
    if warmup < 0:
        raise ValueError("warmup cannot be negative")

    # ---------- KEY GENERATION ----------
    keygen_times: list[int] = []

    with oqs.Signature(algorithm) as keygen_signer:
        for _ in range(warmup):
            keygen_signer.generate_keypair()

        for _ in range(iterations):
            start = time.perf_counter_ns()
            keygen_signer.generate_keypair()
            end = time.perf_counter_ns()
            keygen_times.append(end - start)

    # ---------- CREATE A FIXED KEYPAIR FOR SIGN/VERIFY ----------
    with oqs.Signature(algorithm) as signer, oqs.Signature(algorithm) as verifier:
        public_key = signer.generate_keypair()
        private_key = signer.export_secret_key()

        # ---------- SIGNING ----------
        for _ in range(warmup):
            signer.sign(message)

        sign_times: list[int] = []
        signature = b""

        for _ in range(iterations):
            start = time.perf_counter_ns()
            signature = signer.sign(message)
            end = time.perf_counter_ns()
            sign_times.append(end - start)

        # Verify once before benchmarking to ensure the benchmark input is valid.
        if not verify_safely(verifier, message, signature, public_key):
            raise RuntimeError("Pre-benchmark signature verification failed.")

        # ---------- VERIFICATION ----------
        for _ in range(warmup):
            verifier.verify(message, signature, public_key)

        verify_times: list[int] = []

        for _ in range(iterations):
            start = time.perf_counter_ns()
            valid = verifier.verify(message, signature, public_key)
            end = time.perf_counter_ns()

            if not valid:
                raise RuntimeError("A valid signature failed during benchmarking.")

            verify_times.append(end - start)

        keygen_stats = summarize_timings(keygen_times)
        sign_stats = summarize_timings(sign_times)
        verify_stats = summarize_timings(verify_times)

        result = BenchmarkResult(
            algorithm=algorithm,
            iterations=iterations,
            public_key_bytes=len(public_key),
            private_key_bytes=len(private_key),
            signature_bytes=len(signature),

            keygen_mean_ms=keygen_stats.mean_ms,
            keygen_median_ms=keygen_stats.median_ms,
            keygen_stdev_ms=keygen_stats.stdev_ms,
            keygen_ops_per_second=keygen_stats.ops_per_second,

            sign_mean_ms=sign_stats.mean_ms,
            sign_median_ms=sign_stats.median_ms,
            sign_stdev_ms=sign_stats.stdev_ms,
            sign_ops_per_second=sign_stats.ops_per_second,

            verify_mean_ms=verify_stats.mean_ms,
            verify_median_ms=verify_stats.median_ms,
            verify_stdev_ms=verify_stats.stdev_ms,
            verify_ops_per_second=verify_stats.ops_per_second,
        )

    print_benchmark(result)
    return result


def print_benchmark(result: BenchmarkResult) -> None:
    """Print benchmark results in a readable format."""
    print(f"\n{'=' * 68}")
    print(f"BENCHMARK: {result.algorithm}")
    print(f"{'=' * 68}")
    print(f"Iterations:        {result.iterations}")
    print(f"Public key size:   {result.public_key_bytes} bytes")
    print(f"Private key size:  {result.private_key_bytes} bytes")
    print(f"Signature size:    {result.signature_bytes} bytes")

    print("\nOperation        Mean (ms)    Median (ms)    Std Dev (ms)    Ops/sec")
    print("-" * 68)
    print(
        f"Key generation   {result.keygen_mean_ms:9.6f}    "
        f"{result.keygen_median_ms:11.6f}    "
        f"{result.keygen_stdev_ms:12.6f}    "
        f"{result.keygen_ops_per_second:,.2f}"
    )
    print(
        f"Signing          {result.sign_mean_ms:9.6f}    "
        f"{result.sign_median_ms:11.6f}    "
        f"{result.sign_stdev_ms:12.6f}    "
        f"{result.sign_ops_per_second:,.2f}"
    )
    print(
        f"Verification     {result.verify_mean_ms:9.6f}    "
        f"{result.verify_median_ms:11.6f}    "
        f"{result.verify_stdev_ms:12.6f}    "
        f"{result.verify_ops_per_second:,.2f}"
    )


def save_results_to_csv(
    results: list[BenchmarkResult],
    output_path: str | Path,
) -> None:
    """Save benchmark results so they can be combined with RSA/ECC data."""
    path = Path(output_path)

    rows = [asdict(result) for result in results]

    with path.open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

    print(f"\nBenchmark results saved to: {path.resolve()}")


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="ML-DSA key generation, signing, verification, tamper testing, and benchmarking."
    )

    parser.add_argument(
        "--algorithm",
        choices=SUPPORTED_ALGORITHMS,
        default="ML-DSA-44",
        help="ML-DSA parameter set to test (default: ML-DSA-44).",
    )

    parser.add_argument(
        "--all",
        action="store_true",
        help="Run all three standardized ML-DSA parameter sets.",
    )

    parser.add_argument(
        "--iterations",
        type=int,
        default=1000,
        help="Number of timed iterations per operation (default: 1000).",
    )

    parser.add_argument(
        "--warmup",
        type=int,
        default=20,
        help="Untimed warm-up operations before each benchmark (default: 20).",
    )

    parser.add_argument(
        "--output",
        default="mldsa_results.csv",
        help="CSV benchmark output filename (default: mldsa_results.csv).",
    )

    parser.add_argument(
        "--message",
        default=DEFAULT_MESSAGE.decode("utf-8"),
        help="Message to sign during testing.",
    )

    return parser.parse_args()


def main() -> None:
    args = parse_arguments()
    message = args.message.encode("utf-8")

    algorithms = SUPPORTED_ALGORITHMS if args.all else (args.algorithm,)

    print("Open Quantum Safe / ML-DSA Project")
    print(f"liboqs version:        {oqs.oqs_version()}")
    print(f"liboqs-python version: {oqs.oqs_python_version()}")

    benchmark_results: list[BenchmarkResult] = []

    for algorithm in algorithms:
        functional_security_tests(algorithm, message)

        result = benchmark_algorithm(
            algorithm=algorithm,
            iterations=args.iterations,
            message=message,
            warmup=args.warmup,
        )
        benchmark_results.append(result)

    save_results_to_csv(benchmark_results, args.output)

    print("\nAll requested ML-DSA tests completed successfully.")


if __name__ == "__main__":
    main()
