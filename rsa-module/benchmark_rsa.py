"""
RSA Benchmarking Module

Measures RSA performance for different key sizes.

Metrics:
- Key generation time
- Encryption time
- Decryption time
- Signing time
- Verification time
- Public key storage size
- Private key storage size

Results are exported to:
results/rsa_benchmark.csv
"""

import csv
import os
import statistics
import time

from rsa_crypto import RSACrypto


KEY_SIZES = [2048, 3072]

# Number of times each operation is measured.
ITERATIONS = 100

# Small message because RSA is not designed for encrypting large files directly.
TEST_MESSAGE = b"RSA cryptographic benchmark test message."


def measure_operation(operation, iterations=ITERATIONS):
    """
    Measure the average execution time of an operation.

    Args:
        operation: Function to benchmark.
        iterations (int): Number of executions.

    Returns:
        float: Average execution time in milliseconds.
    """

    measurements = []

    for _ in range(iterations):
        start = time.perf_counter()
        operation()
        end = time.perf_counter()

        measurements.append((end - start) * 1000)

    return statistics.mean(measurements)


def benchmark_key_generation(key_size):
    """
    Benchmark RSA key generation separately because creating
    RSACrypto automatically generates a new key pair.
    """

    measurements = []

    # Key generation is considerably slower than the other operations,
    # so fewer repetitions are sufficient.
    keygen_iterations = 10 #this can be changed i originally had it at 10

    for _ in range(keygen_iterations):
        start = time.perf_counter()

        RSACrypto(key_size)

        end = time.perf_counter()

        measurements.append((end - start) * 1000)

    return statistics.mean(measurements)


def benchmark_rsa(key_size):
    """Run all RSA benchmarks for one key size."""

    print(f"\nBenchmarking RSA-{key_size}...")

    # -----------------------------
    # Key generation
    # -----------------------------

    keygen_time = benchmark_key_generation(key_size)

    # Generate one key pair for remaining benchmarks.
    rsa = RSACrypto(key_size)

    # -----------------------------
    # Encryption
    # -----------------------------

    encryption_time = measure_operation(
        lambda: rsa.encrypt(TEST_MESSAGE)
    )

    # Generate ciphertext once so decryption timing does not
    # accidentally include encryption time.
    ciphertext = rsa.encrypt(TEST_MESSAGE)

    # -----------------------------
    # Decryption
    # -----------------------------

    decryption_time = measure_operation(
        lambda: rsa.decrypt(ciphertext)
    )

    # -----------------------------
    # Signing
    # -----------------------------

    signing_time = measure_operation(
        lambda: rsa.sign(TEST_MESSAGE)
    )

    # Generate one valid signature for verification benchmarking.
    signature = rsa.sign(TEST_MESSAGE)

    # -----------------------------
    # Verification
    # -----------------------------

    verification_time = measure_operation(
        lambda: rsa.verify(TEST_MESSAGE, signature)
    )

    # -----------------------------
    # Key storage sizes
    # -----------------------------

    public_key_bytes = rsa.get_public_key_size_bytes()
    private_key_bytes = rsa.get_private_key_size_bytes()

    # Ciphertext and signature sizes are also useful when comparing
    # classical RSA against post-quantum algorithms.
    ciphertext_bytes = len(ciphertext)
    signature_bytes = len(signature)

    results = {
        "algorithm": "RSA",
        "key_size_bits": key_size,
        "key_generation_ms": keygen_time,
        "encryption_ms": encryption_time,
        "decryption_ms": decryption_time,
        "signing_ms": signing_time,
        "verification_ms": verification_time,
        "public_key_bytes": public_key_bytes,
        "private_key_bytes": private_key_bytes,
        "ciphertext_bytes": ciphertext_bytes,
        "signature_bytes": signature_bytes
    }

    return results


def save_results(results):
    """Save benchmark results to a CSV file."""

    # Store results inside the rsa-module/results directory,
# regardless of where the script is executed from.
    base_dir = os.path.dirname(os.path.abspath(__file__))
    results_dir = os.path.join(base_dir, "results")

    os.makedirs(results_dir, exist_ok=True)

    output_file = os.path.join(
        results_dir,
        "rsa_benchmark.csv"
    )

    fieldnames = [
        "algorithm",
        "key_size_bits",
        "key_generation_ms",
        "encryption_ms",
        "decryption_ms",
        "signing_ms",
        "verification_ms",
        "public_key_bytes",
        "private_key_bytes",
        "ciphertext_bytes",
        "signature_bytes"
    ]

    with open(output_file, "w", newline="") as csv_file:
        writer = csv.DictWriter(
            csv_file,
            fieldnames=fieldnames
        )

        writer.writeheader()
        writer.writerows(results)

    print(f"\nResults saved to: {output_file}")


def print_results(results):
    """Print benchmark results in a readable format."""

    print("\n" + "=" * 65)
    print("RSA BENCHMARK RESULTS")
    print("=" * 65)

    for result in results:

        print(f"\nRSA-{result['key_size_bits']}")
        print("-" * 40)

        print(
            f"Key Generation: "
            f"{result['key_generation_ms']:.4f} ms"
        )

        print(
            f"Encryption:     "
            f"{result['encryption_ms']:.4f} ms"
        )

        print(
            f"Decryption:     "
            f"{result['decryption_ms']:.4f} ms"
        )

        print(
            f"Signing:        "
            f"{result['signing_ms']:.4f} ms"
        )

        print(
            f"Verification:   "
            f"{result['verification_ms']:.4f} ms"
        )

        print(
            f"Public Key:     "
            f"{result['public_key_bytes']} bytes"
        )

        print(
            f"Private Key:    "
            f"{result['private_key_bytes']} bytes"
        )

        print(
            f"Ciphertext:     "
            f"{result['ciphertext_bytes']} bytes"
        )

        print(
            f"Signature:      "
            f"{result['signature_bytes']} bytes"
        )


def main():

    all_results = []

    for key_size in KEY_SIZES:
        result = benchmark_rsa(key_size)
        all_results.append(result)

    print_results(all_results)

    save_results(all_results)


if __name__ == "__main__":
    main()