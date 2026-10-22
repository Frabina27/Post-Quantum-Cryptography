import csv
import os
import statistics
import time

from rsa_crypto import RSACrypto


KEY_SIZES = [2048, 3072]


ITERATIONS = 100


TEST_MESSAGE = b"RSA cryptographic benchmark test message."


def measure_operation(operation, iterations=ITERATIONS):


    measurements = []

    for _ in range(iterations):
        start = time.perf_counter()
        operation()
        end = time.perf_counter()

        measurements.append((end - start) * 1000)

    return statistics.mean(measurements)


def benchmark_key_generation(key_size):


    measurements = []


    keygen_iterations = 10

    for _ in range(keygen_iterations):
        start = time.perf_counter()

        RSACrypto(key_size)

        end = time.perf_counter()

        measurements.append((end - start) * 1000)

    return statistics.mean(measurements)


def benchmark_rsa(key_size):


    print(f"\nBenchmarking RSA-{key_size}...")


    keygen_time = benchmark_key_generation(key_size)


    rsa = RSACrypto(key_size)


    encryption_time = measure_operation(
        lambda: rsa.encrypt(TEST_MESSAGE)
    )


    ciphertext = rsa.encrypt(TEST_MESSAGE)


    decryption_time = measure_operation(
        lambda: rsa.decrypt(ciphertext)
    )


    signing_time = measure_operation(
        lambda: rsa.sign(TEST_MESSAGE)
    )


    signature = rsa.sign(TEST_MESSAGE)


    verification_time = measure_operation(
        lambda: rsa.verify(TEST_MESSAGE, signature)
    )


    public_key_bytes = rsa.get_public_key_size_bytes()
    private_key_bytes = rsa.get_private_key_size_bytes()


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