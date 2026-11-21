# Performance benchmarks for ML-DSA
# times key generation, signing and verification for ML-DSA-44/65/87
# and saves everything to results/mldsa_benchmark.csv
#
# usage:
#   python benchmark_mldsa.py
#   python benchmark_mldsa.py --iterations 500
#   python benchmark_mldsa.py --algorithm ML-DSA-65

import argparse
import csv
import os
import statistics
import time

import oqs

from mldsa_project import MLDSA, ALGORITHMS


ITERATIONS = 1000
WARMUP = 20   # untimed runs first so the first few slow ones don't mess up the average

TEST_MESSAGE = b"ML-DSA cryptographic benchmark test message."


def get_stats(times):
    # times are in nanoseconds, turn them into milliseconds
    times_ms = []
    for t in times:
        times_ms.append(t / 1000000)

    mean = statistics.mean(times_ms)
    median = statistics.median(times_ms)
    if len(times_ms) > 1:
        stdev = statistics.stdev(times_ms)
    else:
        stdev = 0.0

    if mean > 0:
        ops_per_sec = 1000 / mean
    else:
        ops_per_sec = 0

    return mean, median, stdev, ops_per_sec


def time_it(func, iterations, warmup):
    # run func a bunch of times and return a list of how long each one took
    for i in range(warmup):
        func()

    times = []
    for i in range(iterations):
        start = time.perf_counter_ns()
        func()
        end = time.perf_counter_ns()
        times.append(end - start)
    return times


def benchmark_mldsa(algorithm, iterations=ITERATIONS, warmup=WARMUP):

    print("\nBenchmarking " + algorithm + "...")

    dsa = MLDSA(algorithm)

    # key generation
    # (this makes new keys each time but we fix them back after)
    keygen_times = time_it(dsa.signer.generate_keypair, iterations, warmup)
    dsa.generate_keypair()

    # signing
    sign_times = time_it(lambda: dsa.sign(TEST_MESSAGE), iterations, warmup)

    signature = dsa.sign(TEST_MESSAGE)

    # make sure the signature is actually good before timing verify
    if not dsa.verify(TEST_MESSAGE, signature):
        dsa.close()
        raise RuntimeError("signature didn't verify, can't benchmark verify")

    # verification
    # calling the oqs verify directly here so the try/except in our wrapper isn't timed
    verify_times = time_it(
        lambda: dsa.verifier.verify(TEST_MESSAGE, signature, dsa.public_key),
        iterations,
        warmup,
    )

    keygen_mean, keygen_median, keygen_stdev, keygen_ops = get_stats(keygen_times)
    sign_mean, sign_median, sign_stdev, sign_ops = get_stats(sign_times)
    verify_mean, verify_median, verify_stdev, verify_ops = get_stats(verify_times)

    result = {
        "algorithm": algorithm,
        "iterations": iterations,
        "public_key_bytes": dsa.get_public_key_size(),
        "private_key_bytes": dsa.get_private_key_size(),
        "signature_bytes": len(signature),
        "keygen_mean_ms": keygen_mean,
        "keygen_median_ms": keygen_median,
        "keygen_stdev_ms": keygen_stdev,
        "keygen_ops_per_second": keygen_ops,
        "sign_mean_ms": sign_mean,
        "sign_median_ms": sign_median,
        "sign_stdev_ms": sign_stdev,
        "sign_ops_per_second": sign_ops,
        "verify_mean_ms": verify_mean,
        "verify_median_ms": verify_median,
        "verify_stdev_ms": verify_stdev,
        "verify_ops_per_second": verify_ops,
    }

    dsa.close()
    return result


def print_results(results):

    print("\n" + "=" * 72)
    print("ML-DSA BENCHMARK RESULTS")
    print("=" * 72)

    for r in results:
        print("\n" + r["algorithm"] + "  (" + str(r["iterations"]) + " iterations)")
        print("-" * 72)
        print("Public key:  " + str(r["public_key_bytes"]) + " bytes")
        print("Private key: " + str(r["private_key_bytes"]) + " bytes")
        print("Signature:   " + str(r["signature_bytes"]) + " bytes")
        print("")
        print("Operation        Mean (ms)   Median (ms)   Std Dev (ms)      Ops/sec")
        print("Key generation   %9.4f   %11.4f   %12.4f   %10.2f" % (
            r["keygen_mean_ms"], r["keygen_median_ms"], r["keygen_stdev_ms"], r["keygen_ops_per_second"]))
        print("Signing          %9.4f   %11.4f   %12.4f   %10.2f" % (
            r["sign_mean_ms"], r["sign_median_ms"], r["sign_stdev_ms"], r["sign_ops_per_second"]))
        print("Verification     %9.4f   %11.4f   %12.4f   %10.2f" % (
            r["verify_mean_ms"], r["verify_median_ms"], r["verify_stdev_ms"], r["verify_ops_per_second"]))


def save_results(results, filename="mldsa_benchmark.csv"):

    # save in the results folder next to this file (same as the rsa module)
    base_dir = os.path.dirname(os.path.abspath(__file__))
    results_dir = os.path.join(base_dir, "results")
    os.makedirs(results_dir, exist_ok=True)

    output_file = os.path.join(results_dir, filename)

    fieldnames = list(results[0].keys())

    with open(output_file, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results)

    print("\nResults saved to: " + output_file)


def main():

    parser = argparse.ArgumentParser(description="ML-DSA performance benchmarks")
    parser.add_argument("--algorithm", choices=ALGORITHMS, default=None,
                        help="only benchmark one parameter set (default: all 3)")
    parser.add_argument("--iterations", type=int, default=ITERATIONS,
                        help="how many timed runs per operation (default: 1000)")
    parser.add_argument("--warmup", type=int, default=WARMUP,
                        help="untimed runs before timing (default: 20)")
    parser.add_argument("--output", default="mldsa_benchmark.csv",
                        help="csv file name inside results/ (default: mldsa_benchmark.csv)")
    args = parser.parse_args()

    if args.iterations < 2:
        print("iterations needs to be at least 2")
        return
    if args.warmup < 0:
        print("warmup can't be negative")
        return

    if args.algorithm:
        algs = [args.algorithm]
    else:
        algs = ALGORITHMS

    print("liboqs version: " + oqs.oqs_version())

    all_results = []
    for alg in algs:
        result = benchmark_mldsa(alg, args.iterations, args.warmup)
        all_results.append(result)

    print_results(all_results)
    save_results(all_results, args.output)


if __name__ == "__main__":
    main()
