"""Performance and size measurements for the PKI layer.

Runs the same certificate-authority workload once per registered algorithm and
reports how long each operation took and how large each artifact was. Because
every algorithm goes through the identical code path -- see
:mod:`pqpki.algorithms` -- a difference between two rows is a property of the
algorithm rather than of two different implementations, which is the only
reason the comparison means anything.

The workload per iteration is a realistic smallest-useful hierarchy:

1. Generate a root key and self-sign a root certificate.
2. Generate an intermediate key, request a certificate, issue it.
3. Generate a leaf key, request a certificate, issue it.
4. Validate the resulting three-link chain.
5. Revoke a backlog of certificates and publish a complete CRL.
6. Revoke a few more and publish a delta CRL covering only those.

Step 5's backlog matters. A delta CRL exists to avoid republishing a long
revocation list, so measuring one against an *empty* base CRL answers the wrong
question: the delta comes out larger than the base, because it carries one more
entry and an identically sized signature. With a realistic backlog the saving
appears, and how large it is turns out to depend on the algorithm -- which is
the finding worth having.

Run it from the command line::

    python -m pqpki.benchmark --iterations 10 --revoked 500

What this measures, and what it does not
----------------------------------------
Timings come from :func:`time.perf_counter` around the signing and validation
calls, collected through the ``collector`` hook the rest of the package already
exposes. They are wall-clock measurements on a loaded, general-purpose machine
with no warm-up, no pinned CPU and no control for turbo or thermal throttling.
Treat the *ratios between algorithms* as the finding and the absolute
milliseconds as indicative only; the standard deviation column is printed so
that a reader can see when a mean is not worth much.

Artifact sizes, by contrast, are exact. A DER certificate is as many bytes as
it is, every time, on every machine -- which is worth knowing because size is
where post-quantum certificates actually differ, not speed. ECDSA is the one
algorithm whose sizes wobble: its signature is a DER-encoded pair of integers
whose leading zero bytes vary with the value, so its lengths are reported as a
rounded mean over the iterations rather than a constant.

Nothing here is algorithm-aware: the row set comes from
:func:`pqpki.algorithms.list_algorithms`, so registering a sixth algorithm adds
a sixth row with no change to this file.
"""

from __future__ import annotations

import argparse
import csv
import dataclasses
import statistics
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from .algorithms import MetricEvent, get_algorithm, list_algorithms, public_key_size
from .ca import CertificateAuthority
from .csr import generate_csr
from .validate import validate_chain

__all__ = [
    "OPERATIONS",
    "AlgorithmResult",
    "benchmark_algorithm",
    "run",
    "write_csv",
    "main",
]

DER = serialization.Encoding.DER

#: Operations reported, in column order. These are the ``operation`` values the
#: package's ``collector`` hook emits.
OPERATIONS = (
    "generate_key",
    "issue_intermediate",
    "issue_end_entity",
    "validate_chain",
    "publish_crl",
    "publish_delta_crl",
)

#: Artifact sizes reported, in column order. Measured directly rather than
#: through the collector, because the collector reports the size of what an
#: operation produced and some of these are inputs or by-products.
SIZES = (
    "public_key_bytes",
    "signature_bytes",
    "root_cert_bytes",
    "intermediate_cert_bytes",
    "leaf_cert_bytes",
    "crl_bytes",
    "delta_crl_bytes",
)

#: Where :func:`main` writes its CSV, matching the ``<module>/results/`` layout
#: the other modules in this project use.
DEFAULT_OUTPUT = Path(__file__).parent / "results" / "pqpki_benchmark.csv"

LEAF_DNS_NAME = "leaf.benchmark.example"

#: How many certificates are already revoked when the complete CRL is
#: published, and how many more are revoked before the delta. A delta CRL only
#: pays for itself against a non-trivial backlog; see the module docstring.
DEFAULT_REVOKED_BACKLOG = 200
DEFAULT_DELTA_ADDITIONS = 2


@dataclasses.dataclass(frozen=True)
class AlgorithmResult:
    """Aggregated measurements for one algorithm.

    Attributes:
        algorithm: The algorithm name, as registered.
        post_quantum: Whether it is a post-quantum algorithm.
        iterations: How many full hierarchies were built.
        crl_entries: How many revocations the complete CRL carried.
        delta_entries: How many the delta CRL carried.
        durations_ms: Operation name -> every sample, in milliseconds. An
            operation may have more samples than ``iterations``: key
            generation happens three times per hierarchy.
        sizes: Size name -> every sample, in bytes.
    """

    algorithm: str
    post_quantum: bool
    iterations: int
    crl_entries: int
    delta_entries: int
    durations_ms: dict[str, list[float]]
    sizes: dict[str, list[int]]

    def mean_ms(self, operation: str) -> float | None:
        """Mean duration for ``operation``, or None if it was never measured."""
        samples = self.durations_ms.get(operation)
        return statistics.fmean(samples) if samples else None

    def stdev_ms(self, operation: str) -> float | None:
        """Sample standard deviation, or None with fewer than two samples.

        None rather than zero: one sample tells you nothing about spread, and
        reporting 0.0 would claim it told you the spread was zero.
        """
        samples = self.durations_ms.get(operation)
        if not samples or len(samples) < 2:
            return None
        return statistics.stdev(samples)

    def size(self, name: str) -> int | None:
        """Rounded mean size in bytes, or None if it was never measured."""
        samples = self.sizes.get(name)
        return round(statistics.fmean(samples)) if samples else None


def _run_once(
    algorithm: str,
    collect: "list[MetricEvent]",
    sizes: dict[str, list[int]],
    backlog: int = DEFAULT_REVOKED_BACKLOG,
    delta_additions: int = DEFAULT_DELTA_ADDITIONS,
) -> None:
    """Build one full hierarchy and exercise every instrumented operation."""
    root_ca = CertificateAuthority.create_root(
        "Benchmark Root", algorithm, validity_days=3650, collector=collect.append
    )

    intermediate_key = root_ca.algorithm.generate_key(collector=collect.append)
    intermediate_csr = generate_csr("Benchmark Intermediate", intermediate_key)
    intermediate = root_ca.issue_intermediate(intermediate_csr, validity_days=1825)
    intermediate_ca = CertificateAuthority(
        intermediate, intermediate_key, collector=collect.append
    )

    leaf_key = root_ca.algorithm.generate_key(collector=collect.append)
    leaf_csr = generate_csr("Benchmark Leaf", leaf_key, san_dns=[LEAF_DNS_NAME])
    leaf = intermediate_ca.issue_end_entity(leaf_csr, validity_days=90)

    result = validate_chain(
        leaf,
        [intermediate],
        [root_ca.certificate],
        collector=collect.append,
    )
    if not result.valid:
        # A benchmark that silently measures a broken workload is worse than no
        # benchmark, because the numbers still look plausible.
        raise RuntimeError(
            f"benchmark hierarchy for {algorithm} failed validation, so its "
            f"timings would describe something other than a working PKI: "
            f"{result.failures}"
        )

    # A backlog of already-revoked certificates, so the complete CRL has
    # realistic bulk for the delta to be compared against. The serials are
    # synthetic: `revoke` does not require that this CA issued them, because
    # it has no issuance database -- which is documented as a limitation and
    # is convenient exactly once, here.
    for serial in range(1, backlog + 1):
        intermediate_ca.revoke(serial, x509.ReasonFlags.superseded)
    intermediate_ca.publish_crl()

    intermediate_ca.revoke(leaf.serial_number, x509.ReasonFlags.key_compromise)
    for serial in range(backlog + 1, backlog + delta_additions):
        intermediate_ca.revoke(serial, x509.ReasonFlags.cessation_of_operation)
    intermediate_ca.publish_delta_crl()

    sizes["public_key_bytes"].append(public_key_size(leaf_key))
    sizes["signature_bytes"].append(len(leaf.signature))
    sizes["root_cert_bytes"].append(len(root_ca.certificate.public_bytes(DER)))


def benchmark_algorithm(
    algorithm: str,
    iterations: int = 5,
    backlog: int = DEFAULT_REVOKED_BACKLOG,
) -> AlgorithmResult:
    """Measure ``algorithm`` over ``iterations`` complete hierarchies.

    Args:
        algorithm: A name from :func:`pqpki.algorithms.list_algorithms`.
        iterations: How many hierarchies to build. More smooths out scheduler
            noise, at a linear cost in time -- dominated by RSA key
            generation, which is both the slowest operation here and by far
            the most variable.
        backlog: How many certificates are already revoked when the complete
            CRL is published. Governs how big the base CRL is, and therefore
            whether the delta CRL comparison means anything.

    Raises:
        UnknownAlgorithmError: If ``algorithm`` is not registered.
        ValueError: If ``iterations`` is below 1 or ``backlog`` is negative.
    """
    if iterations < 1:
        raise ValueError(f"iterations must be at least 1, got {iterations}")
    if backlog < 0:
        raise ValueError(f"backlog must not be negative, got {backlog}")

    spec = get_algorithm(algorithm)

    durations: dict[str, list[float]] = {name: [] for name in OPERATIONS}
    sizes: dict[str, list[int]] = {name: [] for name in SIZES}

    for _ in range(iterations):
        events: list[MetricEvent] = []
        _run_once(algorithm, events, sizes, backlog=backlog)

        for event in events:
            if event.operation in durations:
                durations[event.operation].append(event.duration_s * 1000.0)
            if event.artifact_bytes is None:
                continue
            # The collector reports what each operation produced, which is
            # where the certificate and CRL sizes come from.
            if event.operation == "issue_intermediate":
                sizes["intermediate_cert_bytes"].append(event.artifact_bytes)
            elif event.operation == "issue_end_entity":
                sizes["leaf_cert_bytes"].append(event.artifact_bytes)
            elif event.operation == "publish_crl":
                sizes["crl_bytes"].append(event.artifact_bytes)
            elif event.operation == "publish_delta_crl":
                sizes["delta_crl_bytes"].append(event.artifact_bytes)

    return AlgorithmResult(
        algorithm=spec.name,
        post_quantum=spec.is_post_quantum,
        iterations=iterations,
        crl_entries=backlog,
        delta_entries=DEFAULT_DELTA_ADDITIONS,
        durations_ms=durations,
        sizes=sizes,
    )


def run(
    algorithms: list[str] | None = None,
    iterations: int = 5,
    backlog: int = DEFAULT_REVOKED_BACKLOG,
) -> list[AlgorithmResult]:
    """Benchmark several algorithms, defaulting to every registered one."""
    names = algorithms if algorithms is not None else list_algorithms()
    return [benchmark_algorithm(name, iterations, backlog) for name in names]


def _columns() -> list[str]:
    header = [
        "algorithm",
        "post_quantum",
        "iterations",
        "crl_entries",
        "delta_entries",
    ]
    for operation in OPERATIONS:
        header.append(f"{operation}_mean_ms")
        header.append(f"{operation}_stdev_ms")
    header.extend(SIZES)
    return header


def _row(result: AlgorithmResult) -> dict[str, object]:
    row: dict[str, object] = {
        "algorithm": result.algorithm,
        "post_quantum": result.post_quantum,
        "iterations": result.iterations,
        "crl_entries": result.crl_entries,
        "delta_entries": result.delta_entries,
    }
    for operation in OPERATIONS:
        mean = result.mean_ms(operation)
        stdev = result.stdev_ms(operation)
        row[f"{operation}_mean_ms"] = "" if mean is None else f"{mean:.6f}"
        row[f"{operation}_stdev_ms"] = "" if stdev is None else f"{stdev:.6f}"
    for name in SIZES:
        value = result.size(name)
        row[name] = "" if value is None else value
    return row


def write_csv(results: list[AlgorithmResult], output: Path) -> Path:
    """Write ``results`` to ``output`` as CSV, creating parent directories."""
    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=_columns())
        writer.writeheader()
        for result in results:
            writer.writerow(_row(result))
    return output


def _print_table(results: list[AlgorithmResult]) -> None:
    """Print a human-readable summary, with the CSV holding the full detail."""
    if not results:
        return

    headers = ("algorithm", "pub key", "signature", "leaf cert", "CRL", "delta")
    print(f"{headers[0]:<12} {headers[1]:>8} {headers[2]:>10} "
          f"{headers[3]:>10} {headers[4]:>8} {headers[5]:>8}   bytes")
    print("-" * 72)
    for result in results:
        print(
            f"{result.algorithm:<12} "
            f"{result.size('public_key_bytes') or 0:>8} "
            f"{result.size('signature_bytes') or 0:>10} "
            f"{result.size('leaf_cert_bytes') or 0:>10} "
            f"{result.size('crl_bytes') or 0:>8} "
            f"{result.size('delta_crl_bytes') or 0:>8}"
        )

    print()
    print(f"{'algorithm':<12} {'keygen':>10} {'issue':>10} {'validate':>10} "
          f"{'CRL':>10} {'delta':>10}   mean ms")
    print("-" * 72)
    for result in results:
        def ms(operation: str) -> str:
            value = result.mean_ms(operation)
            return "-" if value is None else f"{value:.3f}"

        print(
            f"{result.algorithm:<12} "
            f"{ms('generate_key'):>10} "
            f"{ms('issue_end_entity'):>10} "
            f"{ms('validate_chain'):>10} "
            f"{ms('publish_crl'):>10} "
            f"{ms('publish_delta_crl'):>10}"
        )

    first = results[0]
    print()
    print(
        f"Delta CRL saving ({first.crl_entries} revocations in the base, "
        f"{first.delta_entries} new in the delta):"
    )
    for result in results:
        base_size = result.size("crl_bytes")
        delta_size = result.size("delta_crl_bytes")
        if not base_size or not delta_size:
            continue
        saved = 100.0 * (1.0 - delta_size / base_size)
        print(
            f"  {result.algorithm:<12} {base_size:>7} -> {delta_size:>6} bytes "
            f"({saved:5.1f}% smaller)"
        )

    baseline = next((r for r in results if not r.post_quantum), None)
    if baseline is None:
        return

    print()
    print(f"Size relative to {baseline.algorithm}:")
    for result in results:
        parts = []
        for name, label in (
            ("leaf_cert_bytes", "leaf cert"),
            ("signature_bytes", "signature"),
            ("crl_bytes", "CRL"),
        ):
            mine = result.size(name)
            theirs = baseline.size(name)
            if mine and theirs:
                parts.append(f"{label} x{mine / theirs:.1f}")
        print(f"  {result.algorithm:<12} {'  '.join(parts)}")


def main(argv: list[str] | None = None) -> int:
    """Command-line entry point. Returns a process exit status."""
    parser = argparse.ArgumentParser(
        prog="python -m pqpki.benchmark",
        description=(
            "Measure certificate authority timings and artifact sizes for "
            "every algorithm this PKI supports."
        ),
    )
    parser.add_argument(
        "--iterations",
        type=int,
        default=5,
        help="hierarchies to build per algorithm (default: 5)",
    )
    parser.add_argument(
        "--algorithm",
        action="append",
        dest="algorithms",
        metavar="NAME",
        help=(
            "benchmark only this algorithm; repeatable. Defaults to every "
            "registered algorithm."
        ),
    )
    parser.add_argument(
        "--revoked",
        type=int,
        default=DEFAULT_REVOKED_BACKLOG,
        metavar="N",
        help=(
            "revocations already on the complete CRL before the delta is "
            f"published (default: {DEFAULT_REVOKED_BACKLOG}). A delta CRL only "
            "saves anything against a non-empty base."
        ),
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT,
        help=f"CSV destination (default: {DEFAULT_OUTPUT})",
    )
    parser.add_argument(
        "--no-csv",
        action="store_true",
        help="print the summary without writing a CSV",
    )
    args = parser.parse_args(argv)

    if args.iterations < 1:
        parser.error("--iterations must be at least 1")
    if args.revoked < 0:
        parser.error("--revoked must not be negative")

    names = args.algorithms if args.algorithms else list_algorithms()
    unknown = [name for name in names if name not in list_algorithms()]
    if unknown:
        parser.error(
            f"unknown algorithm(s) {unknown}; registered: {list_algorithms()}"
        )

    print(
        f"Benchmarking {len(names)} algorithm(s), "
        f"{args.iterations} iteration(s) each.",
        file=sys.stderr,
    )
    results = run(names, args.iterations, args.revoked)
    _print_table(results)

    if not args.no_csv:
        written = write_csv(results, args.output)
        print(f"\nWrote {written}")
    return 0


if __name__ == "__main__":  # pragma: no cover - exercised via the console script
    raise SystemExit(main())
