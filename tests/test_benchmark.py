"""The benchmark harness.

A benchmark cannot be tested for its numbers -- they vary by machine and by
run, and asserting on a millisecond figure would produce a test that fails on
a loaded laptop. What can be tested is everything around them:

* that the workload actually ran, and produced a *valid* chain while it did
  (a benchmark measuring a broken PKI still reports plausible-looking numbers);
* that every operation and size the harness claims to report is populated;
* that the size relationships hold, since those are exact and machine-
  independent -- a post-quantum certificate really is larger, every time;
* that the CSV is well-formed and complete.

Timings are only checked for being positive and finite.
"""

from __future__ import annotations

import csv
import math

import pytest

from pqpki.algorithms import list_algorithms
from pqpki.benchmark import (
    OPERATIONS,
    SIZES,
    AlgorithmResult,
    benchmark_algorithm,
    main,
    run,
    write_csv,
)
from pqpki.errors import UnknownAlgorithmError

FAST_ALGORITHM = "ecdsa-p256"
PQ_ALGORITHM = "ml-dsa-65"


@pytest.fixture(scope="module")
def fast_result() -> AlgorithmResult:
    return benchmark_algorithm(FAST_ALGORITHM, iterations=2, backlog=10)


# --------------------------------------------------------------------------
# The workload ran, and ran correctly
# --------------------------------------------------------------------------


def test_every_operation_is_measured(fast_result) -> None:
    for operation in OPERATIONS:
        assert fast_result.durations_ms[operation], f"{operation} was never measured"


def test_every_size_is_measured(fast_result) -> None:
    for name in SIZES:
        assert fast_result.sizes[name], f"{name} was never measured"


def test_key_generation_is_sampled_three_times_per_iteration(fast_result) -> None:
    """Root, intermediate, and leaf keys, so two iterations give six samples."""
    assert len(fast_result.durations_ms["generate_key"]) == 6


def test_a_failed_chain_aborts_the_benchmark(monkeypatch) -> None:
    """Numbers from a broken PKI are worse than no numbers."""
    import pqpki.benchmark as benchmark_module
    from pqpki.validate import ValidationResult

    def broken(*args, **kwargs):
        return ValidationResult(
            valid=False, chain_length=0, failures=["signature: forced"], algorithms_used=[]
        )

    monkeypatch.setattr(benchmark_module, "validate_chain", broken)
    with pytest.raises(RuntimeError, match="failed validation"):
        benchmark_algorithm(FAST_ALGORITHM, iterations=1, backlog=0)


# --------------------------------------------------------------------------
# Timings: shape only, never magnitude
# --------------------------------------------------------------------------


def test_durations_are_positive_and_finite(fast_result) -> None:
    for operation in OPERATIONS:
        for sample in fast_result.durations_ms[operation]:
            assert math.isfinite(sample)
            assert sample > 0.0


def test_mean_is_reported_for_every_operation(fast_result) -> None:
    for operation in OPERATIONS:
        assert fast_result.mean_ms(operation) is not None


def test_stdev_needs_at_least_two_samples() -> None:
    """One sample says nothing about spread, so None rather than 0.0."""
    result = AlgorithmResult(
        algorithm="x",
        post_quantum=False,
        iterations=1,
        crl_entries=0,
        delta_entries=0,
        durations_ms={"only_one": [1.0], "two": [1.0, 2.0]},
        sizes={},
    )
    assert result.stdev_ms("only_one") is None
    assert result.stdev_ms("two") is not None


def test_unmeasured_operations_report_none() -> None:
    result = AlgorithmResult(
        algorithm="x",
        post_quantum=False,
        iterations=1,
        crl_entries=0,
        delta_entries=0,
        durations_ms={},
        sizes={},
    )
    assert result.mean_ms("generate_key") is None
    assert result.size("leaf_cert_bytes") is None


# --------------------------------------------------------------------------
# Sizes: exact, so they can be asserted properly
# --------------------------------------------------------------------------


def test_post_quantum_artifacts_are_larger(fast_result) -> None:
    pq = benchmark_algorithm(PQ_ALGORITHM, iterations=1, backlog=10)
    for name in ("public_key_bytes", "signature_bytes", "leaf_cert_bytes"):
        assert pq.size(name) > fast_result.size(name), name


def test_a_certificate_is_larger_than_the_signature_it_carries(fast_result) -> None:
    assert fast_result.size("leaf_cert_bytes") > fast_result.size("signature_bytes")


def test_leaf_and_intermediate_are_comparable_in_size(fast_result) -> None:
    """They differ only by their extension sets, not by orders of magnitude."""
    leaf = fast_result.size("leaf_cert_bytes")
    intermediate = fast_result.size("intermediate_cert_bytes")
    assert 0.5 < leaf / intermediate < 2.0


def test_delta_crl_is_smaller_than_the_base_it_refines() -> None:
    """The reason delta CRLs exist, measured rather than assumed."""
    result = benchmark_algorithm(FAST_ALGORITHM, iterations=1, backlog=200)
    assert result.size("delta_crl_bytes") < result.size("crl_bytes")


def test_the_delta_saving_is_smaller_for_post_quantum() -> None:
    """A finding worth protecting: the fixed signature dominates a short delta.

    A post-quantum signature is a large fixed cost paid once per CRL, so when
    the delta carries only a couple of entries it cannot shrink as far,
    proportionally, as a classical one.
    """
    classical = benchmark_algorithm(FAST_ALGORITHM, iterations=1, backlog=200)
    post_quantum = benchmark_algorithm(PQ_ALGORITHM, iterations=1, backlog=200)

    def saving(result: AlgorithmResult) -> float:
        return 1.0 - result.size("delta_crl_bytes") / result.size("crl_bytes")

    assert saving(classical) > saving(post_quantum)


def test_backlog_governs_the_base_crl_size() -> None:
    small = benchmark_algorithm(FAST_ALGORITHM, iterations=1, backlog=5)
    large = benchmark_algorithm(FAST_ALGORITHM, iterations=1, backlog=100)
    assert large.size("crl_bytes") > small.size("crl_bytes")


def test_reported_entry_counts_match_the_backlog() -> None:
    result = benchmark_algorithm(FAST_ALGORITHM, iterations=1, backlog=7)
    assert result.crl_entries == 7


# --------------------------------------------------------------------------
# Arguments
# --------------------------------------------------------------------------


def test_unknown_algorithm_is_rejected() -> None:
    with pytest.raises(UnknownAlgorithmError):
        benchmark_algorithm("rot13")


def test_zero_iterations_is_rejected() -> None:
    with pytest.raises(ValueError, match="at least 1"):
        benchmark_algorithm(FAST_ALGORITHM, iterations=0)


def test_negative_backlog_is_rejected() -> None:
    with pytest.raises(ValueError, match="must not be negative"):
        benchmark_algorithm(FAST_ALGORITHM, iterations=1, backlog=-1)


def test_run_defaults_to_every_registered_algorithm() -> None:
    results = run(iterations=1, backlog=0)
    assert [r.algorithm for r in results] == list_algorithms()


def test_run_honours_an_explicit_list() -> None:
    results = run([FAST_ALGORITHM], iterations=1, backlog=0)
    assert [r.algorithm for r in results] == [FAST_ALGORITHM]


def test_post_quantum_flag_is_reported_correctly() -> None:
    results = run([FAST_ALGORITHM, PQ_ALGORITHM], iterations=1, backlog=0)
    assert [r.post_quantum for r in results] == [False, True]


# --------------------------------------------------------------------------
# CSV output
# --------------------------------------------------------------------------


def test_csv_has_one_row_per_algorithm(tmp_path, fast_result) -> None:
    path = write_csv([fast_result], tmp_path / "out.csv")
    with path.open(encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    assert len(rows) == 1
    assert rows[0]["algorithm"] == FAST_ALGORITHM


def test_csv_contains_a_column_for_every_operation_and_size(
    tmp_path, fast_result
) -> None:
    path = write_csv([fast_result], tmp_path / "out.csv")
    with path.open(encoding="utf-8") as handle:
        columns = set(next(csv.reader(handle)))
    for operation in OPERATIONS:
        assert f"{operation}_mean_ms" in columns
        assert f"{operation}_stdev_ms" in columns
    for name in SIZES:
        assert name in columns


def test_csv_values_are_parseable_numbers(tmp_path, fast_result) -> None:
    path = write_csv([fast_result], tmp_path / "out.csv")
    with path.open(encoding="utf-8") as handle:
        row = next(csv.DictReader(handle))
    for operation in OPERATIONS:
        assert float(row[f"{operation}_mean_ms"]) > 0
    for name in SIZES:
        assert int(row[name]) > 0


def test_csv_creates_missing_directories(tmp_path, fast_result) -> None:
    path = write_csv([fast_result], tmp_path / "deep" / "nested" / "out.csv")
    assert path.exists()


def test_csv_is_overwritten_not_appended(tmp_path, fast_result) -> None:
    destination = tmp_path / "out.csv"
    write_csv([fast_result], destination)
    write_csv([fast_result], destination)
    with destination.open(encoding="utf-8") as handle:
        assert len(list(csv.DictReader(handle))) == 1


# --------------------------------------------------------------------------
# Command line
# --------------------------------------------------------------------------


def test_main_writes_a_csv_and_returns_zero(tmp_path, capsys) -> None:
    destination = tmp_path / "bench.csv"
    status = main(
        [
            "--algorithm",
            FAST_ALGORITHM,
            "--iterations",
            "1",
            "--revoked",
            "5",
            "--output",
            str(destination),
        ]
    )
    assert status == 0
    assert destination.exists()
    assert "Wrote" in capsys.readouterr().out


def test_main_no_csv_writes_nothing(tmp_path, capsys) -> None:
    destination = tmp_path / "bench.csv"
    main(
        [
            "--algorithm",
            FAST_ALGORITHM,
            "--iterations",
            "1",
            "--revoked",
            "0",
            "--output",
            str(destination),
            "--no-csv",
        ]
    )
    assert not destination.exists()


def test_main_prints_the_comparison_tables(tmp_path, capsys) -> None:
    main(
        [
            "--algorithm",
            FAST_ALGORITHM,
            "--algorithm",
            PQ_ALGORITHM,
            "--iterations",
            "1",
            "--revoked",
            "20",
            "--output",
            str(tmp_path / "bench.csv"),
        ]
    )
    output = capsys.readouterr().out
    assert "Delta CRL saving" in output
    assert "Size relative to" in output


def test_main_rejects_an_unknown_algorithm() -> None:
    with pytest.raises(SystemExit):
        main(["--algorithm", "rot13"])


def test_main_rejects_zero_iterations() -> None:
    with pytest.raises(SystemExit):
        main(["--iterations", "0"])


def test_main_rejects_a_negative_backlog() -> None:
    with pytest.raises(SystemExit):
        main(["--revoked", "-5"])
