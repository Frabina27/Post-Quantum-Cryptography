"""Tests for the demonstration driver.

A demo that silently stops demonstrating anything is worse than no demo, so
these check the actual observable behaviour: the exit status, the artifacts on
disk, and the fact that the output really does show a valid chain becoming an
invalid one for a named reason.
"""

from __future__ import annotations

import re

import pytest

from pqpki import list_algorithms
from pqpki.cli import main


def test_default_run_succeeds(capsys: pytest.CaptureFixture[str]) -> None:
    """The out-of-the-box command, which is the post-quantum path."""
    assert main([]) == 0
    output = capsys.readouterr().out
    assert "ml-dsa-65" in output
    assert "All stages behaved as expected." in output


@pytest.mark.parametrize("name", list_algorithms())
def test_every_algorithm_runs(
    name: str, capsys: pytest.CaptureFixture[str], tmp_path
) -> None:
    assert main(["--algorithm", name, "--directory", str(tmp_path / name)]) == 0
    assert f"pqpki demonstration -- {name}" in capsys.readouterr().out


def test_demo_shows_a_valid_chain_then_a_revoked_one(
    capsys: pytest.CaptureFixture[str], tmp_path
) -> None:
    """The whole narrative arc the demo exists to show."""
    assert main(["--algorithm", "ml-dsa-44", "--directory", str(tmp_path)]) == 0
    output = capsys.readouterr().out

    valid_at = output.index("VALID -- chain of 3 certificates")
    invalid_at = output.index("INVALID --")
    assert valid_at < invalid_at, "validation must succeed before it fails"

    assert "[revoked]" in output
    assert "keyCompromise" in output


def test_demo_reports_metric_events(
    capsys: pytest.CaptureFixture[str], tmp_path
) -> None:
    """Instrumentation must be visibly reachable, with real numbers."""
    assert main(["--algorithm", "ecdsa-p256", "--directory", str(tmp_path)]) == 0
    output = capsys.readouterr().out

    for operation in (
        "generate_key",
        "issue_intermediate",
        "issue_end_entity",
        "publish_crl",
        "validate_chain",
    ):
        assert operation in output

    # A duration column with plausible values, not placeholders.
    durations = re.findall(r"\s(\d+\.\d{4})\s", output)
    assert durations, "no timings were printed"
    assert all(float(value) >= 0.0 for value in durations)


def test_artifacts_are_written_to_the_requested_directory(tmp_path) -> None:
    assert main(["--algorithm", "ml-dsa-44", "--directory", str(tmp_path)]) == 0

    base = tmp_path / "ml-dsa-44"
    assert (base / "root" / "ca.crt").is_file()
    assert (base / "root" / "keys" / "ca.key").is_file()
    assert (base / "intermediate" / "ca.crt").is_file()
    assert (base / "intermediate" / "keys" / "ca.key").is_file()
    assert (base / "leaf.crt").is_file()
    assert (base / "intermediate.crl").is_file()


def test_written_certificates_are_real_pem(tmp_path) -> None:
    """No mocks anywhere: the files must load as certificates."""
    from cryptography import x509

    assert main(["--algorithm", "ml-dsa-44", "--directory", str(tmp_path)]) == 0
    base = tmp_path / "ml-dsa-44"

    leaf = x509.load_pem_x509_certificate((base / "leaf.crt").read_bytes())
    root = x509.load_pem_x509_certificate((base / "root" / "ca.crt").read_bytes())
    intermediate = x509.load_pem_x509_certificate(
        (base / "intermediate" / "ca.crt").read_bytes()
    )
    crl = x509.load_pem_x509_crl((base / "intermediate.crl").read_bytes())

    leaf.verify_directly_issued_by(intermediate)
    intermediate.verify_directly_issued_by(root)
    assert crl.get_revoked_certificate_by_serial_number(leaf.serial_number) is not None


def test_temporary_directory_is_cleaned_up_by_default(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Private keys must not be left lying around unless asked for."""
    import pathlib

    assert main(["--algorithm", "ml-dsa-44"]) == 0
    output = capsys.readouterr().out

    match = re.search(r"Removed (.+?) \(pass --keep", output)
    assert match is not None, output
    assert not pathlib.Path(match.group(1)).exists()


def test_keep_retains_the_directory(capsys: pytest.CaptureFixture[str]) -> None:
    import pathlib
    import shutil

    assert main(["--algorithm", "ml-dsa-44", "--keep"]) == 0
    output = capsys.readouterr().out

    match = re.search(r"Artifacts left in (.+)", output)
    assert match is not None, output
    retained = pathlib.Path(match.group(1).strip())
    try:
        assert retained.is_dir()
        assert (retained / "ml-dsa-44" / "leaf.crt").is_file()
    finally:
        shutil.rmtree(retained, ignore_errors=True)


def test_all_runs_every_algorithm(
    capsys: pytest.CaptureFixture[str], tmp_path
) -> None:
    assert main(["--all", "--directory", str(tmp_path)]) == 0
    output = capsys.readouterr().out

    for name in list_algorithms():
        assert f"pqpki demonstration -- {name}" in output
    assert "Summary" in output
    # Both families must actually have run.
    assert "ecdsa-p256" in output
    assert "ml-dsa-87" in output


def test_unknown_algorithm_is_rejected_by_the_parser() -> None:
    with pytest.raises(SystemExit) as excinfo:
        main(["--algorithm", "ml-dsa-1024"])
    assert excinfo.value.code == 2


def test_help_mentions_the_available_algorithms(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as excinfo:
        main(["--help"])
    assert excinfo.value.code == 0
    output = capsys.readouterr().out
    for name in list_algorithms():
        assert name in output
