"""A self-contained demonstration of the whole package, in one command.

Run it with either of::

    python -m pqpki.cli
    pqpki-demo

It builds a complete hierarchy in a temporary directory, issues an end-entity
certificate, validates the chain, revokes the certificate and validates again
to show the rejection and its named reason, publishes a delta CRL against a
backlog of revocations, and reloads the CA from disk to show that its
revocation state and CRL numbering survived. Every certificate it produces is
real and parseable; you can point ``openssl`` at the files it leaves behind.

The default algorithm is whatever :data:`pqpki.algorithms.DEFAULT_ALGORITHM`
names, which is post-quantum, so the out-of-the-box run is the PQ one. Pass
``--algorithm`` to pick another, or ``--all`` to run the identical demo once
per registered algorithm -- which is the clearest way to see that the classical
and post-quantum paths really are the same code.

This prints the metric events the instrumentation produced, so you can see that
timings and artifact sizes are reachable. It deliberately does not aggregate or
average them: a single run is not a measurement, and
:mod:`pqpki.benchmark` is what turns these events into comparable numbers.
"""

from __future__ import annotations

import argparse
import datetime
import shutil
import sys
import tempfile
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from .algorithms import (
    DEFAULT_ALGORITHM,
    MetricEvent,
    get_algorithm,
    list_algorithms,
)
from .ca import (
    CERT_FILENAME,
    KEY_DIRNAME,
    KEY_FILENAME,
    STATE_FILENAME,
    CertificateAuthority,
)
from .csr import generate_csr
from .revocation import crl_number, delta_base_number
from .validate import ValidationResult, validate_chain

__all__ = ["main"]

LEAF_DNS_NAME = "service.pqpki.example"

#: Advertised in the issued certificates' CRLDistributionPoints and
#: FreshestCRL. Nothing fetches these; they are there so that a certificate
#: says where to look, which is what a real deployment does.
CRL_URL = "http://crl.pqpki.example/intermediate.crl"
DELTA_CRL_URL = "http://crl.pqpki.example/intermediate-delta.crl"

#: Revocations put on the base CRL before the delta is published, so the delta
#: has something to be smaller than. See stage 8.
_BACKLOG = 200

_RULE = "=" * 72
_INDENT = " " * 6


def _say(message: str = "") -> None:
    print(message)


def _detail(message: str) -> None:
    print(f"{_INDENT}{message}")


def _step(number: int, total: int, title: str) -> None:
    print(f"\n[{number}/{total}] {title}")


def _entries(crl) -> str:
    """``"1 entry"`` or ``"201 entries"``, so the output reads correctly."""
    count = len(crl)
    return f"{count} entr{'y' if count == 1 else 'ies'}"


def _der_size(obj) -> int:
    return len(obj.public_bytes(serialization.Encoding.DER))


def _describe(result: ValidationResult) -> None:
    """Print a validation result, including every failure and its code."""
    if result.valid:
        _detail(f"VALID -- chain of {result.chain_length} certificates")
        _detail(f"algorithm at each link: {' <- '.join(result.algorithms_used)}")
        return

    _detail(f"INVALID -- {len(result.failures)} failure(s):")
    for failure in result.failures:
        code, _, detail = failure.partition(": ")
        _detail(f"  [{code}]")
        _detail(f"    {detail}")


def run_demo(algorithm: str, directory: Path) -> bool:
    """Run the full demonstration for one algorithm.

    Args:
        algorithm: A name from :func:`~pqpki.algorithms.list_algorithms`.
        directory: Where to write certificates and keys. Created if absent.

    Returns:
        True if every stage behaved as the demonstration expects. The chain
        must validate before revocation and must be rejected after it; either
        outcome being wrong means the package is broken, so this is checked
        rather than assumed.
    """
    spec = get_algorithm(algorithm)
    events: list[MetricEvent] = []
    collect = events.append
    total = 9

    _say()
    _say(_RULE)
    _say(f"pqpki demonstration -- {spec.name}")
    _say(_RULE)
    _detail(
        f"{'post-quantum' if spec.is_post_quantum else 'classical'}, "
        f"signature OID {spec.oid}"
    )
    _detail(f"working directory: {directory}")

    # -- 1. the root ------------------------------------------------------
    _step(1, total, "Creating a self-signed root CA")
    root_ca = CertificateAuthority.create_root(
        "pqpki Demo Root",
        algorithm,
        validity_days=3650,
        path_length=1,
        collector=collect,
        crl_url=CRL_URL,
        delta_crl_url=DELTA_CRL_URL,
    )
    root = root_ca.certificate
    _detail(f"subject:     {root.subject.rfc4514_string()}")
    _detail(f"serial:      {root.serial_number:x}")
    _detail(f"certificate: {_der_size(root)} bytes DER")
    _detail(f"valid until: {root.not_valid_after_utc.date()}")
    _detail(f"issued certs will point to {CRL_URL}")

    # -- 2. the intermediate ----------------------------------------------
    _step(2, total, "Issuing an intermediate CA from a CSR")
    intermediate_key = spec.generate_key(collector=collect)
    intermediate_csr = generate_csr("pqpki Demo Intermediate", intermediate_key)
    _detail("CSR proof of possession verified before signing")
    intermediate_cert = root_ca.issue_intermediate(
        intermediate_csr, validity_days=1825, path_length=0
    )
    intermediate_ca = CertificateAuthority(
        intermediate_cert,
        intermediate_key,
        collector=collect,
        crl_url=CRL_URL,
        delta_crl_url=DELTA_CRL_URL,
    )
    _detail(f"subject:     {intermediate_cert.subject.rfc4514_string()}")
    _detail(f"certificate: {_der_size(intermediate_cert)} bytes DER")
    _detail("path length: 0 -- may issue end entities but no further CAs")

    # -- 3. the leaf ------------------------------------------------------
    _step(3, total, "Issuing an end-entity certificate")
    leaf_key = spec.generate_key(collector=collect)
    leaf_csr = generate_csr(
        "pqpki Demo Leaf", leaf_key, san_dns=[LEAF_DNS_NAME]
    )
    leaf = intermediate_ca.issue_end_entity(leaf_csr, validity_days=90)
    _detail(f"subject:     {leaf.subject.rfc4514_string()}")
    _detail(f"SAN:         {LEAF_DNS_NAME}")
    _detail(f"serial:      {leaf.serial_number:x}")
    _detail(f"certificate: {_der_size(leaf)} bytes DER")
    distribution = leaf.extensions.get_extension_for_class(
        x509.CRLDistributionPoints
    ).value
    _detail(f"CRL at:      {distribution[0].full_name[0].value}")

    # -- 4. persist -------------------------------------------------------
    _step(4, total, "Writing the hierarchy to disk")
    root_directory = directory / "root"
    intermediate_directory = directory / "intermediate"
    root_ca.save(root_directory)
    intermediate_ca.save(intermediate_directory)
    leaf_path = directory / "leaf.crt"
    leaf_path.write_bytes(leaf.public_bytes(serialization.Encoding.PEM))

    for path in (
        root_directory / CERT_FILENAME,
        root_directory / KEY_DIRNAME / KEY_FILENAME,
        root_directory / STATE_FILENAME,
        intermediate_directory / CERT_FILENAME,
        intermediate_directory / KEY_DIRNAME / KEY_FILENAME,
        intermediate_directory / STATE_FILENAME,
        leaf_path,
    ):
        _detail(f"{path.relative_to(directory)}")
    _detail("private keys are in keys/ with mode 0600 (advisory on Windows)")
    _detail("ca-state.json carries the revocation register and CRL counter")

    # -- 5. validate ------------------------------------------------------
    _step(5, total, "Validating the chain")
    before = validate_chain(
        leaf, [intermediate_cert], [root], collector=collect
    )
    _describe(before)

    # -- 6. revoke --------------------------------------------------------
    _step(6, total, "Revoking the end-entity certificate")
    intermediate_ca.revoke(leaf.serial_number, x509.ReasonFlags.key_compromise)
    crl = intermediate_ca.publish_crl(validity_days=7)
    crl_path = directory / "intermediate.crl"
    crl_path.write_bytes(crl.public_bytes(serialization.Encoding.PEM))
    _detail("reason:   keyCompromise")
    _detail(f"CRL:      {_der_size(crl)} bytes DER, {_entries(crl)}")
    _detail(f"signed with {spec.name}, same agility layer as a certificate")
    _detail(f"written:  {crl_path.relative_to(directory)}")

    # -- 7. re-validate ---------------------------------------------------
    _step(7, total, "Re-validating, now with the CRL supplied")
    after = validate_chain(
        leaf,
        [intermediate_cert],
        [root],
        crls=[crl],
        collector=collect,
    )
    _describe(after)

    # -- 8. delta CRL -----------------------------------------------------
    _step(8, total, "Publishing a delta CRL")
    # Give the base CRL a realistic backlog first. A delta against an empty
    # base is larger than the base, so demonstrating one without a backlog
    # would show the opposite of the point.
    for serial in range(1, _BACKLOG + 1):
        intermediate_ca.revoke(serial, x509.ReasonFlags.superseded)
    base_crl = intermediate_ca.publish_crl(validity_days=7)

    intermediate_ca.revoke(_BACKLOG + 1, x509.ReasonFlags.cessation_of_operation)
    delta_crl = intermediate_ca.publish_delta_crl(validity_days=1)
    delta_path = directory / "intermediate-delta.crl"
    delta_path.write_bytes(delta_crl.public_bytes(serialization.Encoding.PEM))

    base_size = _der_size(base_crl)
    delta_size = _der_size(delta_crl)
    _detail(f"base CRL:  {_entries(base_crl)}, {base_size} bytes DER")
    _detail(f"delta CRL: {_entries(delta_crl)}, {delta_size} bytes DER")
    _detail(f"saving:    {100 * (1 - delta_size / base_size):.1f}% smaller")
    _detail(f"relative to base CRL number {delta_base_number(delta_crl)} (critical)")
    _detail(f"written:   {delta_path.relative_to(directory)}")

    delta_alone = validate_chain(
        leaf, [intermediate_cert], [root], crls=[delta_crl]
    )
    _detail("a delta supplied without its base is refused, not believed:")
    for failure in delta_alone.failures:
        if failure.startswith("crl-problem:"):
            _detail(f"  {failure[:96]}")
            break

    # -- 9. reload --------------------------------------------------------
    _step(9, total, "Reloading the intermediate CA from disk")
    intermediate_ca.save(intermediate_directory)
    reloaded = CertificateAuthority.load(
        intermediate_directory / CERT_FILENAME,
        intermediate_directory / KEY_DIRNAME / KEY_FILENAME,
    )
    _detail(f"revocations restored: {len(reloaded.revoked_serials)}")
    _detail(f"CRL number continues from: {reloaded.crl_number}")
    republished = reloaded.publish_crl(validity_days=7)
    still_revoked = (
        republished.get_revoked_certificate_by_serial_number(leaf.serial_number)
        is not None
    )
    _detail(
        f"republished CRL number {crl_number(republished)}, "
        f"leaf still revoked: {still_revoked}"
    )
    _detail("numbering never goes backwards, so no CRL looks like a replay")

    # -- instrumentation --------------------------------------------------
    _say("\n  Metric events the collector received:")
    _say(f"  {'operation':<20} {'algorithm':<12} {'seconds':>9}  {'bytes':>7}")
    _say(f"  {'-' * 20} {'-' * 12} {'-' * 9}  {'-' * 7}")
    for event in events:
        size = "-" if event.artifact_bytes is None else str(event.artifact_bytes)
        _say(
            f"  {event.operation:<20} {event.algorithm:<12} "
            f"{event.duration_s:>9.4f}  {size:>7}"
        )
    _say(
        "\n  These are single measurements, not a benchmark: one run on a "
        "loaded machine\n  says little. Run `python -m pqpki.benchmark` to "
        "aggregate them over\n  repetitions and across every algorithm."
    )

    # -- did the demonstration actually demonstrate anything? -------------
    expectations_held = True
    if not before.valid:
        _say("\n  UNEXPECTED: the chain failed to validate before revocation.")
        expectations_held = False
    if after.valid:
        _say("\n  UNEXPECTED: the chain still validated after revocation.")
        expectations_held = False
    elif not any(f.startswith("revoked:") for f in after.failures):
        _say("\n  UNEXPECTED: rejected after revocation, but not for revocation.")
        expectations_held = False

    if expectations_held:
        _say(
            f"\n  Result: valid before revocation, rejected afterwards with the "
            f"named\n  reason -- {spec.name} through the same code path every "
            f"other algorithm uses."
        )
    return expectations_held


def main(argv: list[str] | None = None) -> int:
    """Entry point. Returns a process exit status."""
    parser = argparse.ArgumentParser(
        prog="pqpki-demo",
        description=(
            "Build a certificate hierarchy, validate it, revoke a certificate, "
            "and validate again to show the rejection."
        ),
        epilog=(
            "Every certificate produced is a real X.509 certificate. Use --keep "
            "to leave the files in place and inspect them with openssl."
        ),
    )
    parser.add_argument(
        "-a",
        "--algorithm",
        default=DEFAULT_ALGORITHM,
        choices=list_algorithms(),
        help="signature algorithm for the whole hierarchy (default: %(default)s)",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="run the identical demonstration once per registered algorithm",
    )
    parser.add_argument(
        "-d",
        "--directory",
        type=Path,
        default=None,
        help="where to write artifacts (default: a temporary directory)",
    )
    parser.add_argument(
        "--keep",
        action="store_true",
        help="do not delete the working directory on exit",
    )
    arguments = parser.parse_args(argv)

    algorithms = list_algorithms() if arguments.all else [arguments.algorithm]

    if arguments.directory is not None:
        base = arguments.directory
        base.mkdir(parents=True, exist_ok=True)
        temporary = False
    else:
        base = Path(tempfile.mkdtemp(prefix="pqpki-demo-"))
        temporary = True

    try:
        results = {
            algorithm: run_demo(algorithm, base / algorithm)
            for algorithm in algorithms
        }

        _say()
        _say(_RULE)
        if len(results) > 1:
            _say("Summary")
            for algorithm, ok in results.items():
                _say(f"  {algorithm:<12} {'ok' if ok else 'FAILED'}")
        failed = [name for name, ok in results.items() if not ok]
        if failed:
            _say(f"FAILED: {', '.join(failed)}")
            return 1
        _say("All stages behaved as expected.")
        return 0
    finally:
        if temporary and not arguments.keep:
            shutil.rmtree(base, ignore_errors=True)
            _say(f"\nRemoved {base} (pass --keep to retain it).")
        else:
            _say(f"\nArtifacts left in {base}")
            _say("Inspect them with, for example:")
            first = next(iter(algorithms))
            _say(
                f"  openssl verify -CAfile {base / first / 'root' / 'ca.crt'} "
                f"\\\n    -untrusted {base / first / 'intermediate' / 'ca.crt'} "
                f"\\\n    {base / first / 'leaf.crt'}"
            )


if __name__ == "__main__":
    sys.exit(main())
