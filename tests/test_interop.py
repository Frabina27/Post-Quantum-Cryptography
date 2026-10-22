"""Interoperability with the ``openssl`` command-line tool.

The point of these tests is that the certificates this package produces are not
merely parseable by the library that produced them. An independent
implementation -- OpenSSL, written in C, with its own ASN.1 parser and its own
ML-DSA code -- must accept them. That is a much stronger statement than a
round-trip through ``pyca``, and it is the one that matters for a claim about
RFC 9881 conformance.

ML-DSA in X.509 requires OpenSSL 3.5 or newer, so every test here is skipped
when the available ``openssl`` is older or missing. The skip reason names the
version actually found, because "skipped" with no explanation is how a suite
quietly stops testing the thing it was written for.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization

from conftest import Hierarchy

MINIMUM_OPENSSL = (3, 5)


def _detect_openssl() -> tuple[tuple[int, int] | None, str]:
    """Return the detected ``openssl`` version and a description of it."""
    try:
        completed = subprocess.run(
            ["openssl", "version"],
            capture_output=True,
            text=True,
            timeout=15,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return None, f"openssl could not be run ({type(exc).__name__})"

    banner = completed.stdout.strip() or completed.stderr.strip()
    match = re.match(r"OpenSSL\s+(\d+)\.(\d+)", banner)
    if match is None:
        return None, f"could not parse an OpenSSL version from {banner!r}"
    return (int(match.group(1)), int(match.group(2))), banner


OPENSSL_VERSION, OPENSSL_BANNER = _detect_openssl()
HAS_REQUIRED_OPENSSL = (
    OPENSSL_VERSION is not None and OPENSSL_VERSION >= MINIMUM_OPENSSL
)

requires_openssl = pytest.mark.skipif(
    not HAS_REQUIRED_OPENSSL,
    reason=(
        f"needs OpenSSL >= {MINIMUM_OPENSSL[0]}.{MINIMUM_OPENSSL[1]} for ML-DSA "
        f"in X.509; found: {OPENSSL_BANNER}"
    ),
)

pytestmark = [pytest.mark.interop, requires_openssl]


def _write_chain(hierarchy: Hierarchy, directory: Path) -> dict[str, Path]:
    """Write the hierarchy as PEM files and return their paths."""
    paths = {}
    for label, certificate in (
        ("root", hierarchy.root),
        ("intermediate", hierarchy.intermediate),
        ("leaf", hierarchy.leaf),
    ):
        path = directory / f"{label}.pem"
        path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
        paths[label] = path
    return paths


def _openssl(*arguments: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["openssl", *arguments], capture_output=True, text=True, timeout=60
    )


def test_openssl_verifies_the_full_chain(hierarchy: Hierarchy, tmp_path) -> None:
    """The headline interop assertion: exit code 0 from ``openssl verify``."""
    paths = _write_chain(hierarchy, tmp_path)

    result = _openssl(
        "verify",
        "-CAfile",
        str(paths["root"]),
        "-untrusted",
        str(paths["intermediate"]),
        str(paths["leaf"]),
    )

    assert result.returncode == 0, (
        f"openssl rejected a {hierarchy.algorithm} chain.\n"
        f"stdout: {result.stdout}\nstderr: {result.stderr}"
    )
    assert "OK" in result.stdout


def test_openssl_rejects_the_chain_without_the_intermediate(
    hierarchy: Hierarchy, tmp_path
) -> None:
    """Confirms the verify test is not passing for a trivial reason."""
    paths = _write_chain(hierarchy, tmp_path)
    result = _openssl(
        "verify", "-CAfile", str(paths["root"]), str(paths["leaf"])
    )
    assert result.returncode != 0


def test_openssl_rejects_an_untrusted_root(hierarchy: Hierarchy, tmp_path) -> None:
    from conftest import build_hierarchy

    paths = _write_chain(hierarchy, tmp_path)
    stranger = build_hierarchy(hierarchy.algorithm, name_prefix="Interop Stranger")
    stranger_root = tmp_path / "stranger-root.pem"
    stranger_root.write_bytes(
        stranger.root.public_bytes(serialization.Encoding.PEM)
    )

    result = _openssl(
        "verify",
        "-CAfile",
        str(stranger_root),
        "-untrusted",
        str(paths["intermediate"]),
        str(paths["leaf"]),
    )
    assert result.returncode != 0


def test_openssl_names_the_algorithm_we_think_we_used(
    hierarchy: Hierarchy, tmp_path
) -> None:
    """OpenSSL must recognise the signature algorithm, not just tolerate it.

    An unknown OID would print as a dotted string or ``UNDEF``; a recognised
    one prints a name. This is where a wrong OID would surface.
    """
    paths = _write_chain(hierarchy, tmp_path)
    result = _openssl("x509", "-in", str(paths["leaf"]), "-noout", "-text")

    assert result.returncode == 0, result.stderr
    assert "UNDEF" not in result.stdout
    expected = {
        "ecdsa-p256": "ecdsa-with-SHA256",
        "rsa-2048": "sha256WithRSAEncryption",
        "ml-dsa-44": "ML-DSA-44",
        "ml-dsa-65": "ML-DSA-65",
        "ml-dsa-87": "ML-DSA-87",
    }[hierarchy.algorithm]
    assert expected in result.stdout, (
        f"expected {expected!r} in the openssl text dump; got:\n{result.stdout[:2000]}"
    )


def test_openssl_verifies_the_chain_for_server_authentication(
    hierarchy: Hierarchy, tmp_path
) -> None:
    """With an explicit purpose, which exercises the leaf's ExtendedKeyUsage."""
    paths = _write_chain(hierarchy, tmp_path)
    result = _openssl(
        "verify",
        "-purpose",
        "sslserver",
        "-CAfile",
        str(paths["root"]),
        "-untrusted",
        str(paths["intermediate"]),
        str(paths["leaf"]),
    )
    assert result.returncode == 0, f"{result.stdout}\n{result.stderr}"


def test_openssl_parses_our_crl(hierarchy: Hierarchy, tmp_path) -> None:
    """CRLs are signed through the same agility layer, so check them too."""
    crl = hierarchy.intermediate_ca.publish_crl()
    crl_path = tmp_path / "intermediate.crl"
    crl_path.write_bytes(crl.public_bytes(serialization.Encoding.PEM))

    result = _openssl("crl", "-in", str(crl_path), "-noout", "-text")
    assert result.returncode == 0, result.stderr
    assert "UNDEF" not in result.stdout
    assert hierarchy.intermediate.subject.rfc4514_string().split("=")[-1] in result.stdout


def test_openssl_honours_our_crl_when_revoking(
    fresh_hierarchy: Hierarchy, tmp_path
) -> None:
    """An independent implementation must reach the same revocation verdict.

    This is the strongest statement the suite makes about the CRL path: not
    that our own validator rejects a revoked certificate, but that OpenSSL
    does, from the bytes we produced.
    """
    paths = _write_chain(fresh_hierarchy, tmp_path)
    ca = fresh_hierarchy.intermediate_ca

    import cryptography.x509 as x509

    ca.revoke(fresh_hierarchy.leaf.serial_number, x509.ReasonFlags.key_compromise)
    crl = ca.publish_crl()

    # openssl -crl_check wants the CRL alongside the issuing certificate.
    bundle = tmp_path / "bundle.pem"
    bundle.write_bytes(
        fresh_hierarchy.root.public_bytes(serialization.Encoding.PEM)
        + fresh_hierarchy.intermediate.public_bytes(serialization.Encoding.PEM)
        + crl.public_bytes(serialization.Encoding.PEM)
    )

    result = _openssl(
        "verify",
        "-crl_check",
        "-CAfile",
        str(bundle),
        "-untrusted",
        str(paths["intermediate"]),
        str(paths["leaf"]),
    )
    assert result.returncode != 0
    combined = result.stdout + result.stderr
    assert "revoked" in combined.lower(), combined
