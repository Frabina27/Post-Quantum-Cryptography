"""OpenSSL interoperability for the features added after the first six phases.

:mod:`tests.test_interop` covers certificates and complete CRLs. This file
covers what came later: delta CRLs, CRL distribution point extensions, and
passphrase-encrypted private keys. The reason to test these against OpenSSL
rather than only against ``pyca`` is the same as before -- an independent C
implementation with its own ASN.1 parser either accepts what we produced or it
does not, and only the first is evidence of conformance.

The delta CRL tests here found something worth recording. ``openssl verify``
ignores a delta CRL unless two conditions both hold: the ``-use_deltas`` flag
is passed, *and* the complete CRL carries a ``FreshestCRL`` extension linking
it to the delta. Without the linkage OpenSSL loads the delta, does not
associate it with the base, and reports the certificate as good -- silently
missing a revocation. This package puts ``FreshestCRL`` on its complete CRLs
for exactly that reason, and the test below pins the behaviour so that
removing it would fail rather than quietly degrade.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from pqpki import CertificateAuthority, generate_csr, validate_chain
from test_interop import OPENSSL_BANNER, requires_openssl

PEM = serialization.Encoding.PEM

pytestmark = [pytest.mark.interop, requires_openssl]

CRL_URL = "http://crl.pqpki.example/complete.crl"
DELTA_URL = "http://crl.pqpki.example/delta.crl"
PASSPHRASE = "interop passphrase"
BACKLOG = 20


def _openssl(*arguments: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["openssl", *arguments], capture_output=True, text=True, timeout=120
    )


class _Published:
    """A hierarchy written to disk, with its CRLs, ready for ``openssl``."""

    def __init__(self, directory: Path, algorithm: str, *, link_delta: bool) -> None:
        self.directory = directory
        self.ca = CertificateAuthority.create_root(
            "pqpki Interop Root",
            algorithm,
            validity_days=3650,
            crl_url=CRL_URL,
            # Omitting the delta URL is what removes FreshestCRL from both the
            # certificate and the complete CRL, which is the condition the
            # linkage test needs to vary.
            delta_crl_url=DELTA_URL if link_delta else None,
        )
        self.leaf_key = self.ca.algorithm.generate_key()
        self.leaf = self.ca.issue_end_entity(
            generate_csr(
                "pqpki Interop Leaf", self.leaf_key, san_dns=["interop.example"]
            ),
            validity_days=30,
        )

        for serial in range(1, BACKLOG + 1):
            self.ca.revoke(serial, x509.ReasonFlags.superseded)
        self.base = self.ca.publish_crl(validity_days=7)

        self.ca.revoke(self.leaf.serial_number, x509.ReasonFlags.key_compromise)
        self.delta = self.ca.publish_delta_crl(validity_days=1)

        self.root_path = self._write("root.pem", self.ca.certificate)
        self.leaf_path = self._write("leaf.pem", self.leaf)
        self.base_path = self._write("base.crl", self.base)
        self.delta_path = self._write("delta.crl", self.delta)

        # openssl takes one -CRLfile, so a combined file is how both reach it.
        self.both_path = directory / "both.crl"
        self.both_path.write_bytes(
            self.base.public_bytes(PEM) + self.delta.public_bytes(PEM)
        )

    def _write(self, name: str, obj) -> Path:
        path = self.directory / name
        path.write_bytes(obj.public_bytes(PEM))
        return path

    def verify(self, crl_file: Path, *flags: str) -> subprocess.CompletedProcess:
        return _openssl(
            "verify",
            "-crl_check",
            *flags,
            "-CAfile",
            str(self.root_path),
            "-CRLfile",
            str(crl_file),
            str(self.leaf_path),
        )


@pytest.fixture(scope="module")
def published(tmp_path_factory) -> _Published:
    """A post-quantum hierarchy with linked base and delta CRLs."""
    directory = tmp_path_factory.mktemp("interop-delta")
    return _Published(directory, "ml-dsa-65", link_delta=True)


# --------------------------------------------------------------------------
# openssl can parse what we publish
# --------------------------------------------------------------------------


def test_openssl_parses_the_delta_crl(published) -> None:
    result = _openssl("crl", "-in", str(published.delta_path), "-noout", "-text")
    assert result.returncode == 0, result.stderr


def test_openssl_reports_the_delta_crl_indicator(published) -> None:
    result = _openssl("crl", "-in", str(published.delta_path), "-noout", "-text")
    assert "Delta CRL Indicator" in result.stdout


def test_openssl_sees_the_delta_indicator_as_critical(published) -> None:
    """Critical matters: a client that cannot read it must refuse the CRL."""
    result = _openssl("crl", "-in", str(published.delta_path), "-noout", "-text")
    line = next(
        line for line in result.stdout.splitlines() if "Delta CRL Indicator" in line
    )
    assert "critical" in line


def test_openssl_names_the_post_quantum_algorithm_on_the_delta(published) -> None:
    """Not an OID: OpenSSL recognises the algorithm, so the encoding is right."""
    result = _openssl("crl", "-in", str(published.delta_path), "-noout", "-text")
    assert "ML-DSA-65" in result.stdout


def test_openssl_reports_the_crl_distribution_point(published) -> None:
    result = _openssl("x509", "-in", str(published.leaf_path), "-noout", "-text")
    assert "CRL Distribution Points" in result.stdout
    assert CRL_URL in result.stdout


def test_openssl_reports_the_freshest_crl_on_the_certificate(published) -> None:
    result = _openssl("x509", "-in", str(published.leaf_path), "-noout", "-text")
    assert "Freshest CRL" in result.stdout
    assert DELTA_URL in result.stdout


def test_openssl_reports_the_freshest_crl_on_the_complete_crl(published) -> None:
    """The linkage OpenSSL needs in order to apply the delta at all."""
    result = _openssl("crl", "-in", str(published.base_path), "-noout", "-text")
    assert "Freshest CRL" in result.stdout


# --------------------------------------------------------------------------
# openssl and this package agree about what the CRLs mean
# --------------------------------------------------------------------------


def test_both_accept_the_leaf_against_the_base_alone(published) -> None:
    """The base predates the revocation, so neither should reject yet."""
    base_only = published.directory / "base-only.crl"
    base_only.write_bytes(published.base.public_bytes(PEM))

    result = published.verify(base_only, "-use_deltas")
    assert result.returncode == 0, result.stdout + result.stderr

    mine = validate_chain(
        published.leaf, [], [published.ca.certificate], crls=[published.base]
    )
    assert mine.valid, mine.failures


def test_both_reject_the_leaf_given_base_and_delta(published) -> None:
    """The headline agreement: an independent implementation sees the same thing."""
    result = published.verify(published.both_path, "-extended_crl", "-use_deltas")
    assert result.returncode != 0
    assert "revoked" in (result.stdout + result.stderr).lower()

    mine = validate_chain(
        published.leaf,
        [],
        [published.ca.certificate],
        crls=[published.base, published.delta],
    )
    assert not mine.valid
    assert any(f.startswith("revoked:") for f in mine.failures)


def test_both_refuse_a_delta_supplied_without_its_base(published) -> None:
    result = published.verify(published.delta_path, "-use_deltas")
    assert result.returncode != 0

    mine = validate_chain(
        published.leaf, [], [published.ca.certificate], crls=[published.delta]
    )
    assert not mine.valid
    assert any(f.startswith("crl-problem:") for f in mine.failures)


def test_openssl_ignores_a_delta_without_the_use_deltas_flag(published) -> None:
    """Recorded because it is a trap, not because it is our bug.

    Default ``openssl verify -crl_check`` loads the delta and does not apply
    it, so the revoked certificate is reported as good. This package applies
    it. The divergence is OpenSSL's documented opt-in behaviour, and it is the
    reason a deployment relying on delta CRLs has to configure for them
    explicitly.
    """
    result = published.verify(published.both_path)
    assert result.returncode == 0

    mine = validate_chain(
        published.leaf,
        [],
        [published.ca.certificate],
        crls=[published.base, published.delta],
    )
    assert not mine.valid


def test_openssl_needs_the_freshest_crl_linkage_to_apply_a_delta(
    tmp_path,
) -> None:
    """Why FreshestCRL is put on the complete CRL and not only on certificates.

    Same certificates, same revocation, same flags -- the only difference is
    that this CA does not advertise a delta location, so its complete CRL
    carries no FreshestCRL. OpenSSL then cannot associate the delta with the
    base and reports the revoked certificate as good. This package associates
    them by CRLNumber and rejects either way.
    """
    unlinked = _Published(tmp_path, "ecdsa-p256", link_delta=False)

    result = unlinked.verify(unlinked.both_path, "-extended_crl", "-use_deltas")
    assert result.returncode == 0, (
        "OpenSSL unexpectedly applied an unlinked delta CRL; if this now works, "
        "the FreshestCRL-on-the-CRL rationale needs revisiting"
    )

    mine = validate_chain(
        unlinked.leaf,
        [],
        [unlinked.ca.certificate],
        crls=[unlinked.base, unlinked.delta],
    )
    assert not mine.valid
    assert any(f.startswith("revoked:") for f in mine.failures)


# --------------------------------------------------------------------------
# Encrypted private keys
# --------------------------------------------------------------------------


def test_openssl_reads_a_passphrase_encrypted_key(tmp_path, algorithm) -> None:
    """PKCS#8 encryption of an ML-DSA key is newer than that of an RSA key."""
    ca = CertificateAuthority.create_root(
        "pqpki Encrypted Root", algorithm, validity_days=365
    )
    ca.save(tmp_path, passphrase=PASSPHRASE)
    key_path = tmp_path / "keys" / "ca.key"

    result = _openssl(
        "pkey", "-in", str(key_path), "-passin", f"pass:{PASSPHRASE}", "-noout"
    )
    assert result.returncode == 0, result.stderr


def test_openssl_rejects_the_wrong_passphrase(tmp_path) -> None:
    ca = CertificateAuthority.create_root(
        "pqpki Encrypted Root", "ecdsa-p256", validity_days=365
    )
    ca.save(tmp_path, passphrase=PASSPHRASE)

    result = _openssl(
        "pkey",
        "-in",
        str(tmp_path / "keys" / "ca.key"),
        "-passin",
        "pass:not the passphrase",
        "-noout",
    )
    assert result.returncode != 0


def test_the_encrypted_key_file_is_pkcs8(tmp_path) -> None:
    ca = CertificateAuthority.create_root(
        "pqpki Encrypted Root", "ml-dsa-44", validity_days=365
    )
    ca.save(tmp_path, passphrase=PASSPHRASE)
    text = (tmp_path / "keys" / "ca.key").read_text(encoding="ascii")
    assert text.startswith("-----BEGIN ENCRYPTED PRIVATE KEY-----")


def test_openssl_confirms_the_decrypted_key_matches_the_certificate(
    tmp_path,
) -> None:
    """A key that decrypts but belongs to another certificate would be useless."""
    ca = CertificateAuthority.create_root(
        "pqpki Encrypted Root", "ml-dsa-65", validity_days=365
    )
    ca.save(tmp_path, passphrase=PASSPHRASE)

    from_key = _openssl(
        "pkey",
        "-in",
        str(tmp_path / "keys" / "ca.key"),
        "-passin",
        f"pass:{PASSPHRASE}",
        "-pubout",
    )
    from_cert = _openssl(
        "x509", "-in", str(tmp_path / "ca.crt"), "-noout", "-pubkey"
    )
    assert from_key.returncode == 0, from_key.stderr
    assert from_cert.returncode == 0, from_cert.stderr
    assert from_key.stdout.strip() == from_cert.stdout.strip()


def test_openssl_banner_was_detected() -> None:
    """Guards against the whole file silently skipping on a misparse."""
    assert OPENSSL_BANNER.startswith("OpenSSL")
