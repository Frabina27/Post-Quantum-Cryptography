"""The certificate authority: a signing key, its certificate, and the power to
issue subordinate certificates and revoke them.

One class, :class:`CertificateAuthority`, serves as both root and intermediate.
The difference between them is not a type but a fact about a certificate: a
root's issuer equals its subject, an intermediate's does not. Both sign the same
way, so both are the same object.

Nothing here names an algorithm. Every signing call goes through
``spec.sign_args()``, so this module is identical for classical and
post-quantum hierarchies. That is deliberate and it is tested: an architectural
test parses this module's AST and fails if an algorithm name, curve, key size,
or OID appears in it.

This is a teaching implementation -- see :mod:`pqpki` for what it deliberately
does not do. Two things are worth repeating here, where the temptation to
misread them is highest:

* **The private key lives in process memory** and is written unencrypted to
  disk by :meth:`CertificateAuthority.save`. A real CA keeps its key in an HSM
  and its root offline.
* **Revocation state is in memory only.** It lives as long as the
  :class:`CertificateAuthority` instance and is not written by
  :meth:`~CertificateAuthority.save`. A CA reloaded with
  :meth:`~CertificateAuthority.load` has an empty revocation register. A real
  CA has a durable issuance and revocation database, which is also how it knows
  whether a serial it is asked to revoke was ever one of its own.
"""

from __future__ import annotations

import datetime
import os
import time
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.types import (
    CertificateIssuerPrivateKeyTypes,
)
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from .algorithms import AlgorithmSpec, Collector, _emit, get_algorithm, spec_for_key
from .csr import verify_csr_signature
from .errors import CAStateError, IssuanceError

__all__ = ["CertificateAuthority"]

#: Filenames used by :meth:`CertificateAuthority.save` and expected by
#: :meth:`CertificateAuthority.load`. One CA per directory.
CERT_FILENAME = "ca.crt"
KEY_DIRNAME = "keys"
KEY_FILENAME = "ca.key"

#: Mode for private key files. POSIX only in practice; see the note in
#: :meth:`CertificateAuthority.save`.
KEY_FILE_MODE = 0o600


def _utcnow() -> datetime.datetime:
    """Current UTC time, truncated to whole seconds.

    X.509 encodes times at one-second granularity, so a certificate's
    ``notBefore`` would be truncated anyway. Truncating up front means the
    stored value is never *later* than the moment we generated it, which would
    otherwise make a certificate briefly not-yet-valid at the instant of
    issuance.
    """
    return datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)


def _authority_key_identifier(issuer: x509.Certificate) -> x509.AuthorityKeyIdentifier:
    """Build an AKI pointing at ``issuer``.

    Derived from the issuer's own SubjectKeyIdentifier when it has one, so the
    two extensions agree byte for byte and a path builder can match child to
    parent by keyid. Falls back to hashing the issuer's public key for a
    certificate issued by something that omitted its SKI.
    """
    try:
        ski = issuer.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
    except x509.ExtensionNotFound:
        return x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer.public_key())
    return x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ski.value)


def _subject_name(common_name: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])


class CertificateAuthority:
    """A CA that can issue subordinate certificates and publish CRLs.

    Construct one with :meth:`create_root` or :meth:`load` rather than calling
    the initializer, unless you are assembling an intermediate CA from a
    certificate you just had issued -- which is exactly what the initializer is
    for::

        root = CertificateAuthority.create_root("Root", "ml-dsa-65")
        sub_key = root.algorithm.generate_key()
        sub_csr = generate_csr("Intermediate", sub_key)
        sub_cert = root.issue_intermediate(sub_csr, validity_days=1825)
        sub_ca = CertificateAuthority(sub_cert, sub_key)
    """

    def __init__(
        self,
        certificate: x509.Certificate,
        private_key: CertificateIssuerPrivateKeyTypes,
        *,
        collector: Collector | None = None,
    ) -> None:
        """Wrap an existing certificate and its matching private key.

        Args:
            certificate: The CA's own certificate. Must assert
                ``BasicConstraints`` CA=TRUE.
            private_key: The private key matching ``certificate``'s public key.
            collector: Optional sink for :class:`~pqpki.algorithms.MetricEvent`
                timings and artifact sizes, keyword-only. Events are emitted
                for ``issue_intermediate``, ``issue_end_entity``, and
                ``publish_crl``. Nothing is aggregated here; a teammate owns
                the benchmarking harness.

        Raises:
            CAStateError: If the key does not match the certificate, or the
                certificate is not a CA certificate.
        """
        self._certificate = certificate
        self._private_key = private_key
        self._collector = collector

        # An in-memory revocation register: serial -> (revoked_at, reason).
        self._revoked: dict[int, tuple[datetime.datetime, x509.ReasonFlags]] = {}
        # CRLs must carry a monotonically increasing CRLNumber so a relying
        # party can tell a newer CRL from a replayed older one.
        self._crl_number = 0

        self._check_key_matches_certificate()
        self._check_is_ca_certificate()

    # -- construction ------------------------------------------------------

    @classmethod
    def create_root(
        cls,
        common_name: str,
        algorithm: str,
        validity_days: int = 3650,
        *,
        path_length: int | None = None,
        collector: Collector | None = None,
    ) -> "CertificateAuthority":
        """Generate a key and a self-signed root certificate for it.

        Args:
            common_name: Subject (and, being self-signed, issuer) common name.
            algorithm: A name from
                :func:`pqpki.algorithms.list_algorithms`. This is the only
                place in a whole hierarchy where the algorithm is chosen.
            validity_days: Lifetime. Roots are long-lived because replacing one
                means redistributing it to every relying party.
            path_length: ``BasicConstraints`` path length. ``None``, the
                default, means unconstrained, which is what real roots
                normally do -- depth is then limited by the intermediates,
                which default to issuing leaves only.
            collector: Optional metric sink, also used to time key generation.

        Raises:
            UnknownAlgorithmError: If ``algorithm`` is not registered.
        """
        spec = get_algorithm(algorithm)
        private_key = spec.generate_key(collector=collector)

        name = _subject_name(common_name)
        now = _utcnow()
        public_key = private_key.public_key()

        certificate = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)  # self-signed: issuer is its own subject
            .public_key(public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=validity_days))
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=path_length),
                critical=True,
            )
            .add_extension(_ca_key_usage(), critical=True)
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False
            )
            # No AuthorityKeyIdentifier: this certificate is self-signed, so an
            # AKI would just point at itself.
            .sign(private_key, *spec.sign_args())
        )

        return cls(certificate, private_key, collector=collector)

    @classmethod
    def load(
        cls,
        cert_path: Path,
        key_path: Path,
        *,
        collector: Collector | None = None,
    ) -> "CertificateAuthority":
        """Load a CA from a PEM certificate and a PEM private key.

        The loaded CA starts with an **empty revocation register**, because
        :meth:`save` does not persist one. Revoking and republishing a CRL
        after a reload will produce a CRL that has forgotten every earlier
        revocation. A real CA keeps that state in a database; this one does
        not, and pretending otherwise would be worse than saying so.

        Raises:
            CAStateError: If either file cannot be parsed, the key does not
                match the certificate, or the certificate is not a CA.
        """
        try:
            certificate = x509.load_pem_x509_certificate(Path(cert_path).read_bytes())
        except Exception as exc:
            raise CAStateError(f"could not load CA certificate from {cert_path}: {exc}") from exc

        try:
            private_key = serialization.load_pem_private_key(
                Path(key_path).read_bytes(), password=None
            )
        except Exception as exc:
            raise CAStateError(f"could not load CA private key from {key_path}: {exc}") from exc

        return cls(certificate, private_key, collector=collector)  # type: ignore[arg-type]

    # -- invariants --------------------------------------------------------

    def _check_key_matches_certificate(self) -> None:
        """Refuse a key that does not match the certificate.

        Caught here rather than at first use, where it would surface as an
        unverifiable signature on an already-issued certificate.
        """
        spki = serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        from_key = self._private_key.public_key().public_bytes(*spki)
        from_cert = self._certificate.public_key().public_bytes(*spki)
        if from_key != from_cert:
            raise CAStateError(
                "private key does not match the CA certificate public key; "
                "the certificate and key files do not belong together"
            )

    def _check_is_ca_certificate(self) -> None:
        """Refuse to act as a CA without BasicConstraints CA=TRUE."""
        try:
            basic = self._certificate.extensions.get_extension_for_class(
                x509.BasicConstraints
            ).value
        except x509.ExtensionNotFound:
            raise CAStateError(
                "CA certificate has no BasicConstraints extension, so it does "
                "not assert the right to issue certificates"
            ) from None
        if not basic.ca:
            raise CAStateError(
                "CA certificate asserts BasicConstraints CA=FALSE; it is an end-"
                "entity certificate and must not be used to issue"
            )

    @property
    def _basic_constraints(self) -> x509.BasicConstraints:
        return self._certificate.extensions.get_extension_for_class(
            x509.BasicConstraints
        ).value

    # -- properties --------------------------------------------------------

    @property
    def certificate(self) -> x509.Certificate:
        """This CA's own certificate."""
        return self._certificate

    @property
    def algorithm(self) -> AlgorithmSpec:
        """The algorithm this CA signs with, resolved from its private key."""
        return spec_for_key(self._private_key)

    @property
    def private_key(self) -> CertificateIssuerPrivateKeyTypes:
        """This CA's signing key.

        Exposed because building an intermediate CA object requires the key
        that was generated for it. Handling it at all is a property of this
        being a teaching implementation.
        """
        return self._private_key

    # -- issuance ----------------------------------------------------------

    def _start_certificate(
        self, csr: x509.CertificateSigningRequest, validity_days: int
    ) -> x509.CertificateBuilder:
        """Common skeleton for any certificate this CA issues.

        Verifies proof of possession first: a CSR whose self-signature does not
        verify proves nothing about who holds the key, and signing it would
        let an attacker have a CA bind someone else's public key to a name.
        """
        if not verify_csr_signature(csr):
            raise IssuanceError(
                "CSR signature does not verify: the requester has not proven "
                "possession of the private key, so the request must not be signed"
            )

        now = _utcnow()
        return (
            x509.CertificateBuilder()
            .subject_name(csr.subject)
            .issuer_name(self._certificate.subject)
            .public_key(csr.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=validity_days))
        )

    def _sign(
        self, builder: x509.CertificateBuilder, operation: str
    ) -> x509.Certificate:
        """Sign ``builder`` with this CA's key, timing the operation."""
        spec = self.algorithm
        started = time.perf_counter()
        certificate = builder.sign(self._private_key, *spec.sign_args())
        elapsed = time.perf_counter() - started
        _emit(
            self._collector,
            operation,
            spec.name,
            elapsed,
            len(certificate.public_bytes(serialization.Encoding.DER)),
        )
        return certificate

    def issue_intermediate(
        self,
        csr: x509.CertificateSigningRequest,
        validity_days: int,
        path_length: int = 0,
    ) -> x509.Certificate:
        """Issue a subordinate CA certificate from ``csr``.

        Args:
            csr: The intermediate's request. Its proof of possession is
                verified before anything is signed.
            validity_days: Lifetime. Conventionally shorter than the root's.
            path_length: ``BasicConstraints`` path length for the new CA. The
                default of ``0`` means the intermediate may issue end entities
                but no further CAs, which is the usual shape and the safe one.

        Raises:
            IssuanceError: If proof of possession fails, or if this CA's own
                path-length constraint cannot accommodate the request.
        """
        if path_length < 0:
            raise IssuanceError(f"path_length must be non-negative, got {path_length}")

        own_path_length = self._basic_constraints.path_length
        if own_path_length is not None:
            if own_path_length == 0:
                raise IssuanceError(
                    "this CA has a BasicConstraints path length of 0, so it may "
                    "issue end-entity certificates but no subordinate CAs"
                )
            if path_length >= own_path_length:
                raise IssuanceError(
                    f"requested path_length {path_length} is not permitted: this "
                    f"CA has path length {own_path_length}, so a subordinate CA "
                    f"may have at most {own_path_length - 1}"
                )

        subject_public_key = csr.public_key()
        builder = (
            self._start_certificate(csr, validity_days)
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=path_length), critical=True
            )
            .add_extension(_ca_key_usage(), critical=True)
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(subject_public_key),
                critical=False,
            )
            .add_extension(
                _authority_key_identifier(self._certificate), critical=False
            )
        )
        return self._sign(builder, "issue_intermediate")

    def issue_end_entity(
        self,
        csr: x509.CertificateSigningRequest,
        validity_days: int,
        san_dns: list[str] | None = None,
    ) -> x509.Certificate:
        """Issue an end-entity (leaf) certificate from ``csr``.

        Args:
            csr: The subject's request, proof of possession verified first.
            validity_days: Lifetime. Leaves are short-lived, because
                revocation is unreliable and expiry is not.
            san_dns: DNS names for the ``SubjectAlternativeName``. When
                omitted, the names requested in the CSR are used. The CA
                decides this, which is why an explicit argument overrides
                whatever the CSR asked for.

        Raises:
            IssuanceError: If proof of possession fails, or if no SAN names are
                available from either the argument or the CSR.
        """
        names = san_dns if san_dns is not None else _requested_dns_names(csr)
        if not names:
            raise IssuanceError(
                "no SubjectAlternativeName DNS names supplied by argument or "
                "requested in the CSR. Name validation reads the SAN, not the "
                "common name, so a leaf without one identifies nothing"
            )

        subject_public_key = csr.public_key()
        builder = (
            self._start_certificate(csr, validity_days)
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None), critical=True
            )
            .add_extension(_leaf_key_usage(), critical=True)
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName(n) for n in names]),
                critical=False,
            )
            # Not required by the module contract, but both the pyca server
            # verifier and `openssl verify -purpose sslserver` require a leaf
            # to say what it is for. Without it the cross-checks cannot run.
            .add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
                critical=False,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(subject_public_key),
                critical=False,
            )
            .add_extension(
                _authority_key_identifier(self._certificate), critical=False
            )
        )
        return self._sign(builder, "issue_end_entity")

    # -- revocation --------------------------------------------------------

    def revoke(self, serial_number: int, reason: x509.ReasonFlags) -> None:
        """Add ``serial_number`` to this CA's revocation register.

        Takes effect on the next :meth:`publish_crl`. Revoking a serial twice
        keeps the first revocation date, since that is when the certificate
        actually stopped being trustworthy.

        No check is made that this CA issued ``serial_number``: that would need
        an issuance database, which this implementation does not have. A real
        CA would reject an unknown serial rather than publishing a revocation
        for a certificate it never issued.
        """
        if serial_number in self._revoked:
            return
        self._revoked[serial_number] = (_utcnow(), reason)

    @property
    def revoked_serials(self) -> dict[int, tuple[datetime.datetime, x509.ReasonFlags]]:
        """A copy of the in-memory revocation register."""
        return dict(self._revoked)

    def publish_crl(
        self, validity_days: int = 7
    ) -> x509.CertificateRevocationList:
        """Sign and return a CRL covering everything revoked so far.

        Args:
            validity_days: How long until ``nextUpdate``. A relying party that
                sees a CRL past its ``nextUpdate`` should treat revocation
                status as unknown rather than assuming nothing was revoked.

        The CRL is signed with this CA's key through the same agility layer as
        a certificate, so a post-quantum CA publishes an ML-DSA-signed CRL with
        no extra code.
        """
        spec = self.algorithm
        now = _utcnow()
        self._crl_number += 1

        builder = (
            x509.CertificateRevocationListBuilder()
            .issuer_name(self._certificate.subject)
            .last_update(now)
            .next_update(now + datetime.timedelta(days=validity_days))
            .add_extension(x509.CRLNumber(self._crl_number), critical=False)
            .add_extension(_authority_key_identifier(self._certificate), critical=False)
        )

        for serial, (revoked_at, reason) in sorted(self._revoked.items()):
            entry = (
                x509.RevokedCertificateBuilder()
                .serial_number(serial)
                .revocation_date(revoked_at)
                .add_extension(x509.CRLReason(reason), critical=False)
                .build()
            )
            builder = builder.add_revoked_certificate(entry)

        started = time.perf_counter()
        crl = builder.sign(self._private_key, *spec.sign_args())
        elapsed = time.perf_counter() - started
        _emit(
            self._collector,
            "publish_crl",
            spec.name,
            elapsed,
            len(crl.public_bytes(serialization.Encoding.DER)),
        )
        return crl

    # -- persistence -------------------------------------------------------

    def save(self, directory: Path) -> None:
        """Write the certificate and private key under ``directory``.

        Layout, matching what :meth:`load` expects::

            directory/ca.crt        PEM certificate
            directory/keys/ca.key   PEM PKCS#8 private key, mode 0600

        One CA per directory; the filenames are fixed, so saving two CAs to the
        same directory overwrites the first.

        The key is written **unencrypted**, and the ``0600`` mode is only
        meaningful on POSIX. On Windows the POSIX permission bits do not map
        onto ACLs, so :func:`os.chmod` succeeds without actually restricting
        anything. Neither is acceptable for a real CA key, and both are here
        because this is a teaching implementation.

        Revocation state is not saved; see :meth:`load`.
        """
        directory = Path(directory)
        key_directory = directory / KEY_DIRNAME
        directory.mkdir(parents=True, exist_ok=True)
        key_directory.mkdir(parents=True, exist_ok=True)

        (directory / CERT_FILENAME).write_bytes(
            self._certificate.public_bytes(serialization.Encoding.PEM)
        )

        key_path = key_directory / KEY_FILENAME
        key_path.write_bytes(
            self._private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
        os.chmod(key_path, KEY_FILE_MODE)


def _ca_key_usage() -> x509.KeyUsage:
    """KeyUsage for a CA: sign certificates and sign CRLs, nothing else."""
    return x509.KeyUsage(
        digital_signature=False,
        content_commitment=False,
        key_encipherment=False,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=True,
        crl_sign=True,
        encipher_only=False,
        decipher_only=False,
    )


def _leaf_key_usage() -> x509.KeyUsage:
    """KeyUsage for an end entity: sign, and specifically not sign certificates."""
    return x509.KeyUsage(
        digital_signature=True,
        content_commitment=False,
        key_encipherment=False,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=False,
        crl_sign=False,
        encipher_only=False,
        decipher_only=False,
    )


def _requested_dns_names(csr: x509.CertificateSigningRequest) -> list[str]:
    """DNS names a CSR asked for, or an empty list if it asked for none."""
    try:
        san = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    except x509.ExtensionNotFound:
        return []
    return list(san.value.get_values_for_type(x509.DNSName))
