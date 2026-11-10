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

* **The private key lives in process memory.**
  :meth:`CertificateAuthority.save` will encrypt it under a passphrase if you
  pass one, which is better than nothing and still not an HSM: the decrypted
  key sits in this process's address space for as long as the CA is in use. A
  real CA keeps its key in hardware that will not export it, and its root
  offline.
* **Revocation state persists, in a file anyone can edit.**
  :meth:`~CertificateAuthority.save` writes the revocation register and the
  current CRL number to a plain JSON document beside the certificate, so a CA
  reloaded by :meth:`~CertificateAuthority.load` neither forgets its
  revocations nor restarts CRL numbering. Nothing authenticates that file, so
  whoever can write it can silently un-revoke a certificate. A real CA keeps
  this in an access-controlled, audited database -- which is also how it knows
  whether a serial it is asked to revoke was ever one of its own.
"""

from __future__ import annotations

import datetime
import json
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

#: Where :meth:`CertificateAuthority.save` persists the revocation register and
#: CRL counter. Sits beside the certificate, not in ``keys/``: it holds no
#: secrets, and a relying party may legitimately want to read it.
STATE_FILENAME = "ca-state.json"

#: Version tag on the state file, so a future format change can be detected
#: rather than silently misparsed.
STATE_VERSION = 1

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


def _distribution_point(url: str) -> x509.DistributionPoint:
    """A DistributionPoint naming ``url`` and nothing else.

    ``relative_name``, ``crl_issuer`` and ``reasons`` are all left absent on
    purpose. A distribution point that names a ``crl_issuer`` is saying the CRL
    comes from a *different* authority than the certificate's issuer -- an
    indirect CRL -- and a ``reasons`` field partitions revocation reasons
    across several CRLs. This package issues one complete CRL per CA covering
    every reason, so claiming either would be a lie about the deployment.
    """
    return x509.DistributionPoint(
        full_name=[x509.UniformResourceIdentifier(url)],
        relative_name=None,
        crl_issuer=None,
        reasons=None,
    )


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
        crl_url: str | None = None,
        delta_crl_url: str | None = None,
    ) -> None:
        """Wrap an existing certificate and its matching private key.

        Args:
            certificate: The CA's own certificate. Must assert
                ``BasicConstraints`` CA=TRUE.
            private_key: The private key matching ``certificate``'s public key.
            collector: Optional sink for :class:`~pqpki.algorithms.MetricEvent`
                timings and artifact sizes, keyword-only. Events are emitted
                for ``issue_intermediate``, ``issue_end_entity``,
                ``publish_crl`` and ``publish_delta_crl``.
            crl_url: Where this CA publishes its complete CRL. When given,
                every certificate issued from here carries a
                ``CRLDistributionPoints`` extension naming it, which is how a
                relying party that was handed only a certificate finds out
                where to ask about revocation.
            delta_crl_url: Where this CA publishes delta CRLs. When given,
                issued certificates and complete CRLs carry a ``FreshestCRL``
                extension naming it. Independent of ``crl_url``, though
                advertising deltas without a base to apply them to is not
                useful.

        Raises:
            CAStateError: If the key does not match the certificate, or the
                certificate is not a CA certificate.
        """
        self._certificate = certificate
        self._private_key = private_key
        self._collector = collector
        self._crl_url = crl_url
        self._delta_crl_url = delta_crl_url

        # The revocation register: serial -> (revoked_at, reason). Persisted by
        # `save` and restored by `load`.
        self._revoked: dict[int, tuple[datetime.datetime, x509.ReasonFlags]] = {}
        # CRLs must carry a monotonically increasing CRLNumber so a relying
        # party can tell a newer CRL from a replayed older one. This counter is
        # shared between complete and delta CRLs, because RFC 5280 draws them
        # from one sequence.
        self._crl_number = 0
        # The CRLNumber of the most recent complete CRL, and the serials it
        # carried. A delta CRL is defined relative to a specific base, and
        # lists what changed since it; without remembering the base there is
        # nothing to be relative to.
        self._base_crl_number: int | None = None
        self._base_revoked_serials: frozenset[int] = frozenset()

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
        crl_url: str | None = None,
        delta_crl_url: str | None = None,
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
            crl_url: CRL distribution point for certificates this root issues.
                The root's own certificate does not carry one: it is a trust
                anchor, and nothing above it could revoke it.
            delta_crl_url: Freshest-CRL location for certificates this root
                issues.

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

        return cls(
            certificate,
            private_key,
            collector=collector,
            crl_url=crl_url,
            delta_crl_url=delta_crl_url,
        )

    @classmethod
    def load(
        cls,
        cert_path: Path,
        key_path: Path,
        *,
        collector: Collector | None = None,
        passphrase: bytes | str | None = None,
        state_path: Path | None = None,
        crl_url: str | None = None,
        delta_crl_url: str | None = None,
    ) -> "CertificateAuthority":
        """Load a CA from a PEM certificate and a PEM private key.

        Revocation state is restored when a state file is found, so a reloaded
        CA remembers what it revoked and continues its CRL numbering instead of
        restarting at 1. A republished CRL that went backwards in CRLNumber
        would look to a relying party exactly like a replay of an old one.

        Args:
            cert_path: PEM certificate, as written by :meth:`save`.
            key_path: PEM PKCS#8 private key, as written by :meth:`save`.
            collector: Optional metric sink.
            passphrase: Required if, and only if, the key file was saved
                encrypted. Passing one for an unencrypted key is an error, as
                is omitting one for an encrypted key, and both surface as
                :class:`~pqpki.errors.CAStateError`.
            state_path: Where to read persisted revocation state from. Defaults
                to :data:`STATE_FILENAME` beside ``cert_path``. A missing file
                is not an error -- it just means nothing was ever revoked -- but
                an unreadable or malformed one is.
            crl_url: CRL distribution point for newly issued certificates. Not
                persisted, because it describes where *this* deployment serves
                CRLs rather than anything about the CA's identity.
            delta_crl_url: Freshest-CRL location for newly issued certificates.

        Raises:
            CAStateError: If either file cannot be parsed, the passphrase is
                wrong or unnecessary, the state file is malformed, the key does
                not match the certificate, or the certificate is not a CA.
        """
        try:
            certificate = x509.load_pem_x509_certificate(Path(cert_path).read_bytes())
        except Exception as exc:
            raise CAStateError(f"could not load CA certificate from {cert_path}: {exc}") from exc

        password = passphrase.encode() if isinstance(passphrase, str) else passphrase
        try:
            private_key = serialization.load_pem_private_key(
                Path(key_path).read_bytes(), password=password
            )
        except TypeError as exc:
            # `cryptography` raises TypeError, not ValueError, for the two
            # password/encryption mismatches. They are the most likely thing to
            # go wrong here, so they get their own message rather than being
            # reported as an unparseable file.
            if password is None:
                raise CAStateError(
                    f"the CA private key at {key_path} is encrypted, so a "
                    f"passphrase is required to load it"
                ) from exc
            raise CAStateError(
                f"the CA private key at {key_path} is not encrypted, so no "
                f"passphrase should be supplied"
            ) from exc
        except ValueError as exc:
            if password is not None:
                raise CAStateError(
                    f"could not decrypt the CA private key at {key_path}: the "
                    f"passphrase is wrong, or the file is corrupt"
                ) from exc
            raise CAStateError(
                f"could not load CA private key from {key_path}: {exc}"
            ) from exc
        except Exception as exc:
            raise CAStateError(f"could not load CA private key from {key_path}: {exc}") from exc

        ca = cls(
            certificate,
            private_key,  # type: ignore[arg-type]
            collector=collector,
            crl_url=crl_url,
            delta_crl_url=delta_crl_url,
        )

        resolved_state = (
            Path(state_path)
            if state_path is not None
            else Path(cert_path).parent / STATE_FILENAME
        )
        if resolved_state.exists():
            ca._restore_state(resolved_state)
        return ca

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

    @property
    def crl_number(self) -> int:
        """The CRLNumber most recently issued, or 0 before the first CRL."""
        return self._crl_number

    @property
    def base_crl_number(self) -> int | None:
        """CRLNumber of the latest complete CRL, or None if none was published.

        A delta CRL is only meaningful relative to this.
        """
        return self._base_crl_number

    @property
    def crl_url(self) -> str | None:
        """Where this CA says its complete CRL is published, if anywhere."""
        return self._crl_url

    @property
    def delta_crl_url(self) -> str | None:
        """Where this CA says its delta CRLs are published, if anywhere."""
        return self._delta_crl_url

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
        builder = (
            x509.CertificateBuilder()
            .subject_name(csr.subject)
            .issuer_name(self._certificate.subject)
            .public_key(csr.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=validity_days))
        )
        return self._add_revocation_pointers(builder)

    def _add_revocation_pointers(
        self, builder: x509.CertificateBuilder
    ) -> x509.CertificateBuilder:
        """Add CRLDistributionPoints and FreshestCRL, if this CA advertises them.

        Both are non-critical, as RFC 5280 requires. That has a consequence
        worth being explicit about: a relying party is permitted to ignore
        them, so these extensions help a client find a CRL but cannot force it
        to look. Revocation checking is something the validator does because it
        was asked to, not something a certificate can compel.
        """
        if self._crl_url is not None:
            builder = builder.add_extension(
                x509.CRLDistributionPoints([_distribution_point(self._crl_url)]),
                critical=False,
            )
        if self._delta_crl_url is not None:
            builder = builder.add_extension(
                x509.FreshestCRL([_distribution_point(self._delta_crl_url)]),
                critical=False,
            )
        return builder

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
        *,
        extended_key_usage: list[x509.ObjectIdentifier] | None = None,
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
            extended_key_usage: Purpose OIDs for the ``ExtendedKeyUsage``
                extension, keyword-only. Defaults to server authentication,
                which is what the chain-validation cross-checks against
                ``openssl verify -purpose sslserver`` require. Pass
                ``clientAuth`` or ``codeSigning`` for a certificate meant for
                a different job: a certificate that claims every purpose
                constrains nothing, which is the opposite of what the
                extension is for.

        Raises:
            IssuanceError: If proof of possession fails, if no SAN names are
                available from either the argument or the CSR, or if
                ``extended_key_usage`` is given but empty.
        """
        names = san_dns if san_dns is not None else _requested_dns_names(csr)
        if not names:
            raise IssuanceError(
                "no SubjectAlternativeName DNS names supplied by argument or "
                "requested in the CSR. Name validation reads the SAN, not the "
                "common name, so a leaf without one identifies nothing"
            )

        if extended_key_usage is not None and not extended_key_usage:
            raise IssuanceError(
                "extended_key_usage was supplied but empty. An empty "
                "ExtendedKeyUsage permits no purpose at all, which would make "
                "the certificate useless; omit the argument to accept the "
                "default instead"
            )
        purposes = (
            extended_key_usage
            if extended_key_usage is not None
            else [ExtendedKeyUsageOID.SERVER_AUTH]
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
            .add_extension(x509.ExtendedKeyUsage(purposes), critical=False)
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
        """A copy of the revocation register, as persisted by :meth:`save`."""
        return dict(self._revoked)

    def _start_crl(
        self, validity_days: int
    ) -> tuple[x509.CertificateRevocationListBuilder, int]:
        """Begin a CRL, consuming the next CRLNumber.

        Complete and delta CRLs draw from one counter, so a relying party can
        order every CRL this CA ever published against every other.
        """
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
        return builder, self._crl_number

    def _add_entries(
        self,
        builder: x509.CertificateRevocationListBuilder,
        serials: list[int],
    ) -> x509.CertificateRevocationListBuilder:
        """Add one revoked-certificate entry per serial, in serial order."""
        for serial in sorted(serials):
            revoked_at, reason = self._revoked[serial]
            entry = (
                x509.RevokedCertificateBuilder()
                .serial_number(serial)
                .revocation_date(revoked_at)
                .add_extension(x509.CRLReason(reason), critical=False)
                .build()
            )
            builder = builder.add_revoked_certificate(entry)
        return builder

    def _sign_crl(
        self,
        builder: x509.CertificateRevocationListBuilder,
        operation: str,
    ) -> x509.CertificateRevocationList:
        """Sign a CRL with this CA's key, timing and measuring it."""
        spec = self.algorithm
        started = time.perf_counter()
        crl = builder.sign(self._private_key, *spec.sign_args())
        elapsed = time.perf_counter() - started
        _emit(
            self._collector,
            operation,
            spec.name,
            elapsed,
            len(crl.public_bytes(serialization.Encoding.DER)),
        )
        return crl

    def publish_crl(
        self, validity_days: int = 7
    ) -> x509.CertificateRevocationList:
        """Sign and return a complete CRL covering everything revoked so far.

        Args:
            validity_days: How long until ``nextUpdate``. A relying party that
                sees a CRL past its ``nextUpdate`` should treat revocation
                status as unknown rather than assuming nothing was revoked.

        Publishing a complete CRL also establishes a new *base* for delta CRLs:
        any later :meth:`publish_delta_crl` reports changes relative to this
        one. The CRL is signed with this CA's key through the same agility
        layer as a certificate, so a post-quantum CA publishes an
        ML-DSA-signed CRL with no extra code.
        """
        builder, number = self._start_crl(validity_days)

        if self._delta_crl_url is not None:
            # FreshestCRL on a complete CRL tells a relying party that deltas
            # exist and where to get them -- the same job it does on a
            # certificate, for a client that already has the base.
            builder = builder.add_extension(
                x509.FreshestCRL([_distribution_point(self._delta_crl_url)]),
                critical=False,
            )

        builder = self._add_entries(builder, list(self._revoked))
        crl = self._sign_crl(builder, "publish_crl")

        self._base_crl_number = number
        self._base_revoked_serials = frozenset(self._revoked)
        return crl

    def publish_delta_crl(
        self, validity_days: int = 1
    ) -> x509.CertificateRevocationList:
        """Sign and return a delta CRL listing changes since the last base CRL.

        A delta CRL carries only what has been revoked since the complete CRL
        it is relative to, which is what makes it small: a CA with fifty
        thousand revocations can publish a delta of three entries hourly and a
        complete CRL weekly. The saving matters much more for a post-quantum CA
        than a classical one, because an ML-DSA signature is a fixed, large
        cost paid once per CRL -- so for a short list of changes the signature
        dominates the entries, and publishing frequently is what makes that
        overhead worth paying.

        The ``DeltaCRLIndicator`` extension is **critical**, deliberately and
        per RFC 5280: a client that does not understand delta CRLs must reject
        this document outright rather than mistake it for a complete CRL. Doing
        that would be dangerous rather than merely wrong, since every serial
        listed only in the base would appear to have become good again.

        Args:
            validity_days: How long until ``nextUpdate``. Short by default,
                since frequent republication is the point.

        Raises:
            CAStateError: If no complete CRL has been published yet, so there
                is no base for this delta to be relative to.
        """
        if self._base_crl_number is None:
            raise CAStateError(
                "cannot publish a delta CRL before a complete CRL: a delta is "
                "defined as the changes since a specific base CRLNumber, and "
                "this CA has not published one. Call publish_crl() first"
            )

        builder, _ = self._start_crl(validity_days)
        builder = builder.add_extension(
            x509.DeltaCRLIndicator(self._base_crl_number), critical=True
        )

        new_serials = [s for s in self._revoked if s not in self._base_revoked_serials]
        builder = self._add_entries(builder, new_serials)
        return self._sign_crl(builder, "publish_delta_crl")

    # -- persistence -------------------------------------------------------

    def save(
        self, directory: Path, *, passphrase: bytes | str | None = None
    ) -> None:
        """Write the certificate, private key, and revocation state.

        Layout, matching what :meth:`load` expects::

            directory/ca.crt          PEM certificate
            directory/ca-state.json   revocation register and CRL counters
            directory/keys/ca.key     PEM PKCS#8 private key, mode 0600

        One CA per directory; the filenames are fixed, so saving two CAs to the
        same directory overwrites the first.

        Args:
            passphrase: When given, the private key is encrypted with it using
                ``BestAvailableEncryption``. When omitted the key is written in
                the clear, which is the weakest thing this package does to a
                secret and is the default only because an unencrypted key is
                what the demo and the OpenSSL interoperability tests can read
                without being handed a password.

        The ``0600`` mode is meaningful only on POSIX. On Windows the POSIX
        permission bits do not map onto ACLs, so :func:`os.chmod` succeeds
        without actually restricting anything -- which is precisely why
        ``passphrase`` is worth using there: it is the only one of the two
        protections that actually holds on this platform.
        """
        directory = Path(directory)
        key_directory = directory / KEY_DIRNAME
        directory.mkdir(parents=True, exist_ok=True)
        key_directory.mkdir(parents=True, exist_ok=True)

        (directory / CERT_FILENAME).write_bytes(
            self._certificate.public_bytes(serialization.Encoding.PEM)
        )

        if passphrase is None:
            encryption: serialization.KeySerializationEncryption = (
                serialization.NoEncryption()
            )
        else:
            secret = passphrase.encode() if isinstance(passphrase, str) else passphrase
            if not secret:
                raise CAStateError(
                    "an empty passphrase cannot encrypt the CA key; pass None "
                    "to write it unencrypted, or supply a real passphrase"
                )
            encryption = serialization.BestAvailableEncryption(secret)

        key_path = key_directory / KEY_FILENAME
        key_path.write_bytes(
            self._private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=encryption,
            )
        )
        os.chmod(key_path, KEY_FILE_MODE)

        (directory / STATE_FILENAME).write_text(
            json.dumps(self._state_document(), indent=2) + "\n", encoding="utf-8"
        )

    def _state_document(self) -> dict:
        """The revocation state, as a JSON-serializable document.

        Serials are written as hex strings. JSON numbers are IEEE 754 doubles
        in most parsers, and an X.509 serial is up to 160 bits, so round-
        tripping one as a number would silently corrupt it.
        """
        return {
            "version": STATE_VERSION,
            "issuer": self._certificate.subject.rfc4514_string(),
            "crl_number": self._crl_number,
            "base_crl_number": self._base_crl_number,
            "base_revoked_serials": sorted(f"{s:x}" for s in self._base_revoked_serials),
            "revoked": [
                {
                    "serial": f"{serial:x}",
                    "revoked_at": revoked_at.isoformat(),
                    "reason": reason.value,
                }
                for serial, (revoked_at, reason) in sorted(self._revoked.items())
            ],
        }

    def _restore_state(self, state_path: Path) -> None:
        """Load revocation state written by :meth:`save`.

        A malformed state file raises rather than being skipped. Treating it as
        "no revocations" would turn a corrupt file into a silent un-revocation
        of every certificate this CA ever revoked, which is the worst available
        outcome.
        """
        try:
            document = json.loads(state_path.read_text(encoding="utf-8"))
        except Exception as exc:
            raise CAStateError(
                f"could not read CA state from {state_path}: {exc}"
            ) from exc

        if not isinstance(document, dict):
            raise CAStateError(
                f"CA state at {state_path} is not a JSON object"
            )

        version = document.get("version")
        if version != STATE_VERSION:
            raise CAStateError(
                f"CA state at {state_path} has version {version!r}, but this "
                f"version of pqpki writes and reads version {STATE_VERSION}"
            )

        try:
            revoked: dict[int, tuple[datetime.datetime, x509.ReasonFlags]] = {}
            for entry in document["revoked"]:
                serial = int(entry["serial"], 16)
                revoked_at = datetime.datetime.fromisoformat(entry["revoked_at"])
                revoked[serial] = (revoked_at, x509.ReasonFlags(entry["reason"]))

            crl_number = int(document["crl_number"])
            raw_base = document.get("base_crl_number")
            base_crl_number = None if raw_base is None else int(raw_base)
            base_serials = frozenset(
                int(s, 16) for s in document.get("base_revoked_serials", [])
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise CAStateError(
                f"CA state at {state_path} is malformed: {exc}"
            ) from exc

        if crl_number < 0:
            raise CAStateError(
                f"CA state at {state_path} has a negative crl_number "
                f"({crl_number}), which cannot have been issued"
            )
        if base_crl_number is not None and base_crl_number > crl_number:
            raise CAStateError(
                f"CA state at {state_path} says the base CRL number is "
                f"{base_crl_number} but the last CRL number issued is "
                f"{crl_number}; the base cannot be newer than the latest CRL"
            )

        self._revoked = revoked
        self._crl_number = crl_number
        self._base_crl_number = base_crl_number
        self._base_revoked_serials = base_serials


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
