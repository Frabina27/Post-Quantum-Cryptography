"""A file-backed PKI the terminal UI can drive, classical or post-quantum.

:class:`PKIStore` is the integration seam between this package and the
project's terminal front end. The rest of ``pqpki`` deals in objects: a
:class:`~pqpki.ca.CertificateAuthority` you hold, certificates you pass around.
A menu-driven UI cannot hold objects between keystrokes -- the user picks
"Issue Server Certificate" ten minutes after creating the CA, possibly in a
later run of the program -- so something has to own a directory on disk and
answer questions about what is in it. That is this class, and the UI should
need no crypto imports of its own.

Every operation is one method, named after the thing the user chose, returning
a small value the caller can print. Nothing here raises for an
operator error: a missing CA or an unparseable file comes back as a
:class:`~pqpki.errors.PQPKIError` subclass carrying a sentence that can go
straight on screen.

Layout under ``root_directory``::

    root/ca.crt, root/ca-state.json, root/keys/ca.key
    intermediate/ca.crt, intermediate/ca-state.json, intermediate/keys/ca.key
    issued/<serial>.crt
    crl/latest.crl, crl/delta.crl
    chain.pem

The same store serves classical and post-quantum hierarchies; which one it is
depends entirely on the algorithm name passed to :meth:`create_root`. That is
the whole point -- the UI offers a list from
:func:`~pqpki.algorithms.list_algorithms` and nothing downstream changes.

This is a teaching implementation. In particular the store is not concurrent:
two processes using one directory will interleave writes to ``ca-state.json``
and lose revocations. There is no locking, because adding some would imply
this is safe to deploy.
"""

from __future__ import annotations

import dataclasses
from pathlib import Path

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import ExtendedKeyUsageOID

from .algorithms import (
    DEFAULT_ALGORITHM,
    get_algorithm,
    list_algorithms,
    public_key_size,
    spec_for_certificate,
    spec_for_key,
)
from .ca import CERT_FILENAME, KEY_DIRNAME, KEY_FILENAME, CertificateAuthority
from .csr import generate_csr, verify_csr_signature
from .errors import CAStateError, CSRError, PQPKIError, ValidationInputError
from .revocation import crl_number, delta_base_number, is_delta_crl
from .validate import ValidationResult, validate_chain

__all__ = [
    "CertificateProfile",
    "PKIStore",
    "SignatureCheck",
    "available_algorithms",
]

PEM = serialization.Encoding.PEM
DER = serialization.Encoding.DER

ROOT_DIRNAME = "root"
INTERMEDIATE_DIRNAME = "intermediate"
ISSUED_DIRNAME = "issued"
CRL_DIRNAME = "crl"
CRL_FILENAME = "latest.crl"
DELTA_CRL_FILENAME = "delta.crl"
CHAIN_FILENAME = "chain.pem"


def available_algorithms() -> list[str]:
    """Algorithm names the UI can offer. Classical and post-quantum together."""
    return list_algorithms()


class CertificateProfile:
    """The certificate purposes the UI offers, as ExtendedKeyUsage sets.

    A profile is the difference between "issue a certificate" and "issue a
    certificate *for something*". Keeping the three the UI names in one place
    means the menu passes a string and never touches an OID.
    """

    SERVER = "server"
    CLIENT = "client"
    CODE_SIGNING = "code-signing"

    _PURPOSES = {
        SERVER: (ExtendedKeyUsageOID.SERVER_AUTH,),
        CLIENT: (ExtendedKeyUsageOID.CLIENT_AUTH,),
        CODE_SIGNING: (ExtendedKeyUsageOID.CODE_SIGNING,),
    }

    @classmethod
    def names(cls) -> list[str]:
        """Profile names, for building a menu."""
        return list(cls._PURPOSES)

    @classmethod
    def purposes(cls, profile: str) -> list[x509.ObjectIdentifier]:
        """ExtendedKeyUsage OIDs for ``profile``.

        Raises:
            ValidationInputError: If ``profile`` is not one of :meth:`names`.
        """
        try:
            return list(cls._PURPOSES[profile])
        except KeyError:
            raise ValidationInputError(
                f"unknown certificate profile {profile!r}; choose one of "
                f"{cls.names()}"
            ) from None


@dataclasses.dataclass(frozen=True)
class SignatureCheck:
    """The outcome of verifying a detached file signature.

    Attributes:
        valid: Whether the signature verified against the certificate's key.
        algorithm: The algorithm used, as registered.
        detail: A sentence suitable for printing, in either case.
        chain: Chain validation of the signer's certificate, when one was
            requested. ``None`` when the caller only asked about the
            signature. A good signature from an untrusted certificate is a
            different answer from a good signature from a trusted one, and
            conflating them is how signature checks get believed too readily.
    """

    valid: bool
    algorithm: str
    detail: str
    chain: ValidationResult | None = None


class PKIStore:
    """A certificate authority hierarchy living in one directory.

    Args:
        root_directory: Where everything is kept. Created on demand.
        passphrase: Protects both CA private keys on disk. Supply the same one
            on every later construction, since it is not stored anywhere.
        crl_url: Advertised in the ``CRLDistributionPoints`` of issued
            certificates. Nothing in this package fetches it; it is there so a
            certificate says where its CRL lives.
        delta_crl_url: Advertised in ``FreshestCRL``.
    """

    def __init__(
        self,
        root_directory: Path | str,
        *,
        passphrase: str | bytes | None = None,
        crl_url: str | None = None,
        delta_crl_url: str | None = None,
    ) -> None:
        self.directory = Path(root_directory)
        self._passphrase = passphrase
        self._crl_url = crl_url
        self._delta_crl_url = delta_crl_url

    # -- paths -------------------------------------------------------------

    @property
    def root_dir(self) -> Path:
        return self.directory / ROOT_DIRNAME

    @property
    def intermediate_dir(self) -> Path:
        return self.directory / INTERMEDIATE_DIRNAME

    @property
    def issued_dir(self) -> Path:
        return self.directory / ISSUED_DIRNAME

    @property
    def crl_path(self) -> Path:
        return self.directory / CRL_DIRNAME / CRL_FILENAME

    @property
    def delta_crl_path(self) -> Path:
        return self.directory / CRL_DIRNAME / DELTA_CRL_FILENAME

    @property
    def chain_path(self) -> Path:
        return self.directory / CHAIN_FILENAME

    def has_root(self) -> bool:
        """Whether a root CA has been created in this store."""
        return (self.root_dir / CERT_FILENAME).exists()

    def has_intermediate(self) -> bool:
        """Whether an intermediate CA has been created in this store."""
        return (self.intermediate_dir / CERT_FILENAME).exists()

    # -- CA management -----------------------------------------------------

    def create_root(
        self,
        common_name: str,
        algorithm: str = DEFAULT_ALGORITHM,
        validity_days: int = 3650,
    ) -> x509.Certificate:
        """Generate a root key and self-signed root certificate, and save them.

        Args:
            common_name: The root's subject name.
            algorithm: One of :func:`available_algorithms`. The single choice
                that decides whether this hierarchy is classical or
                post-quantum.
            validity_days: Root lifetime.

        Raises:
            CAStateError: If a root already exists here. Overwriting it would
                orphan every certificate already issued under it, so this
                refuses rather than asking.
            UnknownAlgorithmError: If ``algorithm`` is not registered.
        """
        if self.has_root():
            raise CAStateError(
                f"a root CA already exists at {self.root_dir}. Overwriting it "
                f"would leave every certificate issued under it unverifiable; "
                f"delete the directory deliberately if that is what you want"
            )
        get_algorithm(algorithm)  # fail before generating anything

        ca = CertificateAuthority.create_root(
            common_name,
            algorithm,
            validity_days=validity_days,
            path_length=1,
            crl_url=self._crl_url,
            delta_crl_url=self._delta_crl_url,
        )
        ca.save(self.root_dir, passphrase=self._passphrase)
        return ca.certificate

    def create_intermediate(
        self,
        common_name: str,
        algorithm: str | None = None,
        validity_days: int = 1825,
    ) -> x509.Certificate:
        """Generate an intermediate, have the root certify it, and save it.

        Args:
            common_name: The intermediate's subject name.
            algorithm: Defaults to the root's own algorithm, which is almost
                always what is wanted. Passing a different one is allowed and
                produces a deliberately mixed hierarchy -- a classical root
                certifying a post-quantum intermediate, say, which is one
                shape a real migration takes.
            validity_days: Intermediate lifetime, conventionally shorter than
                the root's.

        Raises:
            CAStateError: If no root exists, or an intermediate already does.
        """
        if self.has_intermediate():
            raise CAStateError(
                f"an intermediate CA already exists at {self.intermediate_dir}"
            )
        root = self.load_root()
        chosen = algorithm or root.algorithm.name

        key = get_algorithm(chosen).generate_key()
        csr = generate_csr(common_name, key)
        certificate = root.issue_intermediate(
            csr, validity_days=validity_days, path_length=0
        )

        intermediate = CertificateAuthority(
            certificate,
            key,
            crl_url=self._crl_url,
            delta_crl_url=self._delta_crl_url,
        )
        intermediate.save(self.intermediate_dir, passphrase=self._passphrase)
        self.write_chain_bundle()
        return certificate

    def load_root(self) -> CertificateAuthority:
        """The root CA, with its revocation state restored.

        Raises:
            CAStateError: If no root has been created in this store.
        """
        return self._load(self.root_dir, "root")

    def load_intermediate(self) -> CertificateAuthority:
        """The intermediate CA, with its revocation state restored.

        Raises:
            CAStateError: If no intermediate has been created in this store.
        """
        return self._load(self.intermediate_dir, "intermediate")

    def _load(self, directory: Path, label: str) -> CertificateAuthority:
        if not (directory / CERT_FILENAME).exists():
            raise CAStateError(
                f"no {label} CA has been created yet. Create one before trying "
                f"to use it"
            )
        return CertificateAuthority.load(
            directory / CERT_FILENAME,
            directory / KEY_DIRNAME / KEY_FILENAME,
            passphrase=self._passphrase,
            crl_url=self._crl_url,
            delta_crl_url=self._delta_crl_url,
        )

    def issuing_ca(self) -> CertificateAuthority:
        """The CA that should sign end-entity certificates.

        The intermediate when there is one, otherwise the root. Real
        hierarchies keep the root out of day-to-day issuance so that it can
        stay offline, and the UI should not have to know that rule.
        """
        if self.has_intermediate():
            return self.load_intermediate()
        return self.load_root()

    def write_chain_bundle(self) -> Path:
        """Write intermediate-then-root as one PEM file, and return its path.

        Leaf-to-root order, which is what TLS servers and ``openssl verify
        -untrusted`` both expect.
        """
        certificates = []
        if self.has_intermediate():
            certificates.append(self.load_intermediate().certificate)
        certificates.append(self.load_root().certificate)

        self.chain_path.parent.mkdir(parents=True, exist_ok=True)
        self.chain_path.write_bytes(
            b"".join(c.public_bytes(PEM) for c in certificates)
        )
        return self.chain_path

    # -- issuance ----------------------------------------------------------

    def issue_certificate(
        self,
        common_name: str,
        dns_names: list[str],
        profile: str = CertificateProfile.SERVER,
        algorithm: str | None = None,
        validity_days: int = 90,
    ) -> tuple[x509.Certificate, Path, Path]:
        """Generate a key, request a certificate, issue it, and save both.

        Args:
            common_name: Subject name for the certificate.
            dns_names: ``SubjectAlternativeName`` DNS entries. At least one is
                required, because name validation reads the SAN rather than
                the common name.
            profile: One of :meth:`CertificateProfile.names`.
            algorithm: Defaults to the issuing CA's algorithm.
            validity_days: Leaf lifetime. Short by convention.

        Returns:
            The certificate, the path its PEM was written to, and the path its
            private key was written to.

        Raises:
            CAStateError: If no CA exists to issue it.
            IssuanceError: If issuance is refused.
            ValidationInputError: If ``profile`` is unknown or ``dns_names`` is
                empty.
        """
        if not dns_names:
            raise ValidationInputError(
                "at least one DNS name is required: certificate name "
                "validation reads the SubjectAlternativeName, so a certificate "
                "without one identifies nothing"
            )
        purposes = CertificateProfile.purposes(profile)

        ca = self.issuing_ca()
        chosen = algorithm or ca.algorithm.name
        key = get_algorithm(chosen).generate_key()
        csr = generate_csr(common_name, key, san_dns=dns_names)
        certificate = ca.issue_end_entity(
            csr,
            validity_days=validity_days,
            san_dns=dns_names,
            extended_key_usage=purposes,
        )

        cert_path = self._save_issued(certificate)
        key_path = self._save_issued_key(certificate, key)
        return certificate, cert_path, key_path

    def sign_csr(
        self,
        csr_path: Path | str,
        profile: str = CertificateProfile.SERVER,
        validity_days: int = 90,
    ) -> tuple[x509.Certificate, Path]:
        """Issue a certificate for a CSR someone else generated.

        The request's own signature is checked first, and a request that fails
        is refused. That check is the only evidence the CA ever has that
        whoever asked for the certificate actually holds the private key.

        Raises:
            CSRError: If the file cannot be read or parsed, or its proof of
                possession does not verify.
            CAStateError: If no CA exists to issue it.
        """
        path = Path(csr_path)
        try:
            data = path.read_bytes()
        except OSError as exc:
            raise CSRError(f"could not read a CSR from {path}: {exc}") from exc

        try:
            csr = (
                x509.load_pem_x509_csr(data)
                if b"-----BEGIN" in data
                else x509.load_der_x509_csr(data)
            )
        except Exception as exc:
            raise CSRError(
                f"{path} is not a PEM or DER certificate signing request: {exc}"
            ) from exc

        if not verify_csr_signature(csr):
            raise CSRError(
                f"the signature on {path} does not verify, so the requester has "
                f"not proven possession of the private key. Refusing to sign it"
            )

        ca = self.issuing_ca()
        certificate = ca.issue_end_entity(
            csr,
            validity_days=validity_days,
            extended_key_usage=CertificateProfile.purposes(profile),
        )
        return certificate, self._save_issued(certificate)

    def _save_issued(self, certificate: x509.Certificate) -> Path:
        self.issued_dir.mkdir(parents=True, exist_ok=True)
        path = self.issued_dir / f"{certificate.serial_number:x}.crt"
        path.write_bytes(certificate.public_bytes(PEM))
        return path

    def _save_issued_key(self, certificate: x509.Certificate, key) -> Path:
        """Write a subject's private key beside its certificate.

        Under ``issued/keys/`` with the same ``0600`` caveat as a CA key: this
        is the store generating a key pair on a subject's behalf, which a real
        PKI avoids precisely so that the CA never sees a subject's private key.
        """
        key_directory = self.issued_dir / KEY_DIRNAME
        key_directory.mkdir(parents=True, exist_ok=True)
        path = key_directory / f"{certificate.serial_number:x}.key"
        path.write_bytes(
            key.private_bytes(
                encoding=PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
        return path

    # -- revocation --------------------------------------------------------

    def revoke(
        self,
        serial_number: int,
        reason: x509.ReasonFlags = x509.ReasonFlags.unspecified,
    ) -> None:
        """Revoke a serial and persist the change immediately.

        Saved right away rather than on exit: a revocation that is lost
        because the program was closed is the one kind of state loss with a
        direct security consequence.
        """
        ca = self.issuing_ca()
        ca.revoke(serial_number, reason)
        ca.save(self._issuing_dir(), passphrase=self._passphrase)

    def _issuing_dir(self) -> Path:
        return self.intermediate_dir if self.has_intermediate() else self.root_dir

    def publish_crl(self, validity_days: int = 7) -> Path:
        """Publish a complete CRL and write it to :attr:`crl_path`."""
        ca = self.issuing_ca()
        crl = ca.publish_crl(validity_days=validity_days)
        ca.save(self._issuing_dir(), passphrase=self._passphrase)

        self.crl_path.parent.mkdir(parents=True, exist_ok=True)
        self.crl_path.write_bytes(crl.public_bytes(PEM))
        return self.crl_path

    def publish_delta_crl(self, validity_days: int = 1) -> Path:
        """Publish a delta CRL and write it to :attr:`delta_crl_path`.

        Raises:
            CAStateError: If no complete CRL has been published yet.
        """
        ca = self.issuing_ca()
        delta = ca.publish_delta_crl(validity_days=validity_days)
        ca.save(self._issuing_dir(), passphrase=self._passphrase)

        self.delta_crl_path.parent.mkdir(parents=True, exist_ok=True)
        self.delta_crl_path.write_bytes(delta.public_bytes(PEM))
        return self.delta_crl_path

    def load_crls(self) -> list[x509.CertificateRevocationList]:
        """Every CRL this store has published, complete and delta."""
        crls = []
        for path in (self.crl_path, self.delta_crl_path):
            if path.exists():
                crls.append(x509.load_pem_x509_crl(path.read_bytes()))
        return crls

    def crl_summary(self) -> list[str]:
        """Printable lines describing the published CRLs.

        An empty list means none has been published, which the UI should say
        rather than showing an empty panel.
        """
        lines = []
        for crl in self.load_crls():
            kind = "delta" if is_delta_crl(crl) else "complete"
            entries = len(list(crl))
            line = (
                f"{kind} CRL number {crl_number(crl)}, {entries} entr"
                f"{'y' if entries == 1 else 'ies'}, "
                f"next update {crl.next_update_utc.isoformat()}"
            )
            base = delta_base_number(crl)
            if base is not None:
                line += f", relative to base {base}"
            lines.append(line)
        return lines

    # -- inspection and validation ----------------------------------------

    def describe_certificate(self, path: Path | str) -> list[str]:
        """Printable lines describing a certificate file.

        Raises:
            ValidationInputError: If the file cannot be read or parsed.
        """
        certificate = self._load_certificate(path)
        try:
            algorithm = spec_for_certificate(certificate).name
        except PQPKIError:
            algorithm = (
                f"unrecognised (signature OID "
                f"{certificate.signature_algorithm_oid.dotted_string})"
            )

        lines = [
            f"Subject:    {certificate.subject.rfc4514_string()}",
            f"Issuer:     {certificate.issuer.rfc4514_string()}",
            f"Serial:     {certificate.serial_number:x}",
            f"Algorithm:  {algorithm}",
            f"Public key: {public_key_size(certificate.public_key())} bytes (SPKI)",
            f"Signature:  {len(certificate.signature)} bytes",
            f"Valid from: {certificate.not_valid_before_utc.isoformat()}",
            f"Valid to:   {certificate.not_valid_after_utc.isoformat()}",
            f"Size:       {len(certificate.public_bytes(DER))} bytes (DER)",
        ]
        for extension in certificate.extensions:
            lines.append(
                f"Extension:  {extension.oid._name} "
                f"{'(critical)' if extension.critical else ''}".rstrip()
            )
        return lines

    def describe_csr(self, path: Path | str) -> list[str]:
        """Printable lines describing a CSR file, including whether it verifies.

        Raises:
            CSRError: If the file cannot be read or parsed.
        """
        p = Path(path)
        try:
            data = p.read_bytes()
            csr = (
                x509.load_pem_x509_csr(data)
                if b"-----BEGIN" in data
                else x509.load_der_x509_csr(data)
            )
        except OSError as exc:
            raise CSRError(f"could not read a CSR from {p}: {exc}") from exc
        except Exception as exc:
            raise CSRError(f"{p} is not a certificate signing request: {exc}") from exc

        try:
            algorithm = spec_for_key(csr.public_key()).name
        except PQPKIError:
            algorithm = "unrecognised"

        verified = verify_csr_signature(csr)
        return [
            f"Subject:   {csr.subject.rfc4514_string()}",
            f"Algorithm: {algorithm}",
            f"Proof of possession: {'verifies' if verified else 'DOES NOT VERIFY'}",
            f"Size:      {len(csr.public_bytes(DER))} bytes (DER)",
        ]

    def validate_certificate(
        self, path: Path | str, check_revocation: bool = True
    ) -> ValidationResult:
        """Validate a certificate file against this store's trust anchor.

        Args:
            path: The certificate to validate.
            check_revocation: Whether to consult the published CRLs. When
                there are none, revocation is reported as unchecked rather
                than good.

        Raises:
            CAStateError: If this store has no root to validate against.
            ValidationInputError: If the file cannot be read or parsed.
        """
        certificate = self._load_certificate(path)
        root = self.load_root().certificate
        intermediates = (
            [self.load_intermediate().certificate] if self.has_intermediate() else []
        )
        crls = self.load_crls() if check_revocation else None
        return validate_chain(certificate, intermediates, [root], crls=crls)

    def _load_certificate(self, path: Path | str) -> x509.Certificate:
        p = Path(path)
        try:
            data = p.read_bytes()
        except OSError as exc:
            raise ValidationInputError(
                f"could not read a certificate from {p}: {exc}"
            ) from exc
        try:
            return (
                x509.load_pem_x509_certificate(data)
                if b"-----BEGIN" in data
                else x509.load_der_x509_certificate(data)
            )
        except Exception as exc:
            raise ValidationInputError(
                f"{p} is not a PEM or DER X.509 certificate: {exc}"
            ) from exc

    # -- detached file signatures -----------------------------------------

    def sign_file(
        self, file_path: Path | str, key_path: Path | str, signature_path: Path | str
    ) -> Path:
        """Sign a file with a private key, writing a detached signature.

        The signature is raw bytes, not a container format: this demonstrates
        the signing primitive the certificate machinery is built on, and is
        not CMS or any other interoperable detached-signature standard.

        Raises:
            ValidationInputError: If either input cannot be read, or the key is
                not one of this package's algorithms.
        """
        data = self._read(file_path, "file to sign")
        key_bytes = self._read(key_path, "private key")

        try:
            key = serialization.load_pem_private_key(key_bytes, password=None)
        except Exception as exc:
            raise ValidationInputError(
                f"could not load an unencrypted PEM private key from "
                f"{key_path}: {exc}"
            ) from exc

        spec = spec_for_key(key)
        signature = spec.sign_data(key, data)

        out = Path(signature_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_bytes(signature)
        return out

    def verify_file(
        self,
        file_path: Path | str,
        signature_path: Path | str,
        certificate_path: Path | str,
        *,
        check_chain: bool = False,
    ) -> SignatureCheck:
        """Verify a detached signature against a signer's certificate.

        Args:
            file_path: The file that was signed.
            signature_path: The detached signature.
            certificate_path: The signer's certificate, supplying the public
                key.
            check_chain: Also validate the signer's certificate to this
                store's root. A valid signature from a certificate that does
                not chain to a trusted root proves only that somebody holds
                some key, which is why this is reported separately rather than
                folded into one boolean.

        Raises:
            ValidationInputError: If any input cannot be read or parsed.
        """
        data = self._read(file_path, "signed file")
        signature = self._read(signature_path, "signature")
        certificate = self._load_certificate(certificate_path)

        spec = spec_for_key(certificate.public_key())
        chain = self.validate_certificate(certificate_path) if check_chain else None

        try:
            spec.verify_signature(certificate.public_key(), signature, data)
        except InvalidSignature:
            return SignatureCheck(
                valid=False,
                algorithm=spec.name,
                detail=(
                    f"the {spec.name} signature does not verify against the "
                    f"public key in {Path(certificate_path).name}: the file, "
                    f"the signature, or the signer is not what it claims"
                ),
                chain=chain,
            )

        detail = (
            f"the {spec.name} signature verifies against the public key in "
            f"{Path(certificate_path).name}"
        )
        if chain is not None and not chain.valid:
            detail += (
                ", but that certificate does not chain to this store's root, so "
                "the signer is unauthenticated"
            )
        return SignatureCheck(
            valid=True, algorithm=spec.name, detail=detail, chain=chain
        )

    def _read(self, path: Path | str, label: str) -> bytes:
        try:
            return Path(path).read_bytes()
        except OSError as exc:
            raise ValidationInputError(
                f"could not read the {label} at {path}: {exc}"
            ) from exc
