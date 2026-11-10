"""Deliberately broken certificates, for the security-testing module to attack with.

The security-testing module owns attacks on cryptographic primitives: altered
messages, corrupted ciphertexts, wrong keys. Certificates need the same
treatment, but the interesting failures live a level up -- a chain can be
cryptographically perfect and still have to be rejected, because the issuer was
an end-entity certificate, or the signer lacked ``keyCertSign``, or a CRL said
the subject was revoked. Those cases are tedious to construct from outside the
package, so this module constructs them from inside it.

Two shapes of attack, because a PKI has two places to say no:

:class:`ChainAttack`
    A chain that exists and parses, and that :func:`~pqpki.validate.validate_chain`
    must reject with a *specific* named reason. Asserting the reason is the
    point: "rejected" can hide a validator that rejects everything, and the
    difference between rejecting a revoked certificate as ``revoked`` and
    rejecting it as ``signature`` is the difference between working and
    accidentally working.

:class:`IssuanceAttack`
    A request the CA itself must refuse, before anything is signed. These are
    the attacks that never get as far as producing a certificate -- a forged
    proof of possession, an attempt to use a leaf as a CA, a path-length
    overflow.

Usage from another module::

    from pqpki.attacks import run_all

    for outcome in run_all("ml-dsa-65"):
        print("PASS" if outcome.defended else "FAIL", outcome.name)

Or from the command line, over every algorithm::

    python -m pqpki.attacks

``defended`` is True when the PKI did the right thing, so a row of PASS means
every attack was repelled. That polarity is deliberate: a test harness should
read "did the defence hold", not "did the attack run".

Nothing here is algorithm-specific. Every case is built for whichever algorithm
is asked for, so the same attack set runs against the classical and the
post-quantum hierarchies and any difference in outcome is a real finding rather
than a difference between two test suites.
"""

from __future__ import annotations

import argparse
import dataclasses
import datetime
from typing import Callable

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID

from .algorithms import AlgorithmSpec, get_algorithm, list_algorithms
from .ca import CertificateAuthority
from .csr import generate_csr
from .errors import CAStateError, IssuanceError, PQPKIError
from .validate import FailureCode, validate_chain

__all__ = [
    "ChainAttack",
    "IssuanceAttack",
    "AttackOutcome",
    "chain_attacks",
    "issuance_attacks",
    "run_all",
    "main",
]

DER = serialization.Encoding.DER

#: A marker inside every subject name this module creates. Tampering works by
#: finding this ASCII in the signed bytes and changing one character of it,
#: which keeps the DER structurally valid -- same tag, same length -- while
#: changing what was signed. A length change would produce an unparseable
#: certificate, which tests the DER parser rather than the signature check.
_MARKER = "Target"

LEAF_DNS_NAME = "leaf.attack.example"


@dataclasses.dataclass(frozen=True)
class ChainAttack:
    """A chain that must be rejected, and the reason it must be rejected for.

    Attributes:
        name: Stable identifier, usable as a test id.
        description: What the attacker did, in one sentence.
        expected_code: The :class:`~pqpki.validate.FailureCode` that must
            appear among the reported failures.
        leaf: The certificate to validate.
        intermediates: Candidate intermediates to supply.
        trust_roots: Trust anchors to validate against.
        crls: CRLs to supply, or None to skip revocation checking.
        at_time: The instant to validate at, or None for now.
    """

    name: str
    description: str
    expected_code: str
    leaf: x509.Certificate
    intermediates: list[x509.Certificate]
    trust_roots: list[x509.Certificate]
    crls: list[x509.CertificateRevocationList] | None = None
    at_time: datetime.datetime | None = None

    def run(self) -> "AttackOutcome":
        """Validate the chain and report whether it was correctly rejected."""
        result = validate_chain(
            self.leaf,
            self.intermediates,
            self.trust_roots,
            crls=self.crls,
            at_time=self.at_time,
        )
        if result.valid:
            return AttackOutcome(
                self.name,
                self.description,
                defended=False,
                detail=(
                    f"the chain was ACCEPTED, but should have been rejected "
                    f"with {self.expected_code!r}"
                ),
            )

        codes = [failure.split(":", 1)[0] for failure in result.failures]
        if self.expected_code not in codes:
            return AttackOutcome(
                self.name,
                self.description,
                defended=False,
                detail=(
                    f"the chain was rejected, but for {codes} rather than the "
                    f"expected {self.expected_code!r}"
                ),
            )
        return AttackOutcome(
            self.name,
            self.description,
            defended=True,
            detail=f"rejected with {self.expected_code!r}, as required",
        )


@dataclasses.dataclass(frozen=True)
class IssuanceAttack:
    """A request the CA must refuse before signing anything.

    Attributes:
        name: Stable identifier.
        description: What the attacker asked for.
        expected_error: The exception type the CA must raise.
        attempt: A callable that performs the forbidden request.
    """

    name: str
    description: str
    expected_error: type[PQPKIError]
    attempt: Callable[[], object]

    def run(self) -> "AttackOutcome":
        """Make the request and report whether it was correctly refused."""
        try:
            self.attempt()
        except self.expected_error as exc:
            return AttackOutcome(
                self.name,
                self.description,
                defended=True,
                detail=f"refused with {type(exc).__name__}, as required",
            )
        except Exception as exc:  # noqa: BLE001 - any other error is a failure
            return AttackOutcome(
                self.name,
                self.description,
                defended=False,
                detail=(
                    f"refused, but with {type(exc).__name__} rather than the "
                    f"expected {self.expected_error.__name__}: {exc}"
                ),
            )
        return AttackOutcome(
            self.name,
            self.description,
            defended=False,
            detail="the request was ALLOWED, and should have been refused",
        )


@dataclasses.dataclass(frozen=True)
class AttackOutcome:
    """What happened when one attack was run.

    Attributes:
        name: The attack's identifier.
        description: What the attack did.
        defended: True if the PKI behaved correctly -- rejected the chain for
            the right reason, or refused the request. True is the good case.
        detail: A printable sentence explaining the outcome.
    """

    name: str
    description: str
    defended: bool
    detail: str


# --------------------------------------------------------------------------
# Construction helpers
# --------------------------------------------------------------------------


def _name(common_name: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])


def _tamper(der: bytes, marker: str = _MARKER) -> bytes:
    """Change one character of ``marker`` inside ``der``.

    Finds the marker as ASCII and flips the low bit of its first byte, turning
    a letter into an adjacent letter. The encoded length does not change, so
    the result still parses as DER -- it is simply no longer the bytes that
    were signed, which is exactly the attack being modelled.

    Raises:
        ValueError: If the marker is absent, which would make the "tampered"
            artifact identical to the original and the test vacuous.
    """
    needle = marker.encode("ascii")
    index = der.find(needle)
    if index < 0:
        raise ValueError(
            f"cannot tamper with these bytes: the marker {marker!r} does not "
            f"appear in them, so nothing would have been modified"
        )
    mutated = bytearray(der)
    mutated[index] ^= 0x01
    return bytes(mutated)


def _raw_certificate(
    subject: x509.Name,
    public_key,
    issuer_certificate: x509.Certificate,
    issuer_key,
    spec: AlgorithmSpec,
    *,
    extensions: list[tuple[x509.ExtensionType, bool]],
    validity_days: int = 90,
) -> x509.Certificate:
    """Sign a certificate directly, bypassing :class:`CertificateAuthority`.

    :class:`CertificateAuthority` refuses to produce several of the
    certificates these attacks need -- that refusal is the feature being
    tested elsewhere. To check that the *validator* also catches them, the
    malformed certificate has to be manufactured some other way, which is what
    this does. Signing still goes through ``spec.sign_args()``, so even the
    attack construction is algorithm-agnostic.
    """
    now = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer_certificate.subject)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=validity_days))
    )
    for extension, critical in extensions:
        builder = builder.add_extension(extension, critical=critical)
    return builder.sign(issuer_key, *spec.sign_args())


def _leaf_key_usage() -> x509.KeyUsage:
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


def _ca_key_usage(*, key_cert_sign: bool = True) -> x509.KeyUsage:
    return x509.KeyUsage(
        digital_signature=False,
        content_commitment=False,
        key_encipherment=False,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=key_cert_sign,
        crl_sign=True,
        encipher_only=False,
        decipher_only=False,
    )


@dataclasses.dataclass
class _Hierarchy:
    """A working root -> intermediate -> leaf chain to attack."""

    spec: AlgorithmSpec
    root_ca: CertificateAuthority
    intermediate_ca: CertificateAuthority
    leaf: x509.Certificate
    leaf_key: object

    @property
    def root(self) -> x509.Certificate:
        return self.root_ca.certificate

    @property
    def intermediate(self) -> x509.Certificate:
        return self.intermediate_ca.certificate


def _build(algorithm: str, prefix: str) -> _Hierarchy:
    """Build an intact hierarchy whose names contain the tamper marker."""
    spec = get_algorithm(algorithm)
    root_ca = CertificateAuthority.create_root(
        f"{prefix} Root", algorithm, validity_days=3650, path_length=1
    )

    intermediate_key = spec.generate_key()
    intermediate_csr = generate_csr(f"{prefix} Intermediate", intermediate_key)
    intermediate_cert = root_ca.issue_intermediate(
        intermediate_csr, validity_days=1825, path_length=0
    )
    intermediate_ca = CertificateAuthority(intermediate_cert, intermediate_key)

    leaf_key = spec.generate_key()
    leaf_csr = generate_csr(
        f"{prefix} {_MARKER} Leaf", leaf_key, san_dns=[LEAF_DNS_NAME]
    )
    leaf = intermediate_ca.issue_end_entity(leaf_csr, validity_days=90)
    return _Hierarchy(spec, root_ca, intermediate_ca, leaf, leaf_key)


# --------------------------------------------------------------------------
# The attacks
# --------------------------------------------------------------------------


def chain_attacks(algorithm: str) -> list[ChainAttack]:
    """Build every chain-validation attack for ``algorithm``.

    Each returned attack is a complete, parseable chain that must be rejected.
    Building them costs several key generations, so build once and reuse.

    Raises:
        UnknownAlgorithmError: If ``algorithm`` is not registered.
    """
    good = _build(algorithm, "pqpki Attack")
    # A second, unrelated hierarchy. The name prefix must differ: two
    # hierarchies with identical subject names are genuinely ambiguous to a
    # path builder, so "a certificate from an unrelated CA" needs different
    # names or it tests something else entirely.
    other = _build(algorithm, "pqpki Unrelated")
    # A third hierarchy whose names deliberately *match* the good one. This is
    # the impostor: name chaining succeeds, and only the signature check can
    # tell the difference.
    impostor = _build(algorithm, "pqpki Attack")

    spec = good.spec
    now = datetime.datetime.now(datetime.timezone.utc)
    attacks: list[ChainAttack] = []

    # -- signature attacks ------------------------------------------------

    attacks.append(
        ChainAttack(
            name="tampered-signed-bytes",
            description=(
                "one character of the subject name is altered inside the "
                "signed region of an otherwise genuine leaf certificate"
            ),
            expected_code=FailureCode.SIGNATURE,
            leaf=x509.load_der_x509_certificate(_tamper(good.leaf.public_bytes(DER))),
            intermediates=[good.intermediate],
            trust_roots=[good.root],
        )
    )

    attacks.append(
        ChainAttack(
            name="impostor-issuer-same-name",
            description=(
                "a leaf signed by a CA that copied the real intermediate's "
                "subject name but holds a different key, so only the "
                "signature distinguishes it"
            ),
            expected_code=FailureCode.SIGNATURE,
            leaf=impostor.leaf,
            intermediates=[good.intermediate],
            trust_roots=[good.root],
        )
    )

    # -- trust path attacks -----------------------------------------------

    attacks.append(
        ChainAttack(
            name="unknown-issuer",
            description=(
                "a genuine leaf presented with no intermediate, so the chain "
                "cannot reach any trust anchor"
            ),
            expected_code=FailureCode.NAME_CHAINING,
            leaf=good.leaf,
            intermediates=[],
            trust_roots=[good.root],
        )
    )

    attacks.append(
        ChainAttack(
            name="untrusted-root",
            description=(
                "a complete, internally consistent chain whose self-signed "
                "root is not among the trust anchors"
            ),
            expected_code=FailureCode.NO_TRUST_ANCHOR,
            leaf=good.leaf,
            intermediates=[good.intermediate, good.root],
            trust_roots=[other.root],
        )
    )

    # -- authority attacks ------------------------------------------------

    end_entity_signed = _raw_certificate(
        _name(f"pqpki {_MARKER} Victim"),
        spec.generate_key().public_key(),
        good.leaf,
        good.leaf_key,
        spec,
        extensions=[
            (x509.BasicConstraints(ca=False, path_length=None), True),
            (_leaf_key_usage(), True),
            (x509.SubjectAlternativeName([x509.DNSName(LEAF_DNS_NAME)]), False),
        ],
    )
    attacks.append(
        ChainAttack(
            name="end-entity-used-as-ca",
            description=(
                "an end-entity certificate, which asserts CA=FALSE, is used to "
                "sign another certificate"
            ),
            expected_code=FailureCode.NOT_A_CA,
            leaf=end_entity_signed,
            intermediates=[good.leaf, good.intermediate],
            trust_roots=[good.root],
        )
    )

    # A CA certificate that asserts CA=TRUE but withholds keyCertSign, then
    # signs a leaf anyway. CA=TRUE alone is not permission to sign
    # certificates; KeyUsage has to grant it too.
    weak_ca_key = spec.generate_key()
    weak_ca = _raw_certificate(
        _name(f"pqpki {_MARKER} No CertSign CA"),
        weak_ca_key.public_key(),
        good.root,
        good.root_ca.private_key,
        spec,
        extensions=[
            (x509.BasicConstraints(ca=True, path_length=0), True),
            (_ca_key_usage(key_cert_sign=False), True),
        ],
        validity_days=365,
    )
    weak_leaf = _raw_certificate(
        _name(f"pqpki {_MARKER} Weak Leaf"),
        spec.generate_key().public_key(),
        weak_ca,
        weak_ca_key,
        spec,
        extensions=[
            (x509.BasicConstraints(ca=False, path_length=None), True),
            (_leaf_key_usage(), True),
            (x509.SubjectAlternativeName([x509.DNSName(LEAF_DNS_NAME)]), False),
        ],
    )
    attacks.append(
        ChainAttack(
            name="ca-without-key-cert-sign",
            description=(
                "a CA certificate that asserts CA=TRUE but omits keyCertSign "
                "from its KeyUsage signs a leaf anyway"
            ),
            expected_code=FailureCode.KEY_USAGE_CERT_SIGN,
            leaf=weak_leaf,
            intermediates=[weak_ca],
            trust_roots=[good.root],
        )
    )

    # -- validity window attacks ------------------------------------------

    attacks.append(
        ChainAttack(
            name="expired-certificate",
            description=(
                "a genuine leaf evaluated after its notAfter, as an attacker "
                "replaying an old certificate would present it"
            ),
            expected_code=FailureCode.EXPIRED,
            leaf=good.leaf,
            intermediates=[good.intermediate],
            trust_roots=[good.root],
            at_time=now + datetime.timedelta(days=365 * 2),
        )
    )

    attacks.append(
        ChainAttack(
            name="not-yet-valid-certificate",
            description="a genuine leaf evaluated before its notBefore",
            expected_code=FailureCode.NOT_YET_VALID,
            leaf=good.leaf,
            intermediates=[good.intermediate],
            trust_roots=[good.root],
            at_time=now - datetime.timedelta(days=1),
        )
    )

    # -- revocation attacks -----------------------------------------------

    revoking_ca = _build(algorithm, "pqpki Revoked")
    revoking_ca.intermediate_ca.revoke(
        revoking_ca.leaf.serial_number, x509.ReasonFlags.key_compromise
    )
    revocation_crl = revoking_ca.intermediate_ca.publish_crl()
    attacks.append(
        ChainAttack(
            name="revoked-certificate",
            description=(
                "a cryptographically valid, unexpired leaf that its issuer has "
                "listed on a signed CRL"
            ),
            expected_code=FailureCode.REVOKED,
            leaf=revoking_ca.leaf,
            intermediates=[revoking_ca.intermediate],
            trust_roots=[revoking_ca.root],
            crls=[revocation_crl],
        )
    )

    # A CRL that names the right issuer but was signed by somebody else: the
    # attack of forging a revocation list to deny service, or of forging an
    # empty one to suppress a real revocation.
    attacks.append(
        ChainAttack(
            name="forged-crl",
            description=(
                "a CRL whose issuer name matches the real intermediate but "
                "which was signed by an unrelated key"
            ),
            expected_code=FailureCode.CRL_PROBLEM,
            leaf=good.leaf,
            intermediates=[good.intermediate],
            trust_roots=[good.root],
            crls=[_forge_crl_issuer(good, other)],
        )
    )

    stale_hierarchy = _build(algorithm, "pqpki Stale")
    stale_crl = stale_hierarchy.intermediate_ca.publish_crl(validity_days=1)
    attacks.append(
        ChainAttack(
            name="stale-crl",
            description=(
                "a genuine CRL presented long after its nextUpdate, so an "
                "attacker could be hiding a newer revocation behind it"
            ),
            expected_code=FailureCode.CRL_PROBLEM,
            leaf=stale_hierarchy.leaf,
            intermediates=[stale_hierarchy.intermediate],
            trust_roots=[stale_hierarchy.root],
            crls=[stale_crl],
            at_time=now + datetime.timedelta(days=30),
        )
    )

    # A delta CRL supplied without the base it refines. Believing it would be
    # worse than having no CRL at all: every serial listed only in the base
    # would appear to have become good again.
    delta_hierarchy = _build(algorithm, "pqpki Delta")
    delta_hierarchy.intermediate_ca.revoke(
        delta_hierarchy.leaf.serial_number, x509.ReasonFlags.key_compromise
    )
    delta_hierarchy.intermediate_ca.publish_crl()
    delta_hierarchy.intermediate_ca.revoke(1, x509.ReasonFlags.superseded)
    orphan_delta = delta_hierarchy.intermediate_ca.publish_delta_crl()
    attacks.append(
        ChainAttack(
            name="orphan-delta-crl",
            description=(
                "a delta CRL supplied without its base, which must not be "
                "read as a complete CRL"
            ),
            expected_code=FailureCode.CRL_PROBLEM,
            leaf=delta_hierarchy.leaf,
            intermediates=[delta_hierarchy.intermediate],
            trust_roots=[delta_hierarchy.root],
            crls=[orphan_delta],
        )
    )

    return attacks


def _forge_crl_issuer(
    target: _Hierarchy, forger: _Hierarchy
) -> x509.CertificateRevocationList:
    """Build a CRL naming ``target``'s intermediate but signed by ``forger``'s.

    The signature is genuine, just by the wrong key -- which is precisely the
    situation a relying party must detect, because a CRL is only as
    authoritative as the key that signed it.
    """
    now = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(target.intermediate.subject)
        .last_update(now)
        .next_update(now + datetime.timedelta(days=7))
        .add_extension(x509.CRLNumber(99), critical=False)
    )
    entry = (
        x509.RevokedCertificateBuilder()
        .serial_number(target.leaf.serial_number)
        .revocation_date(now)
        .add_extension(x509.CRLReason(x509.ReasonFlags.key_compromise), critical=False)
        .build()
    )
    builder = builder.add_revoked_certificate(entry)
    return builder.sign(
        forger.intermediate_ca.private_key, *forger.spec.sign_args()
    )


def issuance_attacks(algorithm: str) -> list[IssuanceAttack]:
    """Build every issuance-refusal attack for ``algorithm``.

    Raises:
        UnknownAlgorithmError: If ``algorithm`` is not registered.
    """
    good = _build(algorithm, "pqpki Issuance")
    spec = good.spec
    attacks: list[IssuanceAttack] = []

    # A CSR whose subject was altered after it was self-signed. Proof of
    # possession is the only evidence a CA has that the requester holds the
    # private key for the public key it is about to certify.
    honest_key = spec.generate_key()
    honest_csr = generate_csr(
        f"pqpki {_MARKER} Requester", honest_key, san_dns=[LEAF_DNS_NAME]
    )
    forged_csr = x509.load_der_x509_csr(_tamper(honest_csr.public_bytes(DER)))
    attacks.append(
        IssuanceAttack(
            name="forged-proof-of-possession",
            description=(
                "a CSR whose subject name was altered after signing, so its "
                "self-signature no longer verifies"
            ),
            expected_error=IssuanceError,
            attempt=lambda: good.intermediate_ca.issue_end_entity(
                forged_csr, validity_days=90
            ),
        )
    )

    attacks.append(
        IssuanceAttack(
            name="end-entity-as-certificate-authority",
            description=(
                "an end-entity certificate is loaded as a CA in order to sign "
                "certificates with it"
            ),
            expected_error=CAStateError,
            attempt=lambda: CertificateAuthority(good.leaf, good.leaf_key),
        )
    )

    attacks.append(
        IssuanceAttack(
            name="mismatched-key-and-certificate",
            description=(
                "a CA certificate paired with a private key that does not "
                "match its public key"
            ),
            expected_error=CAStateError,
            attempt=lambda: CertificateAuthority(
                good.intermediate, spec.generate_key()
            ),
        )
    )

    # The intermediate was issued with pathLenConstraint 0, so it may issue
    # end entities and no further CAs.
    sub_key = spec.generate_key()
    sub_csr = generate_csr(f"pqpki {_MARKER} Sub CA", sub_key)
    attacks.append(
        IssuanceAttack(
            name="path-length-overflow",
            description=(
                "a CA whose pathLenConstraint is 0 is asked to issue a "
                "subordinate CA certificate"
            ),
            expected_error=IssuanceError,
            attempt=lambda: good.intermediate_ca.issue_intermediate(
                sub_csr, validity_days=365
            ),
        )
    )

    unnamed_key = spec.generate_key()
    unnamed_csr = generate_csr(f"pqpki {_MARKER} Nameless", unnamed_key)
    attacks.append(
        IssuanceAttack(
            name="leaf-without-subject-alternative-name",
            description=(
                "an end-entity certificate is requested with no SAN, leaving "
                "nothing for name validation to check"
            ),
            expected_error=IssuanceError,
            attempt=lambda: good.intermediate_ca.issue_end_entity(
                unnamed_csr, validity_days=90
            ),
        )
    )

    attacks.append(
        IssuanceAttack(
            name="delta-crl-without-base",
            description=(
                "a delta CRL is requested before any complete CRL exists, so "
                "there is no base for it to be relative to"
            ),
            expected_error=CAStateError,
            attempt=lambda: _build(
                algorithm, "pqpki NoBase"
            ).intermediate_ca.publish_delta_crl(),
        )
    )

    return attacks


def run_all(algorithm: str) -> list[AttackOutcome]:
    """Run every attack against ``algorithm`` and report what the PKI did.

    Returns:
        One :class:`AttackOutcome` per attack. ``defended`` is True where the
        PKI behaved correctly, so an all-True list is a pass.
    """
    outcomes = [attack.run() for attack in chain_attacks(algorithm)]
    outcomes.extend(attack.run() for attack in issuance_attacks(algorithm))
    return outcomes


def main(argv: list[str] | None = None) -> int:
    """Command-line entry point. Returns 0 if every attack was repelled."""
    parser = argparse.ArgumentParser(
        prog="python -m pqpki.attacks",
        description=(
            "Run certificate-level attacks against this PKI and report "
            "whether each was correctly refused."
        ),
    )
    parser.add_argument(
        "--algorithm",
        action="append",
        dest="algorithms",
        metavar="NAME",
        help="attack only this algorithm; repeatable. Defaults to all.",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="print each attack's description and outcome detail",
    )
    args = parser.parse_args(argv)

    names = args.algorithms if args.algorithms else list_algorithms()
    unknown = [name for name in names if name not in list_algorithms()]
    if unknown:
        parser.error(
            f"unknown algorithm(s) {unknown}; registered: {list_algorithms()}"
        )

    total = 0
    held = 0
    for algorithm in names:
        print(f"\n=== {algorithm} ===")
        for outcome in run_all(algorithm):
            total += 1
            held += outcome.defended
            status = "PASS" if outcome.defended else "FAIL"
            print(f"  [{status}] {outcome.name}")
            if args.verbose or not outcome.defended:
                print(f"         {outcome.description}")
                print(f"         -> {outcome.detail}")

    print(f"\n{held}/{total} attacks repelled.")
    return 0 if held == total else 1


if __name__ == "__main__":  # pragma: no cover - exercised via tests
    raise SystemExit(main())
