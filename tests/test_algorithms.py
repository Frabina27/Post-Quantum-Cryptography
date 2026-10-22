"""Tests for the crypto-agility layer.

Parameterized over every name in ``list_algorithms()``, so the classical and
post-quantum specs are exercised identically. Registering a new algorithm is
enough to get it covered here.
"""

from __future__ import annotations

import ast
import pathlib

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa

from pqpki import algorithms as alg
from pqpki.errors import (
    AlgorithmError,
    PQPKIError,
    UnknownAlgorithmError,
    UnsupportedKeyTypeError,
)

ALL_ALGORITHMS = alg.list_algorithms()

# RSA-2048 keygen is slow and highly variable, and several tests need a key per
# algorithm. Generate each one once per session and share it. Nothing in these
# tests mutates a key, so sharing is safe.
_KEY_CACHE: dict[str, object] = {}


@pytest.fixture(params=ALL_ALGORITHMS)
def spec(request: pytest.FixtureRequest) -> alg.AlgorithmSpec:
    """Each registered AlgorithmSpec in turn."""
    return alg.get_algorithm(request.param)


@pytest.fixture
def key(spec: alg.AlgorithmSpec):
    """A private key for ``spec``, generated at most once per session."""
    if spec.name not in _KEY_CACHE:
        _KEY_CACHE[spec.name] = spec.generate_key()
    return _KEY_CACHE[spec.name]


# --------------------------------------------------------------------------
# Registry contents
# --------------------------------------------------------------------------


def test_registry_contains_every_required_algorithm() -> None:
    """The five algorithms the module contract promises, supported day one."""
    assert set(ALL_ALGORITHMS) == {
        "ecdsa-p256",
        "rsa-2048",
        "ml-dsa-44",
        "ml-dsa-65",
        "ml-dsa-87",
    }


def test_list_algorithms_returns_a_copy() -> None:
    """Mutating the returned list must not corrupt the registry."""
    first = alg.list_algorithms()
    first.append("bogus")
    assert "bogus" not in alg.list_algorithms()


@pytest.mark.parametrize(
    ("name", "expected_oid"),
    [
        ("ml-dsa-44", "2.16.840.1.101.3.4.3.17"),
        ("ml-dsa-65", "2.16.840.1.101.3.4.3.18"),
        ("ml-dsa-87", "2.16.840.1.101.3.4.3.19"),
    ],
)
def test_ml_dsa_oids_match_rfc_9881(name: str, expected_oid: str) -> None:
    """RFC 9881 section 4 assigns these exact OIDs. Hardcoded on purpose."""
    spec = alg.get_algorithm(name)
    assert spec.oid == expected_oid
    # For ML-DSA the signature OID and the SPKI key OID are the same value.
    assert spec.key_oid == expected_oid


@pytest.mark.parametrize(
    ("name", "is_pq"),
    [
        ("ecdsa-p256", False),
        ("rsa-2048", False),
        ("ml-dsa-44", True),
        ("ml-dsa-65", True),
        ("ml-dsa-87", True),
    ],
)
def test_post_quantum_flag(name: str, is_pq: bool) -> None:
    assert alg.get_algorithm(name).is_post_quantum is is_pq


def test_spec_name_matches_registry_key(spec: alg.AlgorithmSpec) -> None:
    assert alg.get_algorithm(spec.name) is spec


def test_spec_is_immutable(spec: alg.AlgorithmSpec) -> None:
    """A spec handed to another module must not be mutable by it."""
    with pytest.raises((AttributeError, TypeError)):
        spec.name = "tampered"  # type: ignore[misc]


def test_oids_are_well_formed(spec: alg.AlgorithmSpec) -> None:
    for oid in (spec.oid, spec.key_oid):
        parts = oid.split(".")
        assert len(parts) >= 3, oid
        assert all(p.isdigit() for p in parts), oid


def test_signature_oids_are_unique_across_registry() -> None:
    """Otherwise spec_for_signature_oid silently resolves to the wrong spec."""
    oids = [alg.get_algorithm(n).oid for n in ALL_ALGORITHMS]
    assert len(oids) == len(set(oids))


# --------------------------------------------------------------------------
# The signing seam
# --------------------------------------------------------------------------


def test_sign_args_shape(spec: alg.AlgorithmSpec) -> None:
    """One positional argument, splattable into pyca's .sign(key, ...)."""
    args = spec.sign_args()
    assert isinstance(args, tuple)
    assert len(args) == 1


def test_sign_args_hash_matches_family(spec: alg.AlgorithmSpec) -> None:
    """Pure ML-DSA takes None; hash-then-sign takes a real hash instance."""
    (hash_arg,) = spec.sign_args()
    if spec.is_post_quantum:
        assert hash_arg is None
    else:
        assert isinstance(hash_arg, hashes.SHA256)


def test_hash_algorithm_returns_a_fresh_instance(spec: alg.AlgorithmSpec) -> None:
    """Shared mutable hash state across calls would be a latent aliasing bug."""
    first, second = spec.hash_algorithm, spec.hash_algorithm
    if spec.is_post_quantum:
        assert first is None and second is None
    else:
        assert first is not second


def test_generated_key_can_actually_sign_and_verify(
    spec: alg.AlgorithmSpec, key
) -> None:
    """Real crypto, no mocks: sign_args must produce a usable signing call.

    This is the test that would catch a wrong hash argument, since pyca raises
    rather than silently producing a bad signature.
    """
    message = b"pqpki agility layer probe"
    (hash_arg,) = spec.sign_args()
    if hash_arg is None:
        signature = key.sign(message)
        key.public_key().verify(signature, message)
    else:
        from cryptography.hazmat.primitives.asymmetric import ec, padding

        if isinstance(hash_arg, hashes.SHA256) and hasattr(key, "curve"):
            signature = key.sign(message, ec.ECDSA(hash_arg))
            key.public_key().verify(signature, message, ec.ECDSA(spec.hash_algorithm))
        else:
            signature = key.sign(message, padding.PKCS1v15(), hash_arg)
            key.public_key().verify(
                signature, message, padding.PKCS1v15(), spec.hash_algorithm
            )
    assert len(signature) > 0


# --------------------------------------------------------------------------
# Key generation and reverse lookup
# --------------------------------------------------------------------------


def test_generate_key_round_trips_through_spec_for_key(
    spec: alg.AlgorithmSpec, key
) -> None:
    """Forward and reverse lookup must agree, or validate.py mislabels links."""
    assert alg.spec_for_key(key) is spec
    assert alg.spec_for_key(key.public_key()) is spec
    assert spec.matches_key(key)
    assert spec.matches_key(key.public_key())


def test_specs_do_not_claim_each_others_keys(spec: alg.AlgorithmSpec, key) -> None:
    """Each identity predicate must be exclusive."""
    for other_name in ALL_ALGORITHMS:
        if other_name != spec.name:
            assert not alg.get_algorithm(other_name).matches_key(key)


def test_public_key_size_is_positive_and_stable(spec: alg.AlgorithmSpec, key) -> None:
    size = alg.public_key_size(key)
    assert size > 0
    assert alg.public_key_size(key.public_key()) == size


def test_ml_dsa_keys_are_larger_than_classical() -> None:
    """A sanity check on the comparison the whole project exists to make."""
    classical = max(
        alg.public_key_size(_cached(n)) for n in ALL_ALGORITHMS
        if not alg.get_algorithm(n).is_post_quantum
    )
    pq = min(
        alg.public_key_size(_cached(n)) for n in ALL_ALGORITHMS
        if alg.get_algorithm(n).is_post_quantum
    )
    assert pq > classical


def _cached(name: str):
    if name not in _KEY_CACHE:
        _KEY_CACHE[name] = alg.get_algorithm(name).generate_key()
    return _KEY_CACHE[name]


def test_ml_dsa_sizes_increase_with_parameter_set() -> None:
    sizes = [alg.public_key_size(_cached(n)) for n in ("ml-dsa-44", "ml-dsa-65", "ml-dsa-87")]
    assert sizes == sorted(sizes)
    assert len(set(sizes)) == 3


# --------------------------------------------------------------------------
# Instrumentation
# --------------------------------------------------------------------------


def test_collector_receives_one_generate_key_event(spec: alg.AlgorithmSpec) -> None:
    events: list[alg.MetricEvent] = []
    key = spec.generate_key(collector=events.append)

    assert len(events) == 1
    (event,) = events
    assert event.operation == "generate_key"
    assert event.algorithm == spec.name
    assert event.duration_s >= 0.0
    assert event.artifact_bytes == alg.public_key_size(key)


def test_collector_is_optional(spec: alg.AlgorithmSpec) -> None:
    """The plain contract signature must still work with no collector."""
    assert spec.generate_key() is not None


def test_metric_event_is_immutable() -> None:
    event = alg.MetricEvent("generate_key", "ml-dsa-65", 0.1, 1952)
    with pytest.raises((AttributeError, TypeError)):
        event.duration_s = 99.0  # type: ignore[misc]


def test_collector_exceptions_are_not_swallowed() -> None:
    """A broken harness must fail loudly, not skew a benchmark silently."""

    def boom(_: alg.MetricEvent) -> None:
        raise RuntimeError("collector exploded")

    with pytest.raises(RuntimeError, match="collector exploded"):
        alg.get_algorithm("ml-dsa-44").generate_key(collector=boom)


# --------------------------------------------------------------------------
# Error paths
# --------------------------------------------------------------------------


def test_get_algorithm_rejects_unknown_name() -> None:
    with pytest.raises(UnknownAlgorithmError) as excinfo:
        alg.get_algorithm("ml-dsa-99")
    message = str(excinfo.value)
    assert "ml-dsa-99" in message
    # The message must help: it lists what is actually registered.
    for name in ALL_ALGORITHMS:
        assert name in message


def test_get_algorithm_is_case_sensitive() -> None:
    """No silent normalization; a wrong name is a wrong name."""
    with pytest.raises(UnknownAlgorithmError):
        alg.get_algorithm("ML-DSA-65")


def test_spec_for_key_rejects_unregistered_key_type() -> None:
    with pytest.raises(UnsupportedKeyTypeError, match="Ed25519"):
        alg.spec_for_key(ed25519.Ed25519PrivateKey.generate())


def test_spec_for_key_rejects_unregistered_rsa_size() -> None:
    """An RSA key of the wrong size must not be mistaken for rsa-2048."""
    weak = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    with pytest.raises(UnsupportedKeyTypeError, match="1024"):
        alg.spec_for_key(weak)


def test_spec_for_signature_oid_round_trips(spec: alg.AlgorithmSpec) -> None:
    assert alg.spec_for_signature_oid(spec.oid) is spec


def test_spec_for_signature_oid_rejects_unknown() -> None:
    with pytest.raises(UnsupportedKeyTypeError, match="1.2.3.4"):
        alg.spec_for_signature_oid("1.2.3.4")


def test_every_error_derives_from_the_base() -> None:
    """One except clause must be enough to catch anything this package raises."""
    assert issubclass(UnknownAlgorithmError, AlgorithmError)
    assert issubclass(AlgorithmError, PQPKIError)
    assert issubclass(UnsupportedKeyTypeError, AlgorithmError)


# --------------------------------------------------------------------------
# Architectural guard
# --------------------------------------------------------------------------
#
# Phase 3 of this module only works if nothing outside algorithms.py knows an
# algorithm name. That is an architectural property, so it gets an
# architectural test rather than a code review note.

_PACKAGE_DIR = pathlib.Path(alg.__file__).parent

_FORBIDDEN_STRINGS = (
    "ml-dsa",
    "ecdsa-p256",
    "rsa-2048",
    "2.16.840.1.101.3.4.3",
    "1.2.840.10045",
    "1.2.840.113549",
)
_FORBIDDEN_NAMES = (
    "MLDSA44PrivateKey",
    "MLDSA65PrivateKey",
    "MLDSA87PrivateKey",
    "SECP256R1",
    "generate_private_key",
)


def _code_strings_and_names(path: pathlib.Path) -> tuple[list[str], list[str]]:
    """Return string literals and identifiers in ``path``, ignoring docstrings.

    Docstrings and comments are prose and may legitimately mention an
    algorithm by name; only code counts. A bare string expression statement is
    treated as a docstring, which covers module, class, and function
    docstrings as well as the attribute-docstring style used in this package.
    """
    tree = ast.parse(path.read_text(encoding="utf-8"))
    docstring_nodes = {
        id(node.value)
        for node in ast.walk(tree)
        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant)
    }
    strings = [
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and id(node) not in docstring_nodes
    ]
    names = [
        node.id for node in ast.walk(tree) if isinstance(node, ast.Name)
    ] + [node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)]
    return strings, names


@pytest.mark.parametrize(
    "module_path",
    [p for p in sorted(_PACKAGE_DIR.glob("*.py")) if p.name != "algorithms.py"],
    ids=lambda p: p.name,
)
def test_no_algorithm_knowledge_outside_the_agility_layer(
    module_path: pathlib.Path,
) -> None:
    """Only algorithms.py may name an algorithm, curve, key size, or OID."""
    strings, names = _code_strings_and_names(module_path)

    for literal in strings:
        lowered = literal.lower()
        for forbidden in _FORBIDDEN_STRINGS:
            assert forbidden not in lowered, (
                f"{module_path.name} contains the algorithm-specific literal "
                f"{forbidden!r} in {literal!r}. Route it through "
                f"pqpki.algorithms instead."
            )

    for identifier in names:
        assert identifier not in _FORBIDDEN_NAMES, (
            f"{module_path.name} references {identifier!r} directly. Only "
            f"algorithms.py may touch concrete key types."
        )
