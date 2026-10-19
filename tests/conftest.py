"""Shared fixtures.

The expensive thing in this suite is key generation, and the suite is
parameterized over every registered algorithm. RSA-2048 in particular is slow
and highly variable. So a full root -> intermediate -> leaf hierarchy is built
once per algorithm per session and shared by every test that needs one.

Nothing in the tests mutates a hierarchy, with one exception: revocation state
lives on the CA object, so any test that revokes must build its own CA rather
than touching the session-scoped one. Use the ``fresh_hierarchy`` fixture for
that.
"""

from __future__ import annotations

import dataclasses

import pytest
from cryptography import x509

from pqpki import CertificateAuthority, generate_csr, list_algorithms
from pqpki.algorithms import AlgorithmSpec, get_algorithm

ALL_ALGORITHMS = list_algorithms()

LEAF_DNS_NAME = "leaf.pqpki.example"


@dataclasses.dataclass
class Hierarchy:
    """A complete three-link chain, all signed with one algorithm."""

    algorithm: str
    root_ca: CertificateAuthority
    intermediate_ca: CertificateAuthority
    leaf: x509.Certificate
    leaf_key: object

    @property
    def spec(self) -> AlgorithmSpec:
        return get_algorithm(self.algorithm)

    @property
    def root(self) -> x509.Certificate:
        return self.root_ca.certificate

    @property
    def intermediate(self) -> x509.Certificate:
        return self.intermediate_ca.certificate

    @property
    def chain(self) -> list[x509.Certificate]:
        """Leaf first, root last."""
        return [self.leaf, self.intermediate, self.root]


def build_hierarchy(
    algorithm: str, *, collector=None, name_prefix: str = "pqpki Test"
) -> Hierarchy:
    """Build root -> intermediate -> leaf, all using ``algorithm``.

    This is the code path Phase 3 is about: nothing here mentions whether the
    algorithm is classical or post-quantum.

    Args:
        name_prefix: Distinguishes one hierarchy's subject names from
            another's. This matters more than it looks: path building matches
            issuer to subject *by name*, so two hierarchies built with the same
            prefix are genuinely ambiguous to a validator, and a test that
            means "a certificate from an unrelated CA" must pass a different
            prefix or it will instead be testing signature failure against a
            same-named impostor.
    """
    root_ca = CertificateAuthority.create_root(
        f"{name_prefix} Root", algorithm, validity_days=3650, collector=collector
    )

    intermediate_key = root_ca.algorithm.generate_key(collector=collector)
    intermediate_csr = generate_csr(f"{name_prefix} Intermediate", intermediate_key)
    intermediate_cert = root_ca.issue_intermediate(intermediate_csr, validity_days=1825)
    intermediate_ca = CertificateAuthority(
        intermediate_cert, intermediate_key, collector=collector
    )

    leaf_key = root_ca.algorithm.generate_key(collector=collector)
    leaf_csr = generate_csr(f"{name_prefix} Leaf", leaf_key, san_dns=[LEAF_DNS_NAME])
    leaf = intermediate_ca.issue_end_entity(leaf_csr, validity_days=90)

    return Hierarchy(algorithm, root_ca, intermediate_ca, leaf, leaf_key)


@pytest.fixture(scope="session", params=ALL_ALGORITHMS)
def algorithm(request: pytest.FixtureRequest) -> str:
    """Each registered algorithm name in turn, for the whole session."""
    return request.param


@pytest.fixture(scope="session")
def hierarchy(algorithm: str) -> Hierarchy:
    """A shared, read-only hierarchy for ``algorithm``.

    Do not revoke anything on these CAs; they are shared across tests.
    """
    return build_hierarchy(algorithm)


@pytest.fixture
def fresh_hierarchy(algorithm: str) -> Hierarchy:
    """A throwaway hierarchy for tests that mutate CA state.

    Rebuilt per test, so it costs real key generation. Only use it where the
    shared one genuinely will not do -- revocation being the main case.
    """
    return build_hierarchy(algorithm)
