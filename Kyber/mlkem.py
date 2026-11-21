# ML-KEM, the actual key encapsulation mechanism (FIPS 203, sections 6 and 7).
#
# This is a thin layer on top of K-PKE: encapsulation encrypts a random
# message and hashes it into the shared key, decapsulation decrypts, re-encrypts
# and checks it gets the same ciphertext back (the Fujisaki-Okamoto transform).
#
# The *_internal functions are the deterministic versions from section 6 that
# take their randomness as an argument. They're there for testing against
# known answer vectors -- normal callers should use KeyGen/Encaps/Decaps.

import hmac
import os

from auxiliary import H, J, G, ByteEncode, ByteDecode
from kpke import (
    PARAMS,
    _get_params,
    ek_length,
    ciphertext_length,
    KPKE_KeyGen,
    KPKE_Encrypt,
    KPKE_Decrypt,
)


# Sizes in bytes (Table 3). The ML-KEM ek and ciphertext are the same as for
# K-PKE, only the decapsulation key is bigger.
def mlkem_dk_length(param_set):
    k = _get_params(param_set)[0]
    return 768 * k + 96


def shared_key_length():
    return 32


def _split_dk(dk, k):
    """Pull dk apart into (dk_pke, ek_pke, h, z), steps 1-4 of Algorithm 18."""
    dk_pke = dk[:384 * k]
    ek_pke = dk[384 * k:768 * k + 32]
    h = dk[768 * k + 32:768 * k + 64]
    z = dk[768 * k + 64:768 * k + 96]
    return dk_pke, ek_pke, h, z


def _select(a, b, use_b):
    """Return b if use_b else a, without branching on use_b.

    Python isn't going to be constant time no matter what, but this at least
    keeps the shape of what a real implementation would do instead of an
    obvious if/else on secret data.
    """
    assert len(a) == len(b)
    mask = -int(use_b) & 0xFF  # 0x00 or 0xFF
    return bytes(x ^ (mask & (x ^ y)) for x, y in zip(a, b))


# ---- input checking (7.2 / 7.3) ----

def check_ek(ek, param_set):
    """Encapsulation key check from section 7.2. Raises ValueError on failure."""
    k = _get_params(param_set)[0]

    # type check
    if not isinstance(ek, (bytes, bytearray)) or len(ek) != 384 * k + 32:
        raise ValueError(f"ek should be {384 * k + 32} bytes for {param_set}")

    # modulus check: every 12-bit value has to be < q, otherwise the
    # decode/encode roundtrip won't give back the same bytes
    t_bytes = bytes(ek[:384 * k])
    test = b"".join(ByteEncode(ByteDecode(t_bytes[i:i + 384], 12), 12)
                    for i in range(0, 384 * k, 384))
    if test != t_bytes:
        raise ValueError("ek failed the modulus check")


def check_dk(dk, param_set):
    """The decapsulation key half of the section 7.3 check (type + hash check).

    Raises ValueError on failure.
    """
    k = _get_params(param_set)[0]

    # decapsulation key type check
    if not isinstance(dk, (bytes, bytearray)) or len(dk) != 768 * k + 96:
        raise ValueError(f"dk should be {768 * k + 96} bytes for {param_set}")

    # hash check: H(ek) stored in dk has to match the ek stored in dk
    _, ek_pke, h, _ = _split_dk(bytes(dk), k)
    if H(ek_pke) != h:
        raise ValueError("dk failed the hash check")


def check_decaps_input(dk, c, param_set):
    """Decapsulation input check from section 7.3. Raises ValueError on failure."""
    # ciphertext type check
    c_len = ciphertext_length(param_set)
    if not isinstance(c, (bytes, bytearray)) or len(c) != c_len:
        raise ValueError(f"c should be {c_len} bytes for {param_set}")

    check_dk(dk, param_set)


def check_key_pair(ek, dk, param_set, d=None, z=None):
    """Key pair check from section 7.1. Raises ValueError on failure.

    Optional for someone who got (ek, dk) from somewhere else instead of
    generating it themselves. If the seed (d, z) is available, pass it in and
    it gets checked too. Passing these checks doesn't prove the pair came out
    of KeyGen, it just catches corrupted or mismatched keys.
    """
    _get_params(param_set)
    if (d is None) != (z is None):
        raise ValueError("pass both d and z, or neither")

    # 1. seed consistency
    if d is not None:
        if (bytes(ek), bytes(dk)) != MLKEM_KeyGen_internal(d, z, param_set):
            raise ValueError("(ek, dk) doesn't match the seed (d, z)")

    # 2./3. the same checks Encaps and Decaps do on their inputs
    check_ek(ek, param_set)
    check_dk(dk, param_set)

    # 4. pair-wise consistency: both sides have to land on the same shared key
    m = os.urandom(32)
    K, c = MLKEM_Encaps_internal(bytes(ek), m, param_set)
    K_prime = MLKEM_Decaps_internal(bytes(dk), c, param_set)
    if not hmac.compare_digest(K, K_prime):
        raise ValueError("pair-wise consistency check failed, K != K'")


# ---- internal algorithms (section 6) ----

def MLKEM_KeyGen_internal(d, z, param_set):
    """Algorithm 16. Takes two 32 byte seeds, returns (ek, dk)."""
    _get_params(param_set)  # validate param_set up front
    assert len(d) == 32, "d must be 32 bytes"
    assert len(z) == 32, "z must be 32 bytes"

    ek_pke, dk_pke = KPKE_KeyGen(d, param_set)
    ek = ek_pke
    dk = dk_pke + ek + H(ek) + z
    return ek, dk


def MLKEM_Encaps_internal(ek, m, param_set):
    """Algorithm 17. Returns (K, c) using m as the randomness."""
    assert len(ek) == ek_length(param_set), \
        f"ek should be {ek_length(param_set)} bytes, got {len(ek)}"
    assert len(m) == 32, "m must be 32 bytes"

    # K is the shared key, r is the randomness for K-PKE.Encrypt
    K, r = G(m + H(ek))
    c = KPKE_Encrypt(ek, m, r, param_set)
    return K, c


def MLKEM_Decaps_internal(dk, c, param_set):
    """Algorithm 18. Returns the shared key K' for ciphertext c."""
    k = _get_params(param_set)[0]
    assert len(dk) == 768 * k + 96, \
        f"dk should be {768 * k + 96} bytes, got {len(dk)}"
    assert len(c) == ciphertext_length(param_set), \
        f"c should be {ciphertext_length(param_set)} bytes, got {len(c)}"

    dk_pke, ek_pke, h, z = _split_dk(dk, k)

    m_prime = KPKE_Decrypt(dk_pke, c, param_set)
    K_prime, r_prime = G(m_prime + h)
    K_bar = J(z + c)  # implicit rejection key

    # re-encrypt and make sure we get the same ciphertext back. If not, hand
    # back K_bar instead of an error so an attacker can't tell the difference.
    c_prime = KPKE_Encrypt(ek_pke, m_prime, r_prime, param_set)
    matches = hmac.compare_digest(c, c_prime)
    return _select(K_bar, K_prime, matches)


# ---- external API (section 7) ----

def MLKEM_KeyGen(param_set):
    """Algorithm 19. Returns (ek, dk) using fresh randomness."""
    d = os.urandom(32)
    z = os.urandom(32)
    # os.urandom raises instead of returning NULL, so the spec's
    # "return an error if random bit generation failed" is handled for us
    return MLKEM_KeyGen_internal(d, z, param_set)


def MLKEM_Encaps(ek, param_set):
    """Algorithm 20. Returns (K, c). ek is checked first (section 7.2)."""
    check_ek(ek, param_set)
    m = os.urandom(32)
    return MLKEM_Encaps_internal(bytes(ek), m, param_set)


def MLKEM_Decaps(dk, c, param_set):
    """Algorithm 21. Returns K'. dk and c are checked first (section 7.3)."""
    check_decaps_input(dk, c, param_set)
    return MLKEM_Decaps_internal(bytes(dk), bytes(c), param_set)


if __name__ == "__main__":
    for name in PARAMS:
        ek, dk = MLKEM_KeyGen(name)
        K, c = MLKEM_Encaps(ek, name)
        assert MLKEM_Decaps(dk, c, name) == K
        check_key_pair(ek, dk, name)
        print(f"{name}: ok  (ek={len(ek)}, dk={len(dk)}, c={len(c)})")
