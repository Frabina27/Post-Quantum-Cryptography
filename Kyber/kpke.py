"""
K-PKE Component Scheme for ML-KEM (FIPS 203)
============================================
Implements Section 5 of NIST FIPS 203, "Module-Lattice-Based
Key-Encapsulation Mechanism Standard" (August 13, 2024).

K-PKE is the underlying public-key encryption scheme used to build ML-KEM.
It is NOT approved for use as a stand-alone scheme (Section 5); it is only
a building block for the ML-KEM algorithms in Sections 6 and 7.

Sections covered:
    Table 2       Approved parameter sets (ML-KEM-512 / 768 / 1024)
    5.1  Algorithm 13 — K-PKE.KeyGen(d)
    5.2  Algorithm 14 — K-PKE.Encrypt(ek_PKE, m, r)
    5.3  Algorithm 15 — K-PKE.Decrypt(dk_PKE, c)
"""

from typing import Dict, List, Tuple

from auxiliary import (
    q,
    PRF,
    G,
    ByteEncode,
    ByteDecode,
    Compress,
    Decompress,
    SampleNTT,
    SamplePolyCBD,
    NTT,
    NTT_inv,
    poly_add,
    poly_sub,
    vec_add,
    mat_vec_mul,
    mat_T_vec_mul,
    inner_product,
    ntt_vec,
    intt_vec,
)

# ---------------------------------------------------------------------------
# Table 2 — Approved parameter sets for ML-KEM (Section 8)
#
#   k    : module rank (dimension of vectors / matrix)
#   eta1 : CBD parameter for s, e (KeyGen) and y (Encrypt)
#   eta2 : CBD parameter for e1, e2 (Encrypt)
#   du   : compression bits for ciphertext component u
#   dv   : compression bits for ciphertext component v
# ---------------------------------------------------------------------------
PARAMS: Dict[str, Dict[str, int]] = {
    "ML-KEM-512":  {"k": 2, "eta1": 3, "eta2": 2, "du": 10, "dv": 4},
    "ML-KEM-768":  {"k": 3, "eta1": 2, "eta2": 2, "du": 10, "dv": 4},
    "ML-KEM-1024": {"k": 4, "eta1": 2, "eta2": 2, "du": 11, "dv": 5},
}


def _get_params(param_set: str) -> Tuple[int, int, int, int, int]:
    """Look up (k, eta1, eta2, du, dv) for a named parameter set."""
    if param_set not in PARAMS:
        raise ValueError(
            f"Unknown parameter set {param_set!r}; "
            f"expected one of {sorted(PARAMS)}"
        )
    p = PARAMS[param_set]
    return p["k"], p["eta1"], p["eta2"], p["du"], p["dv"]


# ---------------------------------------------------------------------------
# Byte lengths (Table 3 / Section 5)
#
#   ek_PKE : 384k + 32 bytes   (ByteEncode_12(t̂) || ρ)
#   dk_PKE : 384k bytes        (ByteEncode_12(ŝ))
#   c      : 32(du·k + dv)     (c1 || c2)
# ---------------------------------------------------------------------------
def ek_length(param_set: str) -> int:
    k, _, _, _, _ = _get_params(param_set)
    return 384 * k + 32


def dk_length(param_set: str) -> int:
    k, _, _, _, _ = _get_params(param_set)
    return 384 * k


def ciphertext_length(param_set: str) -> int:
    k, _, _, du, dv = _get_params(param_set)
    return 32 * (du * k + dv)


# ---------------------------------------------------------------------------
# Helpers: apply ByteEncode / ByteDecode / Compress / Decompress to
# polynomials and vectors.  FIPS 203 (Section 2.4.8 / 4.2.1) extends these
# functions to vectors by applying them coordinate-wise and concatenating
# the resulting byte arrays.
# ---------------------------------------------------------------------------
def _compress_poly(f: List[int], d: int) -> List[int]:
    return [Compress(x, d) for x in f]


def _decompress_poly(f: List[int], d: int) -> List[int]:
    return [Decompress(y, d) for y in f]


def _encode_vec(v: List[List[int]], d: int) -> bytes:
    """ByteEncode_d applied to each polynomial in v, outputs concatenated."""
    return b"".join(ByteEncode(poly, d) for poly in v)


def _decode_vec(B: bytes, d: int, k: int) -> List[List[int]]:
    """Inverse of _encode_vec: split B into k chunks of 32d bytes and decode."""
    chunk = 32 * d
    assert len(B) == k * chunk, f"expected {k * chunk} bytes, got {len(B)}"
    return [ByteDecode(B[i * chunk:(i + 1) * chunk], d) for i in range(k)]


def _sample_matrix(rho: bytes, k: int) -> List[List[List[int]]]:
    """
    Generate the k×k matrix Â in the NTT domain from the 32-byte seed ρ.
    (Algorithm 13, lines 3–7; Algorithm 14, lines 4–8)

        for i ← 0; i < k; i++:
            for j ← 0; j < k; j++:
                Â[i, j] ← SampleNTT(ρ || j || i)

    NOTE: the column index j is appended BEFORE the row index i.
    """
    assert len(rho) == 32, "rho must be 32 bytes"
    return [
        [SampleNTT(rho + bytes([j, i])) for j in range(k)]
        for i in range(k)
    ]


# ===========================================================================
# Algorithm 13 — K-PKE.KeyGen(d)
# ===========================================================================

def KPKE_KeyGen(d: bytes, param_set: str) -> Tuple[bytes, bytes]:
    """
    Algorithm 13 — K-PKE.KeyGen(d)

    Uses randomness to generate an encryption key and a corresponding
    decryption key.

        Input:  randomness d ∈ B^32.
        Output: encryption key ek_PKE ∈ B^{384k+32}.
        Output: decryption key dk_PKE ∈ B^{384k}.

    Pseudocode (FIPS 203, Algorithm 13):
         1: (ρ, σ) ← G(d || k)            ▷ expand 32+1 bytes to two 32-byte seeds
         2: N ← 0
         3: for i ← 0; i < k; i++:         ▷ generate matrix Â ∈ (Z_q^256)^{k×k}
         4:     for j ← 0; j < k; j++:
         5:         Â[i, j] ← SampleNTT(ρ || j || i)
         8: for i ← 0; i < k; i++:         ▷ generate s ∈ (Z_q^256)^k
         9:     s[i] ← SamplePolyCBD_η1(PRF_η1(σ, N))
        10:     N ← N + 1
        12: for i ← 0; i < k; i++:         ▷ generate e ∈ (Z_q^256)^k
        13:     e[i] ← SamplePolyCBD_η1(PRF_η1(σ, N))
        14:     N ← N + 1
        16: ŝ ← NTT(s)
        17: ê ← NTT(e)
        18: t̂ ← Â ∘ ŝ + ê
        19: ek_PKE ← ByteEncode_12(t̂) || ρ
        20: dk_PKE ← ByteEncode_12(ŝ)
        21: return (ek_PKE, dk_PKE)

    Parameters
    ----------
    d         : bytes  32 bytes of randomness.
    param_set : str    One of "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024".
    """
    k, eta1, _, _, _ = _get_params(param_set)
    assert len(d) == 32, "d must be 32 bytes"

    # Line 1 — domain separation: append the single byte k (new in FIPS 203)
    rho, sigma = G(d + bytes([k]))
    N = 0

    # Lines 3–7
    A_hat = _sample_matrix(rho, k)

    # Lines 8–11
    s = []
    for _ in range(k):
        s.append(SamplePolyCBD(PRF(eta1, sigma, N), eta1))
        N += 1

    # Lines 12–15
    e = []
    for _ in range(k):
        e.append(SamplePolyCBD(PRF(eta1, sigma, N), eta1))
        N += 1

    # Lines 16–18
    s_hat = ntt_vec(s)
    e_hat = ntt_vec(e)
    t_hat = vec_add(mat_vec_mul(A_hat, s_hat), e_hat)

    # Lines 19–20
    ek_pke = _encode_vec(t_hat, 12) + rho
    dk_pke = _encode_vec(s_hat, 12)
    return ek_pke, dk_pke


# ===========================================================================
# Algorithm 14 — K-PKE.Encrypt(ek_PKE, m, r)
# ===========================================================================

def KPKE_Encrypt(ek_pke: bytes, m: bytes, r: bytes, param_set: str) -> bytes:
    """
    Algorithm 14 — K-PKE.Encrypt(ek_PKE, m, r)

    Uses the encryption key to encrypt a plaintext message using the
    randomness r.

        Input:  encryption key ek_PKE ∈ B^{384k+32}.
        Input:  message m ∈ B^32.
        Input:  randomness r ∈ B^32.
        Output: ciphertext c ∈ B^{32(du·k + dv)}.

    Pseudocode (FIPS 203, Algorithm 14):
         1: N ← 0
         2: t̂ ← ByteDecode_12(ek_PKE[0 : 384k])     ▷ run ByteDecode_12 k times
         3: ρ ← ek_PKE[384k : 384k + 32]            ▷ extract 32-byte seed
         4: for i ← 0; i < k; i++:                   ▷ re-generate matrix Â
         5:     for j ← 0; j < k; j++:
         6:         Â[i, j] ← SampleNTT(ρ || j || i)
         9: for i ← 0; i < k; i++:                   ▷ generate y ∈ (Z_q^256)^k
        10:     y[i] ← SamplePolyCBD_η1(PRF_η1(r, N))
        11:     N ← N + 1
        13: for i ← 0; i < k; i++:                   ▷ generate e1 ∈ (Z_q^256)^k
        14:     e1[i] ← SamplePolyCBD_η2(PRF_η2(r, N))
        15:     N ← N + 1
        17: e2 ← SamplePolyCBD_η2(PRF_η2(r, N))     ▷ sample e2 ∈ Z_q^256
        18: ŷ ← NTT(y)
        19: u ← NTT^{-1}(Â^T ∘ ŷ) + e1
        20: μ ← Decompress_1(ByteDecode_1(m))
        21: v ← NTT^{-1}(t̂^T ∘ ŷ) + e2 + μ
        22: c1 ← ByteEncode_du(Compress_du(u))
        23: c2 ← ByteEncode_dv(Compress_dv(v))
        24: return c ← (c1 || c2)

    Parameters
    ----------
    ek_pke    : bytes  Encryption key of length 384k + 32.
    m         : bytes  32-byte plaintext message.
    r         : bytes  32 bytes of randomness.
    param_set : str    One of "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024".
    """
    k, eta1, eta2, du, dv = _get_params(param_set)
    assert len(ek_pke) == 384 * k + 32, \
        f"ek_PKE must be {384 * k + 32} bytes, got {len(ek_pke)}"
    assert len(m) == 32, "m must be 32 bytes"
    assert len(r) == 32, "r must be 32 bytes"

    # Lines 1–3
    N = 0
    t_hat = _decode_vec(ek_pke[:384 * k], 12, k)
    rho = ek_pke[384 * k:384 * k + 32]

    # Lines 4–8
    A_hat = _sample_matrix(rho, k)

    # Lines 9–12
    y = []
    for _ in range(k):
        y.append(SamplePolyCBD(PRF(eta1, r, N), eta1))
        N += 1

    # Lines 13–16
    e1 = []
    for _ in range(k):
        e1.append(SamplePolyCBD(PRF(eta2, r, N), eta2))
        N += 1

    # Line 17
    e2 = SamplePolyCBD(PRF(eta2, r, N), eta2)

    # Lines 18–19
    y_hat = ntt_vec(y)
    u = vec_add(intt_vec(mat_T_vec_mul(A_hat, y_hat)), e1)

    # Line 20 — each message bit becomes 0 or ⌈q/2⌋ = 1665
    mu = _decompress_poly(ByteDecode(m, 1), 1)

    # Line 21
    v = poly_add(poly_add(NTT_inv(inner_product(t_hat, y_hat)), e2), mu)

    # Lines 22–24
    c1 = b"".join(ByteEncode(_compress_poly(poly, du), du) for poly in u)
    c2 = ByteEncode(_compress_poly(v, dv), dv)
    return c1 + c2


# ===========================================================================
# Algorithm 15 — K-PKE.Decrypt(dk_PKE, c)
# ===========================================================================

def KPKE_Decrypt(dk_pke: bytes, c: bytes, param_set: str) -> bytes:
    """
    Algorithm 15 — K-PKE.Decrypt(dk_PKE, c)

    Uses the decryption key to decrypt a ciphertext.

        Input:  decryption key dk_PKE ∈ B^{384k}.
        Input:  ciphertext c ∈ B^{32(du·k + dv)}.
        Output: message m ∈ B^32.

    Pseudocode (FIPS 203, Algorithm 15):
        1: c1 ← c[0 : 32·du·k]
        2: c2 ← c[32·du·k : 32(du·k + dv)]
        3: u' ← Decompress_du(ByteDecode_du(c1))    ▷ run k times
        4: v' ← Decompress_dv(ByteDecode_dv(c2))
        5: ŝ ← ByteDecode_12(dk_PKE)                ▷ run k times
        6: w ← v' − NTT^{-1}(ŝ^T ∘ NTT(u'))
        7: m ← ByteEncode_1(Compress_1(w))         ▷ decode plaintext m from w
        8: return m

    Parameters
    ----------
    dk_pke    : bytes  Decryption key of length 384k.
    c         : bytes  Ciphertext of length 32(du·k + dv).
    param_set : str    One of "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024".
    """
    k, _, _, du, dv = _get_params(param_set)
    assert len(dk_pke) == 384 * k, \
        f"dk_PKE must be {384 * k} bytes, got {len(dk_pke)}"
    assert len(c) == 32 * (du * k + dv), \
        f"c must be {32 * (du * k + dv)} bytes, got {len(c)}"

    # Lines 1–2
    c1 = c[:32 * du * k]
    c2 = c[32 * du * k:32 * (du * k + dv)]

    # Lines 3–4
    u_prime = [_decompress_poly(poly, du) for poly in _decode_vec(c1, du, k)]
    v_prime = _decompress_poly(ByteDecode(c2, dv), dv)

    # Line 5
    s_hat = _decode_vec(dk_pke, 12, k)

    # Line 6
    w = poly_sub(v_prime, NTT_inv(inner_product(s_hat, ntt_vec(u_prime))))

    # Lines 7–8
    return ByteEncode(_compress_poly(w, 1), 1)


# ===========================================================================
# Self-test
# ===========================================================================

if __name__ == "__main__":
    import os

    print("Running K-PKE self-tests ...")

    TRIALS = 25

    for name in PARAMS:
        # -------------------------------------------------------------------
        # Key / ciphertext sizes match Section 5 / Table 3
        # -------------------------------------------------------------------
        ek, dk = KPKE_KeyGen(os.urandom(32), name)
        assert len(ek) == ek_length(name), f"{name}: wrong ek length"
        assert len(dk) == dk_length(name), f"{name}: wrong dk length"
        c = KPKE_Encrypt(ek, os.urandom(32), os.urandom(32), name)
        assert len(c) == ciphertext_length(name), f"{name}: wrong c length"
        print(f"  [PASS] {name}: sizes  ek={len(ek)}  dk={len(dk)}  c={len(c)}")

        # -------------------------------------------------------------------
        # Encoded t̂ / ŝ coefficients are all valid elements of Z_q
        # (ByteDecode_12 reduces mod q, so unpack the raw 12-bit values:
        #  every 3 bytes hold two little-endian 12-bit integers)
        # -------------------------------------------------------------------
        k = PARAMS[name]["k"]
        for key in (ek[:384 * k], dk):
            for i in range(0, len(key), 3):
                b0, b1, b2 = key[i], key[i + 1], key[i + 2]
                x0 = b0 | ((b1 & 0x0F) << 8)
                x1 = (b1 >> 4) | (b2 << 4)
                assert x0 < q and x1 < q, f"{name}: unreduced coefficient"
        print(f"  [PASS] {name}: encoded key coefficients in [0, q)")

        # -------------------------------------------------------------------
        # Determinism: same inputs -> same outputs
        # -------------------------------------------------------------------
        d = os.urandom(32)
        assert KPKE_KeyGen(d, name) == KPKE_KeyGen(d, name), \
            f"{name}: KeyGen not deterministic"
        m, r = os.urandom(32), os.urandom(32)
        assert KPKE_Encrypt(ek, m, r, name) == KPKE_Encrypt(ek, m, r, name), \
            f"{name}: Encrypt not deterministic"
        print(f"  [PASS] {name}: KeyGen / Encrypt deterministic")

        # -------------------------------------------------------------------
        # Correctness: Decrypt(dk, Encrypt(ek, m, r)) == m
        # -------------------------------------------------------------------
        for _ in range(TRIALS):
            ek, dk = KPKE_KeyGen(os.urandom(32), name)
            m, r = os.urandom(32), os.urandom(32)
            c = KPKE_Encrypt(ek, m, r, name)
            assert KPKE_Decrypt(dk, c, name) == m, \
                f"{name}: decryption failed"
        print(f"  [PASS] {name}: Decrypt(Encrypt(m)) == m  ({TRIALS} trials)")

        # -------------------------------------------------------------------
        # Wrong key should not recover the message
        # -------------------------------------------------------------------
        ek, _ = KPKE_KeyGen(os.urandom(32), name)
        _, dk_other = KPKE_KeyGen(os.urandom(32), name)
        m = os.urandom(32)
        c = KPKE_Encrypt(ek, m, os.urandom(32), name)
        assert KPKE_Decrypt(dk_other, c, name) != m, \
            f"{name}: wrong key decrypted correctly"
        print(f"  [PASS] {name}: wrong decryption key does not recover m")

    print("\nAll K-PKE tests passed.")
