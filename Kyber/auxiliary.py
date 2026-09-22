"""
Auxiliary Algorithms for ML-KEM (FIPS 203)
==========================================
Implements all auxiliary algorithms specified in Section 4 of
NIST FIPS 203, "Module-Lattice-Based Key-Encapsulation Mechanism Standard"
(August 13, 2024).

Sections covered:
    4.1  Cryptographic Functions     — PRF, H, J, G, XOF wrapper
    4.2  General Algorithms
         4.2.1 Conversion and Compression — BitsToBytes, BytesToBits,
                                            ByteEncode_d, ByteDecode_d,
                                            Compress_d, Decompress_d
         4.2.2 Sampling Algorithms        — SampleNTT, SamplePolyCBD_eta
    4.3  Number-Theoretic Transform   — NTT, NTT_inv, MultiplyNTTs,
                                        BaseCaseMultiply

Global constants (Section 2.3):
    n = 256   (polynomial degree)
    q = 3329  (prime modulus)
    zeta = 17 (primitive n-th root of unity mod q)
"""

import hashlib
from typing import List, Tuple

# ---------------------------------------------------------------------------
# Global constants (Section 2.3)
# ---------------------------------------------------------------------------
n: int = 256          # polynomial degree
q: int = 3329         # prime modulus  3329 = 2^8 * 13 + 1
ZETA: int = 17        # primitive 256th root of unity mod q  (zeta^128 ≡ −1 mod q)

# ---------------------------------------------------------------------------
# Appendix A — Precomputed zeta values for NTT / NTT^{-1}
#
# The 128 values of  zeta^{BitRev_7(i)} mod q  for i = 0, ..., 127.
# These are used in Algorithms 9 and 10.
# ---------------------------------------------------------------------------
ZETAS: List[int] = [
    1,    1729, 2580, 3289, 2642, 630,  1897, 848,
    1062, 1919, 193,  797,  2786, 3260, 569,  1746,
    296,  2447, 1339, 1476, 3046, 56,   2240, 1333,
    1426, 2094, 535,  2882, 2393, 2879, 1974, 821,
    289,  331,  3253, 1756, 1197, 2304, 2277, 2055,
    650,  1977, 2513, 632,  2865, 33,   1320, 1915,
    2319, 1435, 807,  452,  1438, 2868, 1534, 2402,
    2647, 2617, 1481, 648,  2474, 3110, 1227, 910,
    17,   2761, 583,  2649, 1637, 723,  2288, 1100,
    1409, 2662, 3281, 233,  756,  2156, 3015, 3050,
    1703, 1651, 2789, 1789, 1847, 952,  1461, 2687,
    939,  2308, 2437, 2388, 733,  2337, 268,  641,
    1584, 2298, 2037, 3220, 375,  2549, 2090, 1645,
    1063, 319,  2773, 757,  2099, 561,  2466, 2594,
    2804, 1092, 403,  1026, 1143, 2150, 2775, 886,
    1722, 1212, 1874, 1029, 2110, 2935, 885,  2154,
]


# ---------------------------------------------------------------------------
# Helper: integer bit-reversal (BitRev_7)
# ---------------------------------------------------------------------------
def _bit_rev_7(r: int) -> int:
    """
    Bit-reversal of a 7-bit integer r.  (Section 2.3)
    If r = r_0 + 2*r_1 + ... + 64*r_6, then
    BitRev_7(r) = r_6 + 2*r_5 + ... + 64*r_0.
    """
    result = 0
    for _ in range(7):
        result = (result << 1) | (r & 1)
        r >>= 1
    return result


# ===========================================================================
# Section 4.1 — Cryptographic Functions
# ===========================================================================

def PRF(eta: int, s: bytes, b: int) -> bytes:
    """
    Pseudorandom function  (Section 4.1, Equation 4.3).

        PRF_eta(s, b) := SHAKE256(s || b, 8 * 64 * eta)

    Parameters
    ----------
    eta : int   Parameter eta in {2, 3} — determines output length.
    s   : bytes 32-byte seed.
    b   : int   1-byte counter (0 <= b <= 255).

    Returns
    -------
    bytes of length 64 * eta.
    """
    assert eta in (2, 3), "eta must be 2 or 3"
    assert len(s) == 32, "s must be 32 bytes"
    assert 0 <= b <= 255, "b must be a single byte value"

    xof = hashlib.shake_256()
    xof.update(s + bytes([b]))
    return xof.digest(64 * eta)


def H(s: bytes) -> bytes:
    """
    Hash function H  (Section 4.1, Equation 4.4).

        H(s) := SHA3-256(s)

    Parameters
    ----------
    s : bytes  Variable-length input.

    Returns
    -------
    bytes of length 32.
    """
    return hashlib.sha3_256(s).digest()


def J(s: bytes) -> bytes:
    """
    Hash function J  (Section 4.1, Equation 4.4).

        J(s) := SHAKE256(s, 8 * 32)

    Parameters
    ----------
    s : bytes  Variable-length input.

    Returns
    -------
    bytes of length 32.
    """
    xof = hashlib.shake_256()
    xof.update(s)
    return xof.digest(32)


def G(c: bytes) -> Tuple[bytes, bytes]:
    """
    Hash function G  (Section 4.1, Equation 4.5).

        G(c) := SHA3-512(c)

    The 64-byte output is split into two 32-byte halves (a, b).

    Parameters
    ----------
    c : bytes  Variable-length input.

    Returns
    -------
    (a, b) : (bytes, bytes)   Two 32-byte outputs.
    """
    digest = hashlib.sha3_512(c).digest()
    return digest[:32], digest[32:]


# ---------------------------------------------------------------------------
# XOF wrapper (Section 4.1)
# The document defines XOF in terms of SHAKE128's incremental (Init /
# Absorb / Squeeze) API.  Python's hashlib provides a stateful shake_128
# object that mirrors this interface.
# ---------------------------------------------------------------------------

class XOF:
    """
    Wrapper around SHAKE128 providing the Init / Absorb / Squeeze interface
    described in Section 4.1 of FIPS 203.

        XOF.Init()          — create a new context
        XOF.Absorb(data)    — feed bytes into the sponge
        XOF.Squeeze(length) — extract `length` bytes of output
    """

    def __init__(self) -> None:
        """XOF.Init() — initialise context."""
        self._h = hashlib.shake_128()
        self._squeezed = False
        self._buf = b""
        self._buf_pos = 0

    def absorb(self, data: bytes) -> None:
        """
        XOF.Absorb(ctx, str)  (Section 4.1)

        Injects data into the absorbing phase.
        Must be called before the first call to squeeze().
        """
        assert not self._squeezed, "Cannot absorb after squeezing has started"
        self._h.update(data)

    def squeeze(self, length: int) -> bytes:
        """
        XOF.Squeeze(ctx, ℓ)  (Section 4.1)

        Extracts `length` bytes from the squeezing phase.

        Note: Python's hashlib shake_128.digest() is not truly incremental
        in the streaming sense but re-generating with increasing lengths
        is equivalent because SHAKE is a stream cipher — each additional
        call conceptually continues from where the previous ended.  We
        implement true streaming by accumulating all data needed up front
        via a running total.
        """
        self._squeezed = True
        start = self._buf_pos
        end = self._buf_pos + length
        # Extend the internal buffer if necessary
        if end > len(self._buf):
            self._buf = self._h.digest(end)
        out = self._buf[start:end]
        self._buf_pos = end
        return out


# ===========================================================================
# Section 4.2.1 — Conversion and Compression Algorithms
# ===========================================================================

def BitsToBytes(b: List[int]) -> bytes:
    """
    Algorithm 3 — BitsToBytes(b)

    Converts a bit array (of a length that is a multiple of eight) into
    an array of bytes.

        Input:  bit array b ∈ {0,1}^{8ℓ}
        Output: byte array B ∈ B^ℓ

    Pseudocode (FIPS 203, Algorithm 3):
        B ← (0, …, 0)
        for i ← 0; i < 8ℓ; i++:
            B[⌊i/8⌋] ← B[⌊i/8⌋] + b[i] · 2^{i mod 8}
        return B
    """
    assert len(b) % 8 == 0, "Bit array length must be a multiple of 8"
    ell = len(b) // 8
    B = bytearray(ell)
    for i in range(8 * ell):
        B[i // 8] += b[i] * (1 << (i % 8))
    return bytes(B)


def BytesToBits(B: bytes) -> List[int]:
    """
    Algorithm 4 — BytesToBits(B)

    Performs the inverse of BitsToBytes, converting a byte array into a
    bit array.

        Input:  byte array B ∈ B^ℓ
        Output: bit array b ∈ {0,1}^{8ℓ}

    Pseudocode (FIPS 203, Algorithm 4):
        C ← B                     ▷ copy B into array C ∈ B^ℓ
        for i ← 0; i < ℓ; i++:
            for j ← 0; j < 8; j++:
                b[8i+j] ← C[i] mod 2
                C[i]    ← ⌊C[i]/2⌋
        return b
    """
    ell = len(B)
    C = list(B)           # mutable copy
    b = [0] * (8 * ell)
    for i in range(ell):
        for j in range(8):
            b[8 * i + j] = C[i] % 2
            C[i] = C[i] // 2
    return b


def ByteEncode(F: List[int], d: int) -> bytes:
    """
    Algorithm 5 — ByteEncode_d(F)

    Encodes an array of d-bit integers into a byte array for 1 ≤ d ≤ 12.

        Input:  integer array F ∈ Z_m^{256},
                where m = 2^d if d < 12, and m = q if d = 12.
        Output: byte array B ∈ B^{32d}.

    Pseudocode (FIPS 203, Algorithm 5):
        for i ← 0; i < 256; i++:
            a ← F[i]               ▷ a ∈ Z_m
            for j ← 0; j < d; j++:
                b[i·d+j] ← a mod 2
                a ← (a − b[i·d+j]) / 2
        B ← BitsToBytes(b)
        return B

    Parameters
    ----------
    F : list of 256 integers.
    d : int in [1, 12].
    """
    assert 1 <= d <= 12, "d must satisfy 1 ≤ d ≤ 12"
    assert len(F) == 256, "F must have exactly 256 elements"

    b = [0] * (256 * d)
    for i in range(256):
        a = int(F[i])
        for j in range(d):
            b[i * d + j] = a % 2
            a = (a - b[i * d + j]) // 2
    return BitsToBytes(b)


def ByteDecode(B: bytes, d: int) -> List[int]:
    """
    Algorithm 6 — ByteDecode_d(B)

    Decodes a byte array into an array of d-bit integers for 1 ≤ d ≤ 12.

        Input:  byte array B ∈ B^{32d}.
        Output: integer array F ∈ Z_m^{256},
                where m = 2^d if d < 12, and m = q if d = 12.

    Pseudocode (FIPS 203, Algorithm 6):
        b ← BytesToBits(B)
        for i ← 0; i < 256; i++:
            F[i] ← Σ_{j←0}^{d−1} b[i·d+j] · 2^j  mod m
        return F

    Parameters
    ----------
    B : bytes of length 32d.
    d : int in [1, 12].
    """
    assert 1 <= d <= 12, "d must satisfy 1 ≤ d ≤ 12"
    assert len(B) == 32 * d, f"B must have length 32d = {32 * d}, got {len(B)}"

    m = (1 << d) if d < 12 else q
    b = BytesToBits(B)
    F = [0] * 256
    for i in range(256):
        value = 0
        for j in range(d):
            value += b[i * d + j] * (1 << j)
        F[i] = value % m
    return F


def Compress(x: int, d: int) -> int:
    """
    Compress_d  (Section 4.2.1, Equation 4.7)

    Maps an element of Z_q to an element of Z_{2^d}, for d < 12.

        Compress_d : Z_q  →  Z_{2^d}
        x  ↦  ⌈(2^d / q) · x⌋  mod  2^d

    where ⌈·⌋ denotes rounding to the nearest integer (ties round up).
    No floating-point arithmetic is used (Section 3.3, FIPS 203).

    Parameters
    ----------
    x : int in [0, q-1].
    d : int, 1 ≤ d < 12.
    """
    assert 0 <= d < 12, "d must satisfy 0 ≤ d < 12"
    # ⌈(2^d / q) · x⌋ = ⌊(2^d * x + q/2) / q⌋  (integer arithmetic)
    # Use the formula:  round(2^d * x / q) = (2^d * x + q//2) // q
    two_d = 1 << d
    return ((two_d * x + q // 2) // q) % two_d


def Decompress(y: int, d: int) -> int:
    """
    Decompress_d  (Section 4.2.1, Equation 4.8)

    Maps an element of Z_{2^d} to an element of Z_q, for d < 12.

        Decompress_d : Z_{2^d}  →  Z_q
        y  ↦  ⌈(q / 2^d) · y⌋

    where ⌈·⌋ denotes rounding to the nearest integer (ties round up).
    No floating-point arithmetic is used (Section 3.3, FIPS 203).

    Parameters
    ----------
    y : int in [0, 2^d - 1].
    d : int, 1 ≤ d < 12.
    """
    assert 0 <= d < 12, "d must satisfy 0 ≤ d < 12"
    # ⌈(q / 2^d) · y⌋ = ⌊(q * y + 2^{d-1}) / 2^d⌋  (integer arithmetic)
    two_d = 1 << d
    return (q * y + two_d // 2) // two_d


# ===========================================================================
# Section 4.2.2 — Sampling Algorithms
# ===========================================================================

def SampleNTT(B: bytes) -> List[int]:
    """
    Algorithm 7 — SampleNTT(B)

    Takes a 34-byte input (32-byte seed + 2 index bytes) and outputs a
    pseudorandom element of T_q (represented as an array of 256 integers
    mod q).

        Input:  byte array B ∈ B^{34}.
                (a 32-byte seed along with two indices)
        Output: array â ∈ Z_q^{256}.
                (the coefficients of the NTT of a polynomial)

    Pseudocode (FIPS 203, Algorithm 7):
        ctx ← XOF.Init()
        ctx ← XOF.Absorb(ctx, B)
        j ← 0
        while j < 256 do:
            (ctx, C) ← XOF.Squeeze(ctx, 3)
            d_1 ← C[0] + 256 · (C[1] mod 16)
            d_2 ← ⌊C[1]/16⌋ + 16 · C[2]
            if d_1 < q then
                â[j] ← d_1
                j ← j + 1
            if d_2 < q and j < 256 then
                â[j] ← d_2
                j ← j + 1
        return â

    Parameters
    ----------
    B : bytes of length 34 (32-byte seed || byte_i || byte_j).
    """
    assert len(B) == 34, "B must be 34 bytes (32-byte seed + 2 index bytes)"

    ctx = XOF()
    ctx.absorb(B)

    a_hat = [0] * 256
    j = 0
    while j < 256:
        C = ctx.squeeze(3)
        d1 = C[0] + 256 * (C[1] % 16)
        d2 = (C[1] // 16) + 16 * C[2]
        if d1 < q:
            a_hat[j] = d1
            j += 1
        if d2 < q and j < 256:
            a_hat[j] = d2
            j += 1
    return a_hat


def SamplePolyCBD(B: bytes, eta: int) -> List[int]:
    """
    Algorithm 8 — SamplePolyCBD_eta(B)

    Takes a seed as input and outputs a pseudorandom sample from the
    distribution D_eta(R_q).

        Input:  byte array B ∈ B^{64η}.
        Output: array f ∈ Z_q^{256}.
                (the coefficients of the sampled polynomial)

    Pseudocode (FIPS 203, Algorithm 8):
        b ← BytesToBits(B)
        for i ← 0; i < 256; i++:
            x ← Σ_{j←0}^{η−1} b[2iη + j]
            y ← Σ_{j←0}^{η−1} b[2iη + η + j]
            f[i] ← x − y  mod  q
        return f

    Parameters
    ----------
    B   : bytes of length 64 * eta.
    eta : int in {2, 3}.
    """
    assert eta in (2, 3), "eta must be 2 or 3"
    assert len(B) == 64 * eta, f"B must have length 64η = {64 * eta}, got {len(B)}"

    b = BytesToBits(B)
    f = [0] * 256
    for i in range(256):
        x = sum(b[2 * i * eta + j] for j in range(eta))
        y = sum(b[2 * i * eta + eta + j] for j in range(eta))
        f[i] = (x - y) % q
    return f


# ===========================================================================
# Section 4.3 — The Number-Theoretic Transform
# ===========================================================================

def NTT(f: List[int]) -> List[int]:
    """
    Algorithm 9 — NTT(f)

    Computes the NTT representation f̂ of the given polynomial f ∈ R_q.

        Input:  array f ∈ Z_q^{256}   (the coefficients of the input polynomial)
        Output: array f̂ ∈ Z_q^{256}  (the coefficients of the NTT)

    Pseudocode (FIPS 203, Algorithm 9):
        f̂ ← f                        ▷ compute in place on a copy
        i ← 1
        for len ← 128; len ≥ 2; len ← len/2:
            for start ← 0; start < 256; start ← start + 2·len:
                zeta ← ζ^{BitRev_7(i)} mod q
                i ← i + 1
                for j ← start; j < start + len; j++:
                    t ← zeta · f̂[j + len]    ▷ steps 8-10 done modulo q
                    f̂[j + len] ← f̂[j] − t
                    f̂[j]       ← f̂[j] + t
        return f̂
    """
    assert len(f) == 256, "f must have 256 coefficients"

    f_hat = list(f)   # copy (inputs passed by value per spec)
    i = 1
    length = 128
    while length >= 2:
        start = 0
        while start < 256:
            zeta = ZETAS[i]
            i += 1
            for j in range(start, start + length):
                t = (zeta * f_hat[j + length]) % q
                f_hat[j + length] = (f_hat[j] - t) % q
                f_hat[j]          = (f_hat[j] + t) % q
            start += 2 * length
        length //= 2
    return f_hat


def NTT_inv(f_hat: List[int]) -> List[int]:
    """
    Algorithm 10 — NTT^{−1}(f̂)

    Computes the polynomial f ∈ R_q that corresponds to the given NTT
    representation f̂ ∈ T_q.

        Input:  array f̂ ∈ Z_q^{256}  (the coefficients of input NTT representation)
        Output: array f ∈ Z_q^{256}   (the coefficients of the inverse NTT)

    Pseudocode (FIPS 203, Algorithm 10):
        f ← f̂                        ▷ compute in place on a copy
        i ← 127
        for len ← 2; len ≤ 128; len ← 2·len:
            for start ← 0; start < 256; start ← start + 2·len:
                zeta ← ζ^{BitRev_7(i)} mod q
                i ← i − 1
                for j ← start; j < start + len; j++:
                    t ← f[j]
                    f[j]       ← t + f[j + len]    ▷ steps 9-10 done modulo q
                    f[j + len] ← zeta · (f[j + len] − t)
        f ← f · 3303  mod  q        ▷ multiply every entry by 3303 ≡ 128^{−1} mod q
        return f

    Note: 3303 ≡ 128^{-1} (mod 3329) because 128 * 3303 = 422784 = 127 * 3329 + 1.
    """
    assert len(f_hat) == 256, "f_hat must have 256 coefficients"

    f = list(f_hat)   # copy
    i = 127
    length = 2
    while length <= 128:
        start = 0
        while start < 256:
            zeta = ZETAS[i]
            i -= 1
            for j in range(start, start + length):
                t = f[j]
                f[j]          = (t + f[j + length]) % q
                f[j + length] = (zeta * (f[j + length] - t)) % q
            start += 2 * length
        length *= 2
    # Multiply every entry by 128^{-1} mod q = 3303
    f = [(coeff * 3303) % q for coeff in f]
    return f


def BaseCaseMultiply(a0: int, a1: int, b0: int, b1: int, gamma: int) -> Tuple[int, int]:
    """
    Algorithm 12 — BaseCaseMultiply(a_0, a_1, b_0, b_1, γ)

    Computes the product of two degree-one polynomials with respect to
    a quadratic modulus.

        Input:  a_0, a_1, b_0, b_1 ∈ Z_q   (coefficients of a_0 + a_1·X and b_0 + b_1·X)
                γ ∈ Z_q                      (the modulus is X^2 − γ)
        Output: c_0, c_1 ∈ Z_q              (coefficients of the product)

    Pseudocode (FIPS 203, Algorithm 12):
        c_0 ← a_0·b_0 + a_1·b_1·γ    ▷ steps 1-2 done modulo q
        c_1 ← a_0·b_1 + a_1·b_0
        return (c_0, c_1)
    """
    c0 = (a0 * b0 + a1 * b1 * gamma) % q
    c1 = (a0 * b1 + a1 * b0) % q
    return c0, c1


def MultiplyNTTs(f_hat: List[int], g_hat: List[int]) -> List[int]:
    """
    Algorithm 11 — MultiplyNTTs(f̂, ĝ)

    Computes the product (in the ring T_q) of two NTT representations.

        Input:  Two arrays f̂ ∈ Z_q^{256} and ĝ ∈ Z_q^{256}.
                (the coefficients of two NTT representations)
        Output: An array ĥ ∈ Z_q^{256}.
                (the coefficients of the product of the inputs)

    Pseudocode (FIPS 203, Algorithm 11):
        for i ← 0; i < 128; i++:
            (ĥ[2i], ĥ[2i+1]) ← BaseCaseMultiply(
                f̂[2i], f̂[2i+1], ĝ[2i], ĝ[2i+1],
                ζ^{2·BitRev_7(i)+1}
            )
        return ĥ

    The values ζ^{2·BitRev_7(i)+1} mod q for i = 0,...,127 are listed in
    Appendix A of FIPS 203 (alternating positive and negative pairs).
    They equal ZETAS[64 + i] (the second half of the ZETAS table starting
    at index 64, which stores zeta^{BitRev_7(i)} for i = 0,...,127; the
    required power is computed directly below).
    """
    assert len(f_hat) == 256, "f_hat must have 256 coefficients"
    assert len(g_hat) == 256, "g_hat must have 256 coefficients"

    h_hat = [0] * 256
    for i in range(128):
        # γ = ζ^{2·BitRev_7(i) + 1} mod q
        # The ZETAS array holds ζ^{BitRev_7(i)} at index i.
        # Therefore ζ^{2·BitRev_7(i)+1} = ZETAS[i]^2 * ZETA mod q.
        # Equivalently, from Appendix A second table:
        # the values are ±ZETAS[64 + i] for i = 0,...,127.
        # We compute directly using ZETAS[i] (= ζ^{BitRev_7(i)}):
        gamma = (ZETAS[i] ** 2 * ZETA) % q    # = ζ^{2*BitRev_7(i)+1}
        h_hat[2 * i], h_hat[2 * i + 1] = BaseCaseMultiply(
            f_hat[2 * i], f_hat[2 * i + 1],
            g_hat[2 * i], g_hat[2 * i + 1],
            gamma,
        )
    return h_hat


# ===========================================================================
# Convenience: vector / matrix operations used in K-PKE and ML-KEM
# (Section 2.4.7)
# ===========================================================================

def poly_add(a: List[int], b: List[int]) -> List[int]:
    """Coefficient-wise addition of two polynomials modulo q."""
    assert len(a) == len(b) == 256
    return [(a[i] + b[i]) % q for i in range(256)]


def poly_sub(a: List[int], b: List[int]) -> List[int]:
    """Coefficient-wise subtraction of two polynomials modulo q."""
    assert len(a) == len(b) == 256
    return [(a[i] - b[i]) % q for i in range(256)]


def vec_add(u: List[List[int]], v: List[List[int]]) -> List[List[int]]:
    """Element-wise addition of two vectors of polynomials."""
    assert len(u) == len(v)
    return [poly_add(u[i], v[i]) for i in range(len(u))]


def mat_vec_mul(A_hat: List[List[List[int]]],
                s_hat: List[List[int]]) -> List[List[int]]:
    """
    Matrix–vector multiplication in T_q:  Â ∘ ŝ  (Equation 2.12).

    A_hat is a k×k matrix of NTT-domain polynomials.
    s_hat is a length-k vector of NTT-domain polynomials.
    Returns a length-k vector.
    """
    k = len(s_hat)
    result = [[0] * 256 for _ in range(k)]
    for i in range(k):
        for j in range(k):
            result[i] = poly_add(result[i], MultiplyNTTs(A_hat[i][j], s_hat[j]))
    return result


def mat_T_vec_mul(A_hat: List[List[List[int]]],
                  s_hat: List[List[int]]) -> List[List[int]]:
    """
    Transpose matrix–vector multiplication in T_q:  Â^T ∘ ŝ  (Equation 2.13).

    A_hat is a k×k matrix of NTT-domain polynomials.
    s_hat is a length-k vector of NTT-domain polynomials.
    Returns a length-k vector.
    """
    k = len(s_hat)
    result = [[0] * 256 for _ in range(k)]
    for i in range(k):
        for j in range(k):
            result[i] = poly_add(result[i], MultiplyNTTs(A_hat[j][i], s_hat[j]))
    return result


def inner_product(u_hat: List[List[int]],
                  v_hat: List[List[int]]) -> List[int]:
    """
    Dot product of two vectors in T_q:  û^T ∘ v̂  (Equation 2.14).

    Returns a single NTT-domain polynomial.
    """
    assert len(u_hat) == len(v_hat)
    result = [0] * 256
    for j in range(len(u_hat)):
        result = poly_add(result, MultiplyNTTs(u_hat[j], v_hat[j]))
    return result


def ntt_vec(v: List[List[int]]) -> List[List[int]]:
    """Apply NTT coordinate-wise to a vector of polynomials (Equation 2.9)."""
    return [NTT(poly) for poly in v]


def intt_vec(v_hat: List[List[int]]) -> List[List[int]]:
    """Apply NTT^{-1} coordinate-wise to a vector of NTT representations."""
    return [NTT_inv(poly_hat) for poly_hat in v_hat]


# ===========================================================================
# Self-test
# ===========================================================================

if __name__ == "__main__":
    print("Running auxiliary algorithm self-tests …")

    # -----------------------------------------------------------------------
    # Test BitsToBytes / BytesToBits  (roundtrip)
    # -----------------------------------------------------------------------
    import os
    test_bytes = os.urandom(32)
    bits = BytesToBits(test_bytes)
    recovered = BitsToBytes(bits)
    assert recovered == test_bytes, "BitsToBytes / BytesToBits roundtrip failed"
    print("  [PASS] BitsToBytes / BytesToBits roundtrip")

    # -----------------------------------------------------------------------
    # Test ByteEncode / ByteDecode  (roundtrip for d in 1..12)
    # -----------------------------------------------------------------------
    import random
    for d in range(1, 13):
        m = (1 << d) if d < 12 else q
        F = [random.randrange(m) for _ in range(256)]
        B = ByteEncode(F, d)
        F2 = ByteDecode(B, d)
        assert F == F2, f"ByteEncode/ByteDecode roundtrip failed for d={d}"
    print("  [PASS] ByteEncode / ByteDecode roundtrip (d = 1..12)")

    # -----------------------------------------------------------------------
    # Test Compress / Decompress:  Compress(Decompress(y)) == y
    # -----------------------------------------------------------------------
    for d in range(1, 12):
        for y in range(1 << d):
            assert Compress(Decompress(y, d), d) == y, \
                f"Compress(Decompress(y, {d})) != y for y={y}"
    print("  [PASS] Compress(Decompress(y)) == y  (d = 1..11)")

    # -----------------------------------------------------------------------
    # Test NTT / NTT_inv  (roundtrip)
    # -----------------------------------------------------------------------
    f = [random.randrange(q) for _ in range(256)]
    f_hat = NTT(f)
    f2 = NTT_inv(f_hat)
    assert f == f2, "NTT / NTT_inv roundtrip failed"
    print("  [PASS] NTT / NTT_inv roundtrip")

    # -----------------------------------------------------------------------
    # Test MultiplyNTTs:  NTT_inv(NTT(a) ⊙ NTT(b)) == a * b (mod X^256+1, q)
    # -----------------------------------------------------------------------
    def poly_mul_naive(a: List[int], b: List[int]) -> List[int]:
        """Reference: schoolbook polynomial multiplication mod X^256+1, q."""
        result = [0] * 256
        for i in range(256):
            for j in range(256):
                coeff = (a[i] * b[j]) % q
                idx = (i + j) % 256
                sign = -1 if (i + j) >= 256 else 1
                result[idx] = (result[idx] + sign * coeff) % q
        return result

    a = [random.randrange(q) for _ in range(256)]
    b = [random.randrange(q) for _ in range(256)]
    expected = poly_mul_naive(a, b)
    ntt_prod = NTT_inv(MultiplyNTTs(NTT(a), NTT(b)))
    assert expected == ntt_prod, "MultiplyNTTs does not match schoolbook multiplication"
    print("  [PASS] MultiplyNTTs (NTT-domain multiplication matches schoolbook)")

    # -----------------------------------------------------------------------
    # Test SampleNTT (basic sanity: output is length 256, all < q)
    # -----------------------------------------------------------------------
    seed = os.urandom(32)
    B34 = seed + bytes([0, 0])
    a_hat = SampleNTT(B34)
    assert len(a_hat) == 256 and all(0 <= x < q for x in a_hat), \
        "SampleNTT output out of range"
    print("  [PASS] SampleNTT basic sanity")

    # -----------------------------------------------------------------------
    # Test SamplePolyCBD (output in valid range for eta=2 and eta=3)
    # -----------------------------------------------------------------------
    for eta in (2, 3):
        prf_out = PRF(eta, os.urandom(32), 0)
        poly = SamplePolyCBD(prf_out, eta)
        assert len(poly) == 256, "SamplePolyCBD wrong output length"
        for coeff in poly:
            # Coefficients should be in [0, eta] or [q-eta, q-1]
            assert (0 <= coeff <= eta) or (q - eta <= coeff < q), \
                f"SamplePolyCBD coeff {coeff} out of expected CBD range for eta={eta}"
    print("  [PASS] SamplePolyCBD (eta=2, eta=3)")

    # -----------------------------------------------------------------------
    # Test hash functions
    # -----------------------------------------------------------------------
    msg = b"test message"
    h = H(msg)
    assert len(h) == 32, "H must return 32 bytes"

    j_out = J(msg)
    assert len(j_out) == 32, "J must return 32 bytes"

    a_g, b_g = G(msg)
    assert len(a_g) == 32 and len(b_g) == 32, "G must return two 32-byte values"
    print("  [PASS] H, J, G hash functions")

    # -----------------------------------------------------------------------
    # Test PRF
    # -----------------------------------------------------------------------
    s = os.urandom(32)
    for eta in (2, 3):
        out = PRF(eta, s, 0)
        assert len(out) == 64 * eta, f"PRF wrong output length for eta={eta}"
    print("  [PASS] PRF")

    print("\nAll auxiliary algorithm tests passed.")
