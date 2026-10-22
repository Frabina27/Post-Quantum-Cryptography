# Helper algorithms for ML-KEM (FIPS 203, section 4).
#
# Hash/XOF wrappers, the byte encoding + compression functions, the two
# samplers, and the NTT. Names follow the spec where possible so it's easy
# to check things against the PDF.

import hashlib

n = 256
q = 3329
ZETA = 17  # 17^128 = -1 mod q, so it's a primitive 256th root of unity

# zeta^BitRev7(i) mod q for i = 0..127 (Appendix A)
ZETAS = [
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


def _bit_rev_7(r):
    """Reverse the low 7 bits of r."""
    out = 0
    for _ in range(7):
        out = (out << 1) | (r & 1)
        r >>= 1
    return out


# ---- hash functions (4.1) ----

def PRF(eta, s, b):
    """PRF_eta(s, b) = SHAKE256(s || b), 64*eta bytes of output."""
    assert eta in (2, 3), "eta must be 2 or 3"
    assert len(s) == 32, "s must be 32 bytes"
    assert 0 <= b <= 255, "b must fit in one byte"
    return hashlib.shake_256(s + bytes([b])).digest(64 * eta)


def H(s):
    return hashlib.sha3_256(s).digest()


def J(s):
    return hashlib.shake_256(s).digest(32)


def G(c):
    """SHA3-512, split into two 32 byte halves."""
    out = hashlib.sha3_512(c).digest()
    return out[:32], out[32:]


class XOF:
    """SHAKE128 with the absorb/squeeze interface the spec uses.

    hashlib can't really stream output, so squeeze() just asks for a longer
    digest and slices off the new part. Since SHAKE output for a shorter
    length is always a prefix of the longer one, this works out the same.
    """

    def __init__(self):
        self._h = hashlib.shake_128()
        self._squeezed = False
        self._buf = b""
        self._pos = 0

    def absorb(self, data):
        assert not self._squeezed, "can't absorb after squeezing"
        self._h.update(data)

    def squeeze(self, length):
        self._squeezed = True
        end = self._pos + length
        if end > len(self._buf):
            self._buf = self._h.digest(end)
        out = self._buf[self._pos:end]
        self._pos = end
        return out


# ---- encoding / compression (4.2.1) ----

def BitsToBytes(b):
    # Algorithm 3. Bits are little-endian inside each byte.
    assert len(b) % 8 == 0, "number of bits must be a multiple of 8"
    out = bytearray(len(b) // 8)
    for i, bit in enumerate(b):
        out[i // 8] += bit << (i % 8)
    return bytes(out)


def BytesToBits(B):
    # Algorithm 4
    bits = []
    for byte in B:
        for _ in range(8):
            bits.append(byte & 1)
            byte >>= 1
    return bits


def ByteEncode(F, d):
    """Algorithm 5: pack 256 d-bit ints into 32*d bytes."""
    assert 1 <= d <= 12, "d must be between 1 and 12"
    assert len(F) == 256, "need exactly 256 coefficients"

    bits = []
    for a in F:
        a = int(a)
        for _ in range(d):
            bits.append(a & 1)
            a >>= 1
    return BitsToBytes(bits)


def ByteDecode(B, d):
    """Algorithm 6: inverse of ByteEncode. For d = 12 results are reduced mod q."""
    assert 1 <= d <= 12, "d must be between 1 and 12"
    assert len(B) == 32 * d, f"expected {32 * d} bytes, got {len(B)}"

    m = q if d == 12 else 1 << d
    bits = BytesToBits(B)
    F = []
    for i in range(256):
        val = 0
        for j in range(d):
            val |= bits[i * d + j] << j
        F.append(val % m)
    return F


def Compress(x, d):
    # round(2^d * x / q) mod 2^d, done with integers only (adding q//2
    # before the floor division gives round-half-up)
    assert 1 <= d < 12, "d must be between 1 and 11"
    return (((x << d) + q // 2) // q) % (1 << d)


def Decompress(y, d):
    # round(q * y / 2^d)
    assert 1 <= d < 12, "d must be between 1 and 11"
    return (q * y + (1 << (d - 1))) >> d


# ---- sampling (4.2.2) ----

def SampleNTT(B):
    """Algorithm 7: rejection sample a polynomial in NTT form from a 34 byte seed."""
    assert len(B) == 34, "B should be a 32 byte seed + 2 index bytes"

    xof = XOF()
    xof.absorb(B)

    a = []
    while len(a) < 256:
        c0, c1, c2 = xof.squeeze(3)
        # 3 bytes -> two 12-bit candidates
        d1 = c0 + 256 * (c1 % 16)
        d2 = (c1 // 16) + 16 * c2
        if d1 < q:
            a.append(d1)
        if d2 < q and len(a) < 256:
            a.append(d2)
    return a


def SamplePolyCBD(B, eta):
    """Algorithm 8: centered binomial distribution with parameter eta."""
    assert eta in (2, 3), "eta must be 2 or 3"
    assert len(B) == 64 * eta, f"expected {64 * eta} bytes, got {len(B)}"

    bits = BytesToBits(B)
    f = []
    for i in range(256):
        start = 2 * i * eta
        x = sum(bits[start:start + eta])
        y = sum(bits[start + eta:start + 2 * eta])
        f.append((x - y) % q)
    return f


# ---- NTT (4.3) ----

def NTT(f):
    # Algorithm 9
    assert len(f) == 256, "f must have 256 coefficients"

    f = list(f)  # don't touch the caller's list
    k = 1
    length = 128
    while length >= 2:
        for start in range(0, 256, 2 * length):
            zeta = ZETAS[k]
            k += 1
            for j in range(start, start + length):
                t = zeta * f[j + length] % q
                f[j + length] = (f[j] - t) % q
                f[j] = (f[j] + t) % q
        length //= 2
    return f


def NTT_inv(f_hat):
    # Algorithm 10
    assert len(f_hat) == 256, "f_hat must have 256 coefficients"

    f = list(f_hat)
    k = 127
    length = 2
    while length <= 128:
        for start in range(0, 256, 2 * length):
            zeta = ZETAS[k]
            k -= 1
            for j in range(start, start + length):
                t = f[j]
                f[j] = (t + f[j + length]) % q
                f[j + length] = zeta * (f[j + length] - t) % q
        length *= 2

    # 3303 = 128^-1 mod q   (128 * 3303 = 127 * 3329 + 1)
    return [x * 3303 % q for x in f]


def BaseCaseMultiply(a0, a1, b0, b1, gamma):
    """(a0 + a1 X)(b0 + b1 X) mod (X^2 - gamma). Algorithm 12."""
    c0 = (a0 * b0 + a1 * b1 * gamma) % q
    c1 = (a0 * b1 + a1 * b0) % q
    return c0, c1


def MultiplyNTTs(f_hat, g_hat):
    # Algorithm 11
    assert len(f_hat) == 256, "f_hat must have 256 coefficients"
    assert len(g_hat) == 256, "g_hat must have 256 coefficients"

    h = [0] * 256
    for i in range(128):
        # gamma = zeta^(2*BitRev7(i) + 1). The spec has a second table for
        # these but it's easy enough to get from ZETAS: ZETAS[i]^2 * zeta.
        gamma = ZETAS[i] * ZETAS[i] * ZETA % q
        h[2 * i], h[2 * i + 1] = BaseCaseMultiply(
            f_hat[2 * i], f_hat[2 * i + 1],
            g_hat[2 * i], g_hat[2 * i + 1],
            gamma,
        )
    return h


# ---- polynomial / vector helpers used by K-PKE ----

def poly_add(a, b):
    assert len(a) == len(b) == 256
    return [(x + y) % q for x, y in zip(a, b)]


def poly_sub(a, b):
    assert len(a) == len(b) == 256
    return [(x - y) % q for x, y in zip(a, b)]


def vec_add(u, v):
    assert len(u) == len(v)
    return [poly_add(a, b) for a, b in zip(u, v)]


def mat_vec_mul(A_hat, s_hat):
    """A * s with everything already in the NTT domain."""
    k = len(s_hat)
    out = []
    for i in range(k):
        acc = [0] * 256
        for j in range(k):
            acc = poly_add(acc, MultiplyNTTs(A_hat[i][j], s_hat[j]))
        out.append(acc)
    return out


def mat_T_vec_mul(A_hat, s_hat):
    """Same as mat_vec_mul but with A transposed."""
    k = len(s_hat)
    out = []
    for i in range(k):
        acc = [0] * 256
        for j in range(k):
            acc = poly_add(acc, MultiplyNTTs(A_hat[j][i], s_hat[j]))
        out.append(acc)
    return out


def inner_product(u_hat, v_hat):
    assert len(u_hat) == len(v_hat)
    acc = [0] * 256
    for a, b in zip(u_hat, v_hat):
        acc = poly_add(acc, MultiplyNTTs(a, b))
    return acc


def ntt_vec(v):
    return [NTT(p) for p in v]


def intt_vec(v_hat):
    return [NTT_inv(p) for p in v_hat]


if __name__ == "__main__":
    # quick sanity check, the real tests are in test_auxiliary.py
    import random

    f = [random.randrange(q) for _ in range(256)]
    assert NTT_inv(NTT(f)) == f
    for d in range(1, 13):
        m = q if d == 12 else 1 << d
        F = [random.randrange(m) for _ in range(256)]
        assert ByteDecode(ByteEncode(F, d), d) == F
    print("ok")
