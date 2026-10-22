# K-PKE, the public key encryption scheme underneath ML-KEM (FIPS 203, section 5).
#
# Not meant to be used on its own -- it's just the building block for the
# actual KEM in sections 6/7.

from auxiliary import (
    PRF,
    G,
    ByteEncode,
    ByteDecode,
    Compress,
    Decompress,
    SampleNTT,
    SamplePolyCBD,
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

# Parameter sets from Table 2
PARAMS = {
    "ML-KEM-512":  {"k": 2, "eta1": 3, "eta2": 2, "du": 10, "dv": 4},
    "ML-KEM-768":  {"k": 3, "eta1": 2, "eta2": 2, "du": 10, "dv": 4},
    "ML-KEM-1024": {"k": 4, "eta1": 2, "eta2": 2, "du": 11, "dv": 5},
}


def _get_params(param_set):
    """Returns (k, eta1, eta2, du, dv)."""
    if param_set not in PARAMS:
        raise ValueError(f"unknown parameter set {param_set!r}, "
                         f"pick one of {sorted(PARAMS)}")
    p = PARAMS[param_set]
    return p["k"], p["eta1"], p["eta2"], p["du"], p["dv"]


# Sizes in bytes
def ek_length(param_set):
    k = _get_params(param_set)[0]
    return 384 * k + 32


def dk_length(param_set):
    k = _get_params(param_set)[0]
    return 384 * k


def ciphertext_length(param_set):
    k, _, _, du, dv = _get_params(param_set)
    return 32 * (du * k + dv)


def _compress_poly(f, d):
    return [Compress(x, d) for x in f]


def _decompress_poly(f, d):
    return [Decompress(y, d) for y in f]


def _encode_vec(v, d):
    # encode each polynomial and glue the results together
    return b"".join(ByteEncode(p, d) for p in v)


def _decode_vec(B, d, k):
    size = 32 * d
    assert len(B) == k * size, f"expected {k * size} bytes, got {len(B)}"
    return [ByteDecode(B[i * size:(i + 1) * size], d) for i in range(k)]


def _sample_matrix(rho, k):
    # A[i][j] = SampleNTT(rho || j || i)
    # careful: j goes first, that's what the spec says
    assert len(rho) == 32, "rho must be 32 bytes"
    return [[SampleNTT(rho + bytes([j, i])) for j in range(k)]
            for i in range(k)]


def _sample_cbd_vec(seed, eta, k, counter):
    """Sample k CBD polynomials, bumping the PRF counter each time.

    Returns the vector and the updated counter.
    """
    vec = []
    for _ in range(k):
        vec.append(SamplePolyCBD(PRF(eta, seed, counter), eta))
        counter += 1
    return vec, counter


def KPKE_KeyGen(d, param_set):
    """Algorithm 13. Takes 32 random bytes, returns (ek, dk)."""
    k, eta1, _, _, _ = _get_params(param_set)
    assert len(d) == 32, "d must be 32 bytes"

    # FIPS 203 added k to the hash input here (round 3 Kyber didn't have it)
    rho, sigma = G(d + bytes([k]))

    A_hat = _sample_matrix(rho, k)
    s, N = _sample_cbd_vec(sigma, eta1, k, 0)
    e, N = _sample_cbd_vec(sigma, eta1, k, N)

    s_hat = ntt_vec(s)
    e_hat = ntt_vec(e)
    t_hat = vec_add(mat_vec_mul(A_hat, s_hat), e_hat)

    ek = _encode_vec(t_hat, 12) + rho
    dk = _encode_vec(s_hat, 12)
    return ek, dk


def KPKE_Encrypt(ek, m, r, param_set):
    """Algorithm 14. Encrypts a 32 byte message m using randomness r."""
    k, eta1, eta2, du, dv = _get_params(param_set)
    assert len(ek) == 384 * k + 32, \
        f"ek should be {384 * k + 32} bytes, got {len(ek)}"
    assert len(m) == 32, "m must be 32 bytes"
    assert len(r) == 32, "r must be 32 bytes"

    t_hat = _decode_vec(ek[:384 * k], 12, k)
    rho = ek[384 * k:]
    A_hat = _sample_matrix(rho, k)

    y, N = _sample_cbd_vec(r, eta1, k, 0)
    e1, N = _sample_cbd_vec(r, eta2, k, N)
    e2 = SamplePolyCBD(PRF(eta2, r, N), eta2)

    y_hat = ntt_vec(y)
    u = vec_add(intt_vec(mat_T_vec_mul(A_hat, y_hat)), e1)

    # each bit of m turns into either 0 or 1665 (~q/2)
    mu = _decompress_poly(ByteDecode(m, 1), 1)
    v = poly_add(poly_add(NTT_inv(inner_product(t_hat, y_hat)), e2), mu)

    c1 = _encode_vec([_compress_poly(p, du) for p in u], du)
    c2 = ByteEncode(_compress_poly(v, dv), dv)
    return c1 + c2


def KPKE_Decrypt(dk, c, param_set):
    """Algorithm 15. Recovers the 32 byte message from ciphertext c."""
    k, _, _, du, dv = _get_params(param_set)
    assert len(dk) == 384 * k, f"dk should be {384 * k} bytes, got {len(dk)}"
    assert len(c) == 32 * (du * k + dv), \
        f"c should be {32 * (du * k + dv)} bytes, got {len(c)}"

    split = 32 * du * k
    c1, c2 = c[:split], c[split:]

    u = [_decompress_poly(p, du) for p in _decode_vec(c1, du, k)]
    v = _decompress_poly(ByteDecode(c2, dv), dv)
    s_hat = _decode_vec(dk, 12, k)

    # w = v - s^T u  ~=  mu + small noise
    w = poly_sub(v, NTT_inv(inner_product(s_hat, ntt_vec(u))))

    # rounding w to 1 bit per coefficient gets rid of the noise
    return ByteEncode(_compress_poly(w, 1), 1)


if __name__ == "__main__":
    import os

    for name in PARAMS:
        ek, dk = KPKE_KeyGen(os.urandom(32), name)
        msg = os.urandom(32)
        ct = KPKE_Encrypt(ek, msg, os.urandom(32), name)
        assert KPKE_Decrypt(dk, ct, name) == msg
        print(f"{name}: ok  (ek={len(ek)}, dk={len(dk)}, c={len(ct)})")
