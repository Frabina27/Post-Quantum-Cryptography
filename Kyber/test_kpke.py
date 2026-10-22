# Tests for kpke.py
# run with:  python -m unittest discover -s Kyber -v

import os
import random
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from auxiliary import q, SampleNTT, poly_sub, mat_vec_mul, intt_vec
from kpke import (
    PARAMS, _get_params, ek_length, dk_length, ciphertext_length,
    _compress_poly, _decompress_poly, _encode_vec, _decode_vec, _sample_matrix,
    KPKE_KeyGen, KPKE_Encrypt, KPKE_Decrypt,
)


def rand_bytes(rng, size=32):
    return bytes(rng.randrange(256) for _ in range(size))


def unpack_12bit(blob):
    # pull the raw 12-bit values out without going through ByteDecode
    # (which would reduce them mod q and hide any bad values)
    vals = []
    for i in range(0, len(blob), 3):
        b0, b1, b2 = blob[i:i + 3]
        vals.append(b0 | ((b1 & 0x0F) << 8))
        vals.append((b1 >> 4) | (b2 << 4))
    return vals


class TestParams(unittest.TestCase):

    def test_param_sets(self):
        # Table 2
        self.assertEqual(PARAMS, {
            "ML-KEM-512":  {"k": 2, "eta1": 3, "eta2": 2, "du": 10, "dv": 4},
            "ML-KEM-768":  {"k": 3, "eta1": 2, "eta2": 2, "du": 10, "dv": 4},
            "ML-KEM-1024": {"k": 4, "eta1": 2, "eta2": 2, "du": 11, "dv": 5},
        })
        self.assertEqual(_get_params("ML-KEM-512"), (2, 3, 2, 10, 4))
        self.assertEqual(_get_params("ML-KEM-768"), (3, 2, 2, 10, 4))
        self.assertEqual(_get_params("ML-KEM-1024"), (4, 2, 2, 11, 5))

    def test_unknown_param_set(self):
        for name in ("", "ML-KEM-256", "Kyber512", "ml-kem-512"):
            for fn in (_get_params, ek_length, dk_length, ciphertext_length):
                with self.assertRaises(ValueError):
                    fn(name)

    def test_sizes(self):
        # (ek, dk, c) sizes, should match Table 3
        sizes = {
            "ML-KEM-512":  (800, 768, 768),
            "ML-KEM-768":  (1184, 1152, 1088),
            "ML-KEM-1024": (1568, 1536, 1568),
        }
        for name, (ek, dk, c) in sizes.items():
            self.assertEqual(ek_length(name), ek)
            self.assertEqual(dk_length(name), dk)
            self.assertEqual(ciphertext_length(name), c)

    def test_encode_decode_vec(self):
        rng = random.Random(101)
        for k in (2, 3, 4):
            for d in (4, 10, 12):
                m = q if d == 12 else 1 << d
                vec = [[rng.randrange(m) for _ in range(256)] for _ in range(k)]
                enc = _encode_vec(vec, d)
                self.assertEqual(len(enc), k * 32 * d)
                self.assertEqual(_decode_vec(enc, d, k), vec)

    def test_compress_poly_roundtrip(self):
        for d in (1, 4, 5, 10, 11):
            poly = [i % (1 << d) for i in range(256)]
            self.assertEqual(_compress_poly(_decompress_poly(poly, d), d), poly)

    def test_matrix_index_order(self):
        # A[i][j] = SampleNTT(rho || j || i), easy to get backwards
        rho = bytes(range(32))
        k = 3
        A = _sample_matrix(rho, k)
        self.assertEqual(len(A), k)
        for i in range(k):
            self.assertEqual(len(A[i]), k)
            for j in range(k):
                self.assertEqual(A[i][j], SampleNTT(rho + bytes([j, i])))
                if i != j:
                    self.assertNotEqual(A[i][j], A[j][i])


class TestKPKE(unittest.TestCase):

    def test_keygen(self):
        d = bytes(range(32))
        for name, p in PARAMS.items():
            k, eta1 = p["k"], p["eta1"]

            ek, dk = KPKE_KeyGen(d, name)
            self.assertEqual(len(ek), ek_length(name))
            self.assertEqual(len(dk), dk_length(name))

            for x in unpack_12bit(ek[:384 * k]) + unpack_12bit(dk):
                self.assertLess(x, q)

            # recover e = t - A*s and check both s and e look like CBD samples
            t_hat = _decode_vec(ek[:384 * k], 12, k)
            s_hat = _decode_vec(dk, 12, k)
            A = _sample_matrix(ek[384 * k:], k)

            As = mat_vec_mul(A, s_hat)
            e_hat = [poly_sub(t_hat[i], As[i]) for i in range(k)]

            for vec in (intt_vec(s_hat), intt_vec(e_hat)):
                for poly in vec:
                    for c in poly:
                        self.assertTrue(c <= eta1 or c >= q - eta1,
                                        f"{name}: {c} is too big for eta={eta1}")

    def test_rho_depends_on_k(self):
        # since k gets hashed in with d, the same d should give different
        # rho for each parameter set
        d = b"\x5a" * 32
        rhos = {KPKE_KeyGen(d, name)[0][-32:] for name in PARAMS}
        self.assertEqual(len(rhos), len(PARAMS))

    def test_deterministic(self):
        d, m, r = b"\x11" * 32, b"\x22" * 32, b"\x33" * 32
        for name in PARAMS:
            ek, dk = KPKE_KeyGen(d, name)
            self.assertEqual(KPKE_KeyGen(d, name), (ek, dk))
            self.assertEqual(KPKE_Encrypt(ek, m, r, name), KPKE_Encrypt(ek, m, r, name))

    def test_edge_case_messages(self):
        messages = [
            b"\x00" * 32,
            b"\xff" * 32,
            b"\xaa" * 32,
            b"\x55" * 32,
            b"\x01" + b"\x00" * 31,
            b"\x00" * 31 + b"\x80",
            bytes(range(32)),
        ]
        rng = random.Random(2025)
        for name in PARAMS:
            ek, dk = KPKE_KeyGen(rand_bytes(rng), name)
            for m in messages:
                c = KPKE_Encrypt(ek, m, rand_bytes(rng), name)
                self.assertEqual(len(c), ciphertext_length(name))
                self.assertEqual(KPKE_Decrypt(dk, c, name), m, f"{name}, m={m.hex()}")

    def test_random_messages(self):
        rng = random.Random(424242)
        for name in PARAMS:
            for trial in range(10):
                d, m, r = rand_bytes(rng), rand_bytes(rng), rand_bytes(rng)
                ek, dk = KPKE_KeyGen(d, name)
                c = KPKE_Encrypt(ek, m, r, name)
                self.assertEqual(KPKE_Decrypt(dk, c, name), m, f"{name} trial {trial}")

    def test_different_r(self):
        m = b"Post-Quantum Cryptography ML-KEM"
        for name in PARAMS:
            ek, dk = KPKE_KeyGen(b"\x01" * 32, name)
            c1 = KPKE_Encrypt(ek, m, b"\x10" * 32, name)
            c2 = KPKE_Encrypt(ek, m, b"\x20" * 32, name)
            self.assertNotEqual(c1, c2)
            self.assertEqual(KPKE_Decrypt(dk, c1, name), m)
            self.assertEqual(KPKE_Decrypt(dk, c2, name), m)

    def test_wrong_key(self):
        m = b"Secret 32-byte plaintext message"
        for name in PARAMS:
            ek, _ = KPKE_KeyGen(b"\x01" * 32, name)
            _, other_dk = KPKE_KeyGen(b"\x02" * 32, name)
            c = KPKE_Encrypt(ek, m, b"\x99" * 32, name)
            self.assertNotEqual(KPKE_Decrypt(other_dk, c, name), m)

    def test_tampered_ciphertext(self):
        m = bytes(32)
        for name in PARAMS:
            ek, dk = KPKE_KeyGen(b"\x05" * 32, name)
            c = bytearray(KPKE_Encrypt(ek, m, b"\x77" * 32, name))
            c[-1] ^= 0xFF  # mess up the end of c2
            self.assertNotEqual(KPKE_Decrypt(dk, bytes(c), name), m)

    def test_bad_input_lengths(self):
        m = r = bytes(32)
        for name in PARAMS:
            ek, dk = KPKE_KeyGen(bytes(32), name)
            c = KPKE_Encrypt(ek, m, r, name)

            with self.assertRaises(AssertionError):
                KPKE_KeyGen(bytes(31), name)
            with self.assertRaises(AssertionError):
                KPKE_KeyGen(bytes(33), name)

            with self.assertRaises(AssertionError):
                KPKE_Encrypt(ek[:-1], m, r, name)
            with self.assertRaises(AssertionError):
                KPKE_Encrypt(ek, m[:-1], r, name)
            with self.assertRaises(AssertionError):
                KPKE_Encrypt(ek, m, r[:-1], name)

            with self.assertRaises(AssertionError):
                KPKE_Decrypt(dk[:-1], c, name)
            with self.assertRaises(AssertionError):
                KPKE_Decrypt(dk, c[:-1], name)


if __name__ == "__main__":
    unittest.main(verbosity=2)
