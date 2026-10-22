# Tests for auxiliary.py
# run with:  python -m unittest discover -s Kyber -v

import hashlib
import os
import random
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from auxiliary import (
    n, q, ZETA, ZETAS, _bit_rev_7,
    PRF, H, J, G, XOF,
    BitsToBytes, BytesToBits, ByteEncode, ByteDecode, Compress, Decompress,
    SampleNTT, SamplePolyCBD,
    NTT, NTT_inv, BaseCaseMultiply, MultiplyNTTs,
    poly_add, poly_sub, vec_add, mat_vec_mul, mat_T_vec_mul, inner_product,
    ntt_vec, intt_vec,
)


def schoolbook_mul(a, b):
    # slow multiplication in Z_q[X]/(X^256 + 1) to check the NTT against
    res = [0] * 256
    for i in range(256):
        for j in range(256):
            prod = a[i] * b[j]
            if i + j >= 256:
                res[i + j - 256] -= prod
            else:
                res[i + j] += prod
    return [x % q for x in res]


def rand_poly(rng, m=q):
    return [rng.randrange(m) for _ in range(256)]


class TestConstants(unittest.TestCase):

    def test_constants(self):
        self.assertEqual(n, 256)
        self.assertEqual(q, 3329)
        self.assertEqual(ZETA, 17)
        # 17 should be a primitive 256th root of unity mod q
        self.assertEqual(pow(ZETA, 128, q), q - 1)
        self.assertEqual(pow(ZETA, 256, q), 1)
        for e in range(1, 256):
            self.assertNotEqual(pow(ZETA, e, q), 1)

    def test_bit_rev(self):
        self.assertEqual(_bit_rev_7(0), 0)
        self.assertEqual(_bit_rev_7(1), 64)
        self.assertEqual(_bit_rev_7(64), 1)
        self.assertEqual(_bit_rev_7(127), 127)
        self.assertEqual(_bit_rev_7(0b0000011), 0b1100000)

        # should be a permutation that undoes itself
        outputs = set()
        for r in range(128):
            rev = _bit_rev_7(r)
            self.assertTrue(0 <= rev < 128)
            self.assertEqual(_bit_rev_7(rev), r)
            outputs.add(rev)
        self.assertEqual(len(outputs), 128)

    def test_zetas_table(self):
        self.assertEqual(len(ZETAS), 128)
        for i in range(128):
            self.assertEqual(ZETAS[i], pow(ZETA, _bit_rev_7(i), q), f"ZETAS[{i}]")


class TestHashes(unittest.TestCase):

    def test_prf(self):
        seed = bytes(range(32))
        for eta in (2, 3):
            for b in (0, 1, 127, 255):
                out = PRF(eta, seed, b)
                self.assertEqual(len(out), 64 * eta)
                self.assertEqual(out, hashlib.shake_256(seed + bytes([b])).digest(64 * eta))

    def test_prf_different_inputs(self):
        s1 = b"\x01" * 32
        s2 = b"\x02" * 32
        self.assertNotEqual(PRF(2, s1, 0), PRF(2, s1, 1))
        self.assertNotEqual(PRF(2, s1, 0), PRF(2, s2, 0))
        # eta only changes the output length
        self.assertEqual(PRF(2, s1, 0), PRF(3, s1, 0)[:128])

    def test_prf_bad_args(self):
        seed = bytes(32)
        bad_calls = [(1, seed, 0), (4, seed, 0), (2, b"short", 0),
                     (2, seed, -1), (2, seed, 256)]
        for args in bad_calls:
            with self.assertRaises(AssertionError):
                PRF(*args)

    def test_h(self):
        # SHA3-256("") from the NIST examples
        self.assertEqual(H(b"").hex(),
                         "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a")
        msg = b"ML-KEM FIPS 203 test input"
        self.assertEqual(H(msg), hashlib.sha3_256(msg).digest())

    def test_j(self):
        for msg in (b"", b"abc", b"\xff" * 100):
            self.assertEqual(J(msg), hashlib.shake_256(msg).digest(32))

    def test_g(self):
        for msg in (b"", b"seed_and_rank", os.urandom(33)):
            a, b = G(msg)
            self.assertEqual(len(a), 32)
            self.assertEqual(len(b), 32)
            self.assertNotEqual(a, b)
            self.assertEqual(a + b, hashlib.sha3_512(msg).digest())

    def test_xof_squeeze_in_pieces(self):
        data = b"0123456789abcdef" * 2 + b"\x01\x02"
        expected = hashlib.shake_128(data).digest(60)

        x = XOF()
        x.absorb(data)
        self.assertEqual(b"".join(x.squeeze(3) for _ in range(20)), expected)

        # absorbing in chunks + uneven squeezes should give the same stream
        x = XOF()
        x.absorb(data[:10])
        x.absorb(data[10:25])
        x.absorb(data[25:])
        self.assertEqual(x.squeeze(17) + x.squeeze(43), expected)

    def test_xof_no_absorb_after_squeeze(self):
        x = XOF()
        x.absorb(b"initial")
        x.squeeze(3)
        with self.assertRaises(AssertionError):
            x.absorb(b"more data")


class TestEncoding(unittest.TestCase):

    def test_bits_bytes_known(self):
        self.assertEqual(BitsToBytes([]), b"")
        self.assertEqual(BytesToBits(b""), [])

        # least significant bit comes first
        cases = [
            (b"\x01", [1, 0, 0, 0, 0, 0, 0, 0]),
            (b"\x80", [0, 0, 0, 0, 0, 0, 0, 1]),
            (b"\x0b", [1, 1, 0, 1, 0, 0, 0, 0]),
        ]
        for byte, bits in cases:
            self.assertEqual(BitsToBytes(bits), byte)
            self.assertEqual(BytesToBits(byte), bits)

    def test_bits_bytes_roundtrip(self):
        rng = random.Random(42)
        for length in (1, 4, 32, 64):
            raw = bytes(rng.randrange(256) for _ in range(length))
            bits = BytesToBits(raw)
            self.assertEqual(len(bits), 8 * length)
            self.assertTrue(set(bits) <= {0, 1})
            self.assertEqual(BitsToBytes(bits), raw)

    def test_bits_to_bytes_bad_length(self):
        for bad in (1, 7, 9, 15):
            with self.assertRaises(AssertionError):
                BitsToBytes([0] * bad)

    def test_byte_encode_decode(self):
        rng = random.Random(12345)
        for d in range(1, 13):
            m = q if d == 12 else 1 << d

            zeros = [0] * 256
            enc = ByteEncode(zeros, d)
            self.assertEqual(enc, bytes(32 * d))
            self.assertEqual(ByteDecode(enc, d), zeros)

            biggest = [m - 1] * 256
            self.assertEqual(ByteDecode(ByteEncode(biggest, d), d), biggest)

            poly = rand_poly(rng, m)
            enc = ByteEncode(poly, d)
            self.assertEqual(len(enc), 32 * d)
            self.assertEqual(ByteDecode(enc, d), poly)

    def test_byte_decode_12_reduces(self):
        # all 1 bits -> every value is 4095, which should get reduced mod q
        out = ByteDecode(b"\xff" * (32 * 12), 12)
        self.assertEqual(out, [4095 % q] * 256)

    def test_byte_encode_decode_bad_args(self):
        with self.assertRaises(AssertionError):
            ByteEncode([0] * 256, 0)
        with self.assertRaises(AssertionError):
            ByteEncode([0] * 256, 13)
        with self.assertRaises(AssertionError):
            ByteEncode([0] * 255, 4)
        with self.assertRaises(AssertionError):
            ByteDecode(bytes(31), 1)
        with self.assertRaises(AssertionError):
            ByteDecode(bytes(32), 0)
        with self.assertRaises(AssertionError):
            ByteDecode(bytes(32 * 13), 13)

    def test_compress_decompress_roundtrip(self):
        # Compress(Decompress(y)) == y should hold for every y and d < 12
        for d in range(1, 12):
            for y in range(1 << d):
                x = Decompress(y, d)
                self.assertTrue(0 <= x < q)
                self.assertEqual(Compress(x, d), y, f"d={d}, y={y}")

    def test_compress_error(self):
        # going the other way loses info, but the error should be at most
        # about q / 2^(d+1)
        for d in range(1, 12):
            max_err = (q + (1 << d)) // (2 << d)
            for x in range(0, q, 7):
                y = Compress(x, d)
                self.assertTrue(0 <= y < (1 << d))
                diff = (Decompress(y, d) - x) % q
                if diff > q // 2:
                    diff -= q
                self.assertLessEqual(abs(diff), max_err)

    def test_compress_d1(self):
        self.assertEqual(Decompress(0, 1), 0)
        self.assertEqual(Decompress(1, 1), 1665)
        self.assertEqual(Compress(0, 1), 0)
        self.assertEqual(Compress(1665, 1), 1)
        self.assertEqual(Compress(q - 1, 1), 0)

    def test_compress_bad_d(self):
        for d in (0, 12, 13):
            with self.assertRaises(AssertionError):
                Compress(0, d)
            with self.assertRaises(AssertionError):
                Decompress(0, d)


class TestSampling(unittest.TestCase):

    def test_sample_ntt_basic(self):
        seed = bytes(range(32))
        a = SampleNTT(seed + b"\x00\x00")
        self.assertEqual(len(a), 256)
        self.assertTrue(all(0 <= x < q for x in a))
        self.assertEqual(SampleNTT(seed + b"\x00\x00"), a)
        self.assertNotEqual(SampleNTT(seed + b"\x00\x01"), a)

    def test_sample_ntt_against_manual(self):
        # redo the rejection sampling by hand straight from the SHAKE output
        B = b"\x42" * 32 + b"\x01\x02"
        stream = hashlib.shake_128(B).digest(1024)
        expected = []
        i = 0
        while len(expected) < 256:
            c0, c1, c2 = stream[i:i + 3]
            i += 3
            d1 = c0 + 256 * (c1 % 16)
            d2 = (c1 // 16) + 16 * c2
            if d1 < q:
                expected.append(d1)
            if d2 < q and len(expected) < 256:
                expected.append(d2)
        self.assertEqual(SampleNTT(B), expected)

    def test_sample_ntt_bad_length(self):
        for size in (33, 35):
            with self.assertRaises(AssertionError):
                SampleNTT(bytes(size))

    def test_cbd_range(self):
        for eta in (2, 3):
            # all zeros, and all ones (x = y = eta), both cancel out to 0
            self.assertEqual(SamplePolyCBD(bytes(64 * eta), eta), [0] * 256)
            self.assertEqual(SamplePolyCBD(b"\xff" * (64 * eta), eta), [0] * 256)

            poly = SamplePolyCBD(PRF(eta, bytes(range(32)), 0), eta)
            self.assertEqual(len(poly), 256)
            for c in poly:
                self.assertTrue(c <= eta or c >= q - eta, f"{c} out of range (eta={eta})")

    def test_cbd_eta2_by_hand(self):
        # with eta=2 each nibble is one coefficient: low 2 bits - high 2 bits
        #   0x33 -> 0011 0011 -> 2, 2
        #   0xcc -> 1100 1100 -> -2, -2
        buf = b"\x33\xcc" + bytes(126)
        poly = SamplePolyCBD(buf, 2)
        self.assertEqual(poly[:4], [2, 2, q - 2, q - 2])
        self.assertEqual(poly[4:], [0] * 252)

    def test_cbd_bad_args(self):
        with self.assertRaises(AssertionError):
            SamplePolyCBD(bytes(128), 1)
        with self.assertRaises(AssertionError):
            SamplePolyCBD(bytes(128), 3)
        with self.assertRaises(AssertionError):
            SamplePolyCBD(bytes(192), 2)


class TestNTT(unittest.TestCase):

    def test_roundtrip(self):
        rng = random.Random(99)
        f = rand_poly(rng)
        f_orig = list(f)

        f_hat = NTT(f)
        self.assertEqual(f, f_orig, "NTT modified its input")
        self.assertEqual(len(f_hat), 256)
        self.assertTrue(all(0 <= x < q for x in f_hat))

        f_hat_orig = list(f_hat)
        back = NTT_inv(f_hat)
        self.assertEqual(f_hat, f_hat_orig, "NTT_inv modified its input")
        self.assertEqual(back, f)

    def test_zero_and_one(self):
        zero = [0] * 256
        self.assertEqual(NTT(zero), zero)
        self.assertEqual(NTT_inv(zero), zero)

        # 1 mod (X^2 - gamma) is just 1 for every factor, so NTT(1) = [1, 0, 1, 0, ...]
        one = [1] + [0] * 255
        one_hat = [1, 0] * 128
        self.assertEqual(NTT(one), one_hat)
        self.assertEqual(NTT_inv(one_hat), one)

    def test_linear(self):
        rng = random.Random(2024)
        f = rand_poly(rng)
        g = rand_poly(rng)
        self.assertEqual(NTT(poly_add(f, g)), poly_add(NTT(f), NTT(g)))

        c = 1234
        self.assertEqual(NTT([c * x % q for x in f]), [c * x % q for x in NTT(f)])

    def test_base_case_multiply(self):
        c0, c1 = BaseCaseMultiply(3, 5, 7, 11, 17)
        self.assertEqual(c0, (3 * 7 + 5 * 11 * 17) % q)
        self.assertEqual(c1, (3 * 11 + 5 * 7) % q)

    def test_multiply_matches_schoolbook(self):
        rng = random.Random(31415)
        for _ in range(5):
            a = rand_poly(rng)
            b = rand_poly(rng)
            self.assertEqual(NTT_inv(MultiplyNTTs(NTT(a), NTT(b))), schoolbook_mul(a, b))

    def test_multiply_ring_properties(self):
        rng = random.Random(2718)
        a, b, c = rand_poly(rng), rand_poly(rng), rand_poly(rng)
        one = NTT([1] + [0] * 255)
        mul = MultiplyNTTs

        self.assertEqual(mul(a, b), mul(b, a))
        self.assertEqual(mul(a, one), a)
        self.assertEqual(mul(mul(a, b), c), mul(a, mul(b, c)))
        self.assertEqual(mul(a, poly_add(b, c)), poly_add(mul(a, b), mul(a, c)))

    def test_vector_helpers(self):
        rng = random.Random(777)
        k = 3
        u = [rand_poly(rng) for _ in range(k)]
        v = [rand_poly(rng) for _ in range(k)]

        for i in range(k):
            self.assertEqual(poly_sub(poly_add(u[i], v[i]), v[i]), u[i])

        u_hat = ntt_vec(u)
        self.assertEqual(intt_vec(u_hat), u)

        total = vec_add(u, v)
        for i in range(k):
            self.assertEqual(total[i], poly_add(u[i], v[i]))

        # <u, A v> should equal <A^T u, v>
        A = [[rand_poly(rng) for _ in range(k)] for _ in range(k)]
        v_hat = ntt_vec(v)
        self.assertEqual(inner_product(u_hat, mat_vec_mul(A, v_hat)),
                         inner_product(mat_T_vec_mul(A, u_hat), v_hat))

    def test_bad_lengths(self):
        with self.assertRaises(AssertionError):
            NTT([0] * 255)
        with self.assertRaises(AssertionError):
            NTT_inv([0] * 257)
        with self.assertRaises(AssertionError):
            MultiplyNTTs([0] * 255, [0] * 256)
        with self.assertRaises(AssertionError):
            MultiplyNTTs([0] * 256, [0] * 255)


if __name__ == "__main__":
    unittest.main(verbosity=2)
