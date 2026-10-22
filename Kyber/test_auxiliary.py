"""
Unit tests for Kyber/auxiliary.py (FIPS 203 Section 4 Auxiliary Algorithms).

Can be run directly or via unittest / pytest:
    python Kyber/test_auxiliary.py
    python -m unittest discover -s Kyber -v
"""

import hashlib
import os
import random
import sys
import unittest

# Ensure imports work regardless of current working directory
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from auxiliary import (
    n,
    q,
    ZETA,
    ZETAS,
    _bit_rev_7,
    PRF,
    H,
    J,
    G,
    XOF,
    BitsToBytes,
    BytesToBits,
    ByteEncode,
    ByteDecode,
    Compress,
    Decompress,
    SampleNTT,
    SamplePolyCBD,
    NTT,
    NTT_inv,
    BaseCaseMultiply,
    MultiplyNTTs,
    poly_add,
    poly_sub,
    vec_add,
    mat_vec_mul,
    mat_T_vec_mul,
    inner_product,
    ntt_vec,
    intt_vec,
)


def _poly_mul_schoolbook(a, b):
    """Reference schoolbook multiplication in R_q = Z_q[X] / (X^256 + 1)."""
    result = [0] * 256
    for i in range(256):
        for j in range(256):
            coeff = (a[i] * b[j]) % q
            idx = (i + j) % 256
            sign = -1 if (i + j) >= 256 else 1
            result[idx] = (result[idx] + sign * coeff) % q
    return result


class TestConstantsAndBitRev(unittest.TestCase):
    """Tests for Section 2.3 global constants, _bit_rev_7, and Appendix A ZETAS."""

    def test_global_constants(self):
        self.assertEqual(n, 256)
        self.assertEqual(q, 3329)
        self.assertEqual(ZETA, 17)
        # 17 is a primitive 256th root of unity mod 3329: 17^128 ≡ -1 (mod 3329)
        self.assertEqual(pow(ZETA, 128, q), q - 1)
        self.assertEqual(pow(ZETA, 256, q), 1)
        for k in range(1, 256):
            self.assertNotEqual(pow(ZETA, k, q), 1)

    def test_bit_rev_7_known_values_and_involution(self):
        self.assertEqual(_bit_rev_7(0), 0)
        self.assertEqual(_bit_rev_7(1), 64)
        self.assertEqual(_bit_rev_7(64), 1)
        self.assertEqual(_bit_rev_7(127), 127)
        self.assertEqual(_bit_rev_7(0b0000011), 0b1100000)

        seen = set()
        for r in range(128):
            rev = _bit_rev_7(r)
            self.assertTrue(0 <= rev < 128)
            self.assertEqual(_bit_rev_7(rev), r)
            seen.add(rev)
        self.assertEqual(len(seen), 128)

    def test_zetas_table_matches_formula(self):
        self.assertEqual(len(ZETAS), 128)
        for i in range(128):
            expected = pow(ZETA, _bit_rev_7(i), q)
            self.assertEqual(ZETAS[i], expected, f"Mismatch at ZETAS[{i}]")


class TestCryptographicFunctions(unittest.TestCase):
    """Tests for Section 4.1 cryptographic functions (PRF, H, J, G, XOF)."""

    def test_prf_output_lengths_and_values(self):
        seed = bytes(range(32))
        for eta in (2, 3):
            for b_val in (0, 1, 127, 255):
                out = PRF(eta, seed, b_val)
                self.assertEqual(len(out), 64 * eta)
                expected = hashlib.shake_256(seed + bytes([b_val])).digest(64 * eta)
                self.assertEqual(out, expected)

    def test_prf_domain_separation(self):
        seed1 = b"\x01" * 32
        seed2 = b"\x02" * 32
        self.assertNotEqual(PRF(2, seed1, 0), PRF(2, seed1, 1))
        self.assertNotEqual(PRF(2, seed1, 0), PRF(2, seed2, 0))
        self.assertEqual(PRF(2, seed1, 0), PRF(3, seed1, 0)[:128])

    def test_prf_invalid_inputs(self):
        valid_seed = b"\x00" * 32
        with self.assertRaises(AssertionError):
            PRF(1, valid_seed, 0)
        with self.assertRaises(AssertionError):
            PRF(4, valid_seed, 0)
        with self.assertRaises(AssertionError):
            PRF(2, b"short", 0)
        with self.assertRaises(AssertionError):
            PRF(2, valid_seed, -1)
        with self.assertRaises(AssertionError):
            PRF(2, valid_seed, 256)

    def test_h_sha3_256(self):
        # NIST empty-message vector for SHA3-256
        empty_expected = bytes.fromhex(
            "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
        )
        self.assertEqual(H(b""), empty_expected)

        msg = b"ML-KEM FIPS 203 test input"
        self.assertEqual(len(H(msg)), 32)
        self.assertEqual(H(msg), hashlib.sha3_256(msg).digest())

    def test_j_shake256(self):
        for msg in (b"", b"abc", b"\xff" * 100):
            out = J(msg)
            self.assertEqual(len(out), 32)
            self.assertEqual(out, hashlib.shake_256(msg).digest(32))

    def test_g_sha3_512_split(self):
        for msg in (b"", b"seed_and_rank", os.urandom(33)):
            a, b = G(msg)
            self.assertEqual(len(a), 32)
            self.assertEqual(len(b), 32)
            self.assertNotEqual(a, b)
            self.assertEqual(a + b, hashlib.sha3_512(msg).digest())

    def test_xof_streaming_absorb_and_squeeze(self):
        data = b"0123456789abcdef" * 2 + b"\x01\x02"
        expected_stream = hashlib.shake_128(data).digest(60)

        # Single absorb, multiple incremental squeezes
        xof1 = XOF()
        xof1.absorb(data)
        chunks = [xof1.squeeze(3) for _ in range(20)]
        self.assertEqual(b"".join(chunks), expected_stream)

        # Multiple absorbs, mixed-size squeezes
        xof2 = XOF()
        xof2.absorb(data[:10])
        xof2.absorb(data[10:25])
        xof2.absorb(data[25:])
        part1 = xof2.squeeze(17)
        part2 = xof2.squeeze(43)
        self.assertEqual(part1 + part2, expected_stream)

    def test_xof_absorb_after_squeeze_disallowed(self):
        xof = XOF()
        xof.absorb(b"initial")
        xof.squeeze(3)
        with self.assertRaises(AssertionError):
            xof.absorb(b"more data")


class TestConversionAndCompression(unittest.TestCase):
    """Tests for Section 4.2.1 conversion and compression algorithms."""

    def test_bits_to_bytes_and_bytes_to_bits_known_vectors(self):
        self.assertEqual(BitsToBytes([]), b"")
        self.assertEqual(BytesToBits(b""), [])

        # Little-endian bit order within each byte
        self.assertEqual(BitsToBytes([1, 0, 0, 0, 0, 0, 0, 0]), b"\x01")
        self.assertEqual(BitsToBytes([0, 0, 0, 0, 0, 0, 0, 1]), b"\x80")
        self.assertEqual(BitsToBytes([1, 1, 0, 1, 0, 0, 0, 0]), b"\x0b")

        self.assertEqual(BytesToBits(b"\x01"), [1, 0, 0, 0, 0, 0, 0, 0])
        self.assertEqual(BytesToBits(b"\x80"), [0, 0, 0, 0, 0, 0, 0, 1])
        self.assertEqual(BytesToBits(b"\x0b"), [1, 1, 0, 1, 0, 0, 0, 0])

    def test_bits_bytes_roundtrip(self):
        rng = random.Random(42)
        for length in (1, 4, 32, 64):
            raw = bytes(rng.randrange(256) for _ in range(length))
            bits = BytesToBits(raw)
            self.assertEqual(len(bits), 8 * length)
            self.assertTrue(all(b in (0, 1) for b in bits))
            self.assertEqual(BitsToBytes(bits), raw)

    def test_bits_to_bytes_invalid_length(self):
        for bad_len in (1, 7, 9, 15):
            with self.assertRaises(AssertionError):
                BitsToBytes([0] * bad_len)

    def test_byte_encode_decode_roundtrip_all_d(self):
        rng = random.Random(12345)
        for d in range(1, 13):
            m = (1 << d) if d < 12 else q

            # All zeros
            zeros = [0] * 256
            enc_zeros = ByteEncode(zeros, d)
            self.assertEqual(len(enc_zeros), 32 * d)
            self.assertEqual(enc_zeros, b"\x00" * (32 * d))
            self.assertEqual(ByteDecode(enc_zeros, d), zeros)

            # Max valid values (m - 1)
            max_vals = [m - 1] * 256
            self.assertEqual(ByteDecode(ByteEncode(max_vals, d), d), max_vals)

            # Random valid polynomial
            poly = [rng.randrange(m) for _ in range(256)]
            encoded = ByteEncode(poly, d)
            self.assertEqual(len(encoded), 32 * d)
            decoded = ByteDecode(encoded, d)
            self.assertEqual(decoded, poly)

    def test_byte_decode_d12_reduces_mod_q(self):
        # 0xFF bytes give 12-bit integers equal to 4095; ByteDecode_12 reduces mod q (4095 % 3329 = 766)
        all_ones = b"\xff" * (32 * 12)
        decoded = ByteDecode(all_ones, 12)
        self.assertEqual(len(decoded), 256)
        self.assertTrue(all(x == 4095 % q for x in decoded))

    def test_byte_encode_decode_invalid_arguments(self):
        with self.assertRaises(AssertionError):
            ByteEncode([0] * 256, 0)
        with self.assertRaises(AssertionError):
            ByteEncode([0] * 256, 13)
        with self.assertRaises(AssertionError):
            ByteEncode([0] * 255, 4)
        with self.assertRaises(AssertionError):
            ByteDecode(b"\x00" * 31, 1)
        with self.assertRaises(AssertionError):
            ByteDecode(b"\x00" * 32, 0)
        with self.assertRaises(AssertionError):
            ByteDecode(b"\x00" * (32 * 13), 13)

    def test_compress_decompress_exact_roundtrip(self):
        # Property from FIPS 203 Section 4.2.1: Compress_d(Decompress_d(y)) == y for all d in 1..11
        for d in range(1, 12):
            two_d = 1 << d
            for y in range(two_d):
                decomp = Decompress(y, d)
                self.assertTrue(0 <= decomp < q)
                comp = Compress(decomp, d)
                self.assertEqual(comp, y, f"Failed for d={d}, y={y}")

    def test_compress_decompress_error_bound(self):
        # For any x in Z_q, |Decompress_d(Compress_d(x)) - x mod+- q| <= round(q / 2^(d+1))
        for d in range(1, 12):
            two_d = 1 << d
            max_err = (q + two_d) // (2 * two_d)
            for x in range(0, q, 7):
                y = Compress(x, d)
                self.assertTrue(0 <= y < two_d)
                x_prime = Decompress(y, d)
                diff = (x_prime - x) % q
                signed_diff = diff if diff <= q // 2 else diff - q
                self.assertLessEqual(abs(signed_diff), max_err)

    def test_compress_decompress_d1_known_values(self):
        self.assertEqual(Decompress(0, 1), 0)
        self.assertEqual(Decompress(1, 1), 1665)  # ceil(3329 / 2) = 1665
        self.assertEqual(Compress(0, 1), 0)
        self.assertEqual(Compress(1665, 1), 1)
        self.assertEqual(Compress(q - 1, 1), 0)

    def test_compress_decompress_invalid_d(self):
        for bad_d in (0, 12, 13):
            with self.assertRaises(AssertionError):
                Compress(0, bad_d)
            with self.assertRaises(AssertionError):
                Decompress(0, bad_d)


class TestSamplingAlgorithms(unittest.TestCase):
    """Tests for Section 4.2.2 sampling algorithms (SampleNTT, SamplePolyCBD)."""

    def test_sample_ntt_range_and_determinism(self):
        seed = bytes(range(32))
        b00 = seed + bytes([0, 0])
        b01 = seed + bytes([0, 1])

        a00 = SampleNTT(b00)
        self.assertEqual(len(a00), 256)
        self.assertTrue(all(0 <= coeff < q for coeff in a00))
        self.assertEqual(SampleNTT(b00), a00)
        self.assertNotEqual(SampleNTT(b01), a00)

    def test_sample_ntt_matches_manual_rejection_sampling(self):
        B = b"\x42" * 32 + b"\x01\x02"
        stream = hashlib.shake_128(B).digest(1024)
        expected = []
        pos = 0
        while len(expected) < 256:
            c0, c1, c2 = stream[pos], stream[pos + 1], stream[pos + 2]
            pos += 3
            d1 = c0 + 256 * (c1 % 16)
            d2 = (c1 // 16) + 16 * c2
            if d1 < q:
                expected.append(d1)
            if d2 < q and len(expected) < 256:
                expected.append(d2)
        self.assertEqual(SampleNTT(B), expected)

    def test_sample_ntt_invalid_length(self):
        with self.assertRaises(AssertionError):
            SampleNTT(b"\x00" * 33)
        with self.assertRaises(AssertionError):
            SampleNTT(b"\x00" * 35)

    def test_sample_poly_cbd_ranges_and_edge_cases(self):
        for eta in (2, 3):
            # All-zero input -> all-zero polynomial
            zeros = SamplePolyCBD(b"\x00" * (64 * eta), eta)
            self.assertEqual(zeros, [0] * 256)

            # All-0xFF input -> x = eta, y = eta -> x - y = 0 for all coefficients
            ones = SamplePolyCBD(b"\xff" * (64 * eta), eta)
            self.assertEqual(ones, [0] * 256)

            # Random input -> coefficients in [0, eta] or [q - eta, q - 1]
            prf_bytes = PRF(eta, bytes(range(32)), 0)
            poly = SamplePolyCBD(prf_bytes, eta)
            self.assertEqual(len(poly), 256)
            for c in poly:
                self.assertTrue(
                    (0 <= c <= eta) or (q - eta <= c < q),
                    f"Coefficient {c} out of range for eta={eta}",
                )

    def test_sample_poly_cbd_known_byte_pattern_eta2(self):
        # For eta=2, each 4-bit nibble produces one coefficient:
        # low 2 bits sum to x, high 2 bits sum to y, coeff = (x - y) mod q.
        # Byte 0x33 = 0b0011_0011 -> nibble 0 is 0b0011 (x=2, y=0 -> 2), nibble 1 is 0b0011 (x=2, y=0 -> 2)
        # Byte 0xCC = 0b1100_1100 -> nibble 0 is 0b1100 (x=0, y=2 -> q-2), nibble 1 is 0b1100 (x=0, y=2 -> q-2)
        buf = b"\x33" + b"\xcc" + b"\x00" * 126
        poly = SamplePolyCBD(buf, 2)
        self.assertEqual(poly[0], 2)
        self.assertEqual(poly[1], 2)
        self.assertEqual(poly[2], q - 2)
        self.assertEqual(poly[3], q - 2)
        self.assertEqual(poly[4:], [0] * 252)

    def test_sample_poly_cbd_invalid_inputs(self):
        with self.assertRaises(AssertionError):
            SamplePolyCBD(b"\x00" * 128, 1)
        with self.assertRaises(AssertionError):
            SamplePolyCBD(b"\x00" * 128, 3)
        with self.assertRaises(AssertionError):
            SamplePolyCBD(b"\x00" * 192, 2)


class TestNTTAndPolynomialArithmetic(unittest.TestCase):
    """Tests for Section 4.3 NTT, NTT_inv, MultiplyNTTs, and vector/matrix operations."""

    def test_ntt_roundtrip_and_immutability(self):
        rng = random.Random(99)
        f = [rng.randrange(q) for _ in range(256)]
        f_copy = list(f)

        f_hat = NTT(f)
        self.assertEqual(f, f_copy, "NTT should not mutate input")
        self.assertEqual(len(f_hat), 256)
        self.assertTrue(all(0 <= x < q for x in f_hat))

        f_hat_copy = list(f_hat)
        recovered = NTT_inv(f_hat)
        self.assertEqual(f_hat, f_hat_copy, "NTT_inv should not mutate input")
        self.assertEqual(recovered, f)

    def test_ntt_zero_and_one_polynomials(self):
        zero = [0] * 256
        self.assertEqual(NTT(zero), zero)
        self.assertEqual(NTT_inv(zero), zero)

        # Constant polynomial 1 has residue (1 + 0*X) mod (X^2 - gamma_i) in all 128 factors
        one = [1] + [0] * 255
        one_hat = [1 if i % 2 == 0 else 0 for i in range(256)]
        self.assertEqual(NTT(one), one_hat)
        self.assertEqual(NTT_inv(one_hat), one)

    def test_ntt_linearity(self):
        rng = random.Random(2024)
        f = [rng.randrange(q) for _ in range(256)]
        g = [rng.randrange(q) for _ in range(256)]
        scalar = 1234

        lhs = NTT(poly_add(f, g))
        rhs = poly_add(NTT(f), NTT(g))
        self.assertEqual(lhs, rhs)

        scaled_f = [(scalar * c) % q for c in f]
        scaled_f_hat = [(scalar * c) % q for c in NTT(f)]
        self.assertEqual(NTT(scaled_f), scaled_f_hat)

    def test_base_case_multiply(self):
        # (a0 + a1*X)(b0 + b1*X) = (a0*b0 + a1*b1*gamma) + (a0*b1 + a1*b0)*X (mod X^2 - gamma, q)
        c0, c1 = BaseCaseMultiply(3, 5, 7, 11, 17)
        self.assertEqual(c0, (3 * 7 + 5 * 11 * 17) % q)
        self.assertEqual(c1, (3 * 11 + 5 * 7) % q)

    def test_multiply_ntts_matches_schoolbook(self):
        rng = random.Random(31415)
        for _ in range(5):
            a = [rng.randrange(q) for _ in range(256)]
            b = [rng.randrange(q) for _ in range(256)]
            expected = _poly_mul_schoolbook(a, b)
            actual = NTT_inv(MultiplyNTTs(NTT(a), NTT(b)))
            self.assertEqual(actual, expected)

    def test_multiply_ntts_algebraic_properties(self):
        rng = random.Random(2718)
        a_hat = [rng.randrange(q) for _ in range(256)]
        b_hat = [rng.randrange(q) for _ in range(256)]
        c_hat = [rng.randrange(q) for _ in range(256)]
        one_hat = NTT([1] + [0] * 255)

        # Commutativity
        self.assertEqual(MultiplyNTTs(a_hat, b_hat), MultiplyNTTs(b_hat, a_hat))
        # Identity
        self.assertEqual(MultiplyNTTs(a_hat, one_hat), a_hat)
        # Associativity
        self.assertEqual(
            MultiplyNTTs(MultiplyNTTs(a_hat, b_hat), c_hat),
            MultiplyNTTs(a_hat, MultiplyNTTs(b_hat, c_hat)),
        )
        # Distributivity over addition
        self.assertEqual(
            MultiplyNTTs(a_hat, poly_add(b_hat, c_hat)),
            poly_add(MultiplyNTTs(a_hat, b_hat), MultiplyNTTs(a_hat, c_hat)),
        )

    def test_poly_and_vector_matrix_helpers(self):
        rng = random.Random(777)
        k = 3
        u = [[rng.randrange(q) for _ in range(256)] for _ in range(k)]
        v = [[rng.randrange(q) for _ in range(256)] for _ in range(k)]

        # poly_add / poly_sub inverse
        for i in range(k):
            self.assertEqual(poly_sub(poly_add(u[i], v[i]), v[i]), u[i])

        # ntt_vec / intt_vec roundtrip
        u_hat = ntt_vec(u)
        self.assertEqual(intt_vec(u_hat), u)

        # vec_add
        sum_vec = vec_add(u, v)
        for i in range(k):
            self.assertEqual(sum_vec[i], poly_add(u[i], v[i]))

        # Transpose adjoint identity in T_q: <u_hat, A_hat * v_hat> == <A_hat^T * u_hat, v_hat>
        A_hat = [
            [[rng.randrange(q) for _ in range(256)] for _ in range(k)]
            for _ in range(k)
        ]
        v_hat = ntt_vec(v)
        lhs = inner_product(u_hat, mat_vec_mul(A_hat, v_hat))
        rhs = inner_product(mat_T_vec_mul(A_hat, u_hat), v_hat)
        self.assertEqual(lhs, rhs)

    def test_ntt_and_multiply_invalid_lengths(self):
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
