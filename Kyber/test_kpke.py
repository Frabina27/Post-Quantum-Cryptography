"""
Unit tests for Kyber/kpke.py (FIPS 203 Section 5 K-PKE Component Scheme).

Can be run directly or via unittest / pytest:
    python Kyber/test_kpke.py
    python -m unittest discover -s Kyber -v
"""

import os
import random
import sys
import unittest

# Ensure imports work regardless of current working directory
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from auxiliary import (
    q,
    SampleNTT,
    poly_sub,
    mat_vec_mul,
    intt_vec,
)
from kpke import (
    PARAMS,
    _get_params,
    ek_length,
    dk_length,
    ciphertext_length,
    _compress_poly,
    _decompress_poly,
    _encode_vec,
    _decode_vec,
    _sample_matrix,
    KPKE_KeyGen,
    KPKE_Encrypt,
    KPKE_Decrypt,
)


class TestKPKEParametersAndHelpers(unittest.TestCase):
    """Tests for FIPS 203 Table 2 & Table 3 parameter sets and helper functions."""

    def test_approved_parameter_sets_table2(self):
        expected = {
            "ML-KEM-512":  {"k": 2, "eta1": 3, "eta2": 2, "du": 10, "dv": 4},
            "ML-KEM-768":  {"k": 3, "eta1": 2, "eta2": 2, "du": 10, "dv": 4},
            "ML-KEM-1024": {"k": 4, "eta1": 2, "eta2": 2, "du": 11, "dv": 5},
        }
        self.assertEqual(PARAMS, expected)
        self.assertEqual(_get_params("ML-KEM-512"), (2, 3, 2, 10, 4))
        self.assertEqual(_get_params("ML-KEM-768"), (3, 2, 2, 10, 4))
        self.assertEqual(_get_params("ML-KEM-1024"), (4, 2, 2, 11, 5))

    def test_unknown_parameter_set_raises_value_error(self):
        for bad_name in ("", "ML-KEM-256", "Kyber512", "ml-kem-512"):
            with self.assertRaises(ValueError):
                _get_params(bad_name)
            with self.assertRaises(ValueError):
                ek_length(bad_name)
            with self.assertRaises(ValueError):
                dk_length(bad_name)
            with self.assertRaises(ValueError):
                ciphertext_length(bad_name)

    def test_key_and_ciphertext_byte_lengths_table3(self):
        # FIPS 203 Table 3 sizes (ek_PKE = 384k + 32, dk_PKE = 384k, c = 32(du*k + dv))
        expected_lengths = {
            "ML-KEM-512":  (800, 768, 768),
            "ML-KEM-768":  (1184, 1152, 1088),
            "ML-KEM-1024": (1568, 1536, 1568),
        }
        for name, (exp_ek, exp_dk, exp_c) in expected_lengths.items():
            self.assertEqual(ek_length(name), exp_ek)
            self.assertEqual(dk_length(name), exp_dk)
            self.assertEqual(ciphertext_length(name), exp_c)

    def test_encode_decode_vec_roundtrip(self):
        rng = random.Random(101)
        for k in (2, 3, 4):
            for d in (4, 10, 12):
                m = (1 << d) if d < 12 else q
                vec = [[rng.randrange(m) for _ in range(256)] for _ in range(k)]
                encoded = _encode_vec(vec, d)
                self.assertEqual(len(encoded), k * 32 * d)
                decoded = _decode_vec(encoded, d, k)
                self.assertEqual(decoded, vec)

    def test_compress_decompress_poly_roundtrip(self):
        for d in (1, 4, 5, 10, 11):
            poly = [i % (1 << d) for i in range(256)]
            decompressed = _decompress_poly(poly, d)
            recompressed = _compress_poly(decompressed, d)
            self.assertEqual(recompressed, poly)

    def test_sample_matrix_indexing_order(self):
        # FIPS 203 Algorithm 13 line 5: A_hat[i, j] = SampleNTT(rho || j || i)
        rho = bytes(range(32))
        k = 3
        A_hat = _sample_matrix(rho, k)
        self.assertEqual(len(A_hat), k)
        for i in range(k):
            self.assertEqual(len(A_hat[i]), k)
            for j in range(k):
                self.assertEqual(A_hat[i][j], SampleNTT(rho + bytes([j, i])))
                if i != j:
                    self.assertNotEqual(A_hat[i][j], A_hat[j][i])


class TestKPKEKeyGenEncryptDecrypt(unittest.TestCase):
    """Tests for KPKE_KeyGen (Alg. 13), KPKE_Encrypt (Alg. 14), and KPKE_Decrypt (Alg. 15)."""

    def test_keygen_structure_and_algebraic_relation(self):
        d = bytes(range(32))
        for name, params in PARAMS.items():
            k = params["k"]
            eta1 = params["eta1"]

            ek, dk = KPKE_KeyGen(d, name)
            self.assertEqual(len(ek), ek_length(name))
            self.assertEqual(len(dk), dk_length(name))

            # Unpack raw 12-bit integers and verify all are < q
            for blob in (ek[:384 * k], dk):
                for idx in range(0, len(blob), 3):
                    b0, b1, b2 = blob[idx], blob[idx + 1], blob[idx + 2]
                    x0 = b0 | ((b1 & 0x0F) << 8)
                    x1 = (b1 >> 4) | (b2 << 4)
                    self.assertLess(x0, q)
                    self.assertLess(x1, q)

            # Verify t_hat = A_hat * s_hat + e_hat where s and e have coefficients in [-eta1, eta1] mod q
            t_hat = _decode_vec(ek[:384 * k], 12, k)
            rho = ek[384 * k:]
            s_hat = _decode_vec(dk, 12, k)
            A_hat = _sample_matrix(rho, k)

            As_hat = mat_vec_mul(A_hat, s_hat)
            e_hat = [poly_sub(t_hat[i], As_hat[i]) for i in range(k)]
            s = intt_vec(s_hat)
            e = intt_vec(e_hat)

            for vec in (s, e):
                for poly in vec:
                    for coeff in poly:
                        self.assertTrue(
                            (0 <= coeff <= eta1) or (q - eta1 <= coeff < q),
                            f"{name}: key coefficient {coeff} outside CBD_{eta1} support",
                        )

    def test_keygen_domain_separation_by_k(self):
        # FIPS 203 hashes (d || k) in G, so the public seed rho must differ across parameter sets
        d = b"\x5a" * 32
        rhos = set()
        for name in PARAMS:
            ek, _ = KPKE_KeyGen(d, name)
            rho = ek[-32:]
            rhos.add(rho)
        self.assertEqual(len(rhos), len(PARAMS))

    def test_determinism(self):
        d = b"\x11" * 32
        m = b"\x22" * 32
        r = b"\x33" * 32
        for name in PARAMS:
            ek1, dk1 = KPKE_KeyGen(d, name)
            ek2, dk2 = KPKE_KeyGen(d, name)
            self.assertEqual(ek1, ek2)
            self.assertEqual(dk1, dk2)

            c1 = KPKE_Encrypt(ek1, m, r, name)
            c2 = KPKE_Encrypt(ek1, m, r, name)
            self.assertEqual(c1, c2)

    def test_encrypt_decrypt_edge_case_messages(self):
        edge_messages = [
            b"\x00" * 32,
            b"\xff" * 32,
            b"\xaa" * 32,
            b"\x55" * 32,
            bytes([1]) + b"\x00" * 31,
            b"\x00" * 31 + bytes([0x80]),
            bytes(range(32)),
        ]
        rng = random.Random(2025)
        for name in PARAMS:
            d = bytes(rng.randrange(256) for _ in range(32))
            ek, dk = KPKE_KeyGen(d, name)
            for m in edge_messages:
                r = bytes(rng.randrange(256) for _ in range(32))
                c = KPKE_Encrypt(ek, m, r, name)
                self.assertEqual(len(c), ciphertext_length(name))
                decrypted = KPKE_Decrypt(dk, c, name)
                self.assertEqual(decrypted, m, f"Failed on {name} for message {m.hex()}")

    def test_encrypt_decrypt_random_trials(self):
        rng = random.Random(424242)
        for name in PARAMS:
            for trial in range(10):
                d = bytes(rng.randrange(256) for _ in range(32))
                m = bytes(rng.randrange(256) for _ in range(32))
                r = bytes(rng.randrange(256) for _ in range(32))
                ek, dk = KPKE_KeyGen(d, name)
                c = KPKE_Encrypt(ek, m, r, name)
                self.assertEqual(KPKE_Decrypt(dk, c, name), m, f"{name} failed on trial {trial}")

    def test_different_randomness_produces_distinct_ciphertexts(self):
        d = b"\x01" * 32
        m = b"Post-Quantum Cryptography ML-KEM"
        r1 = b"\x10" * 32
        r2 = b"\x20" * 32
        for name in PARAMS:
            ek, dk = KPKE_KeyGen(d, name)
            c1 = KPKE_Encrypt(ek, m, r1, name)
            c2 = KPKE_Encrypt(ek, m, r2, name)
            self.assertNotEqual(c1, c2)
            self.assertEqual(KPKE_Decrypt(dk, c1, name), m)
            self.assertEqual(KPKE_Decrypt(dk, c2, name), m)

    def test_wrong_decryption_key_does_not_recover_message(self):
        m = b"Secret 32-byte plaintext message"
        r = b"\x99" * 32
        for name in PARAMS:
            ek1, _ = KPKE_KeyGen(b"\x01" * 32, name)
            _, dk2 = KPKE_KeyGen(b"\x02" * 32, name)
            c = KPKE_Encrypt(ek1, m, r, name)
            self.assertNotEqual(KPKE_Decrypt(dk2, c, name), m)

    def test_corrupted_ciphertext_changes_decrypted_message(self):
        m = b"\x00" * 32
        r = b"\x77" * 32
        for name in PARAMS:
            ek, dk = KPKE_KeyGen(b"\x05" * 32, name)
            c = bytearray(KPKE_Encrypt(ek, m, r, name))
            # Flip the last byte in c2 (which encodes compressed v)
            c[-1] ^= 0xFF
            self.assertNotEqual(KPKE_Decrypt(dk, bytes(c), name), m)

    def test_input_length_assertions(self):
        for name in PARAMS:
            ek, dk = KPKE_KeyGen(b"\x00" * 32, name)
            m = b"\x00" * 32
            r = b"\x00" * 32
            c = KPKE_Encrypt(ek, m, r, name)

            # KPKE_KeyGen wrong d length
            with self.assertRaises(AssertionError):
                KPKE_KeyGen(b"\x00" * 31, name)
            with self.assertRaises(AssertionError):
                KPKE_KeyGen(b"\x00" * 33, name)

            # KPKE_Encrypt wrong ek, m, r lengths
            with self.assertRaises(AssertionError):
                KPKE_Encrypt(ek[:-1], m, r, name)
            with self.assertRaises(AssertionError):
                KPKE_Encrypt(ek, m[:-1], r, name)
            with self.assertRaises(AssertionError):
                KPKE_Encrypt(ek, m, r[:-1], name)

            # KPKE_Decrypt wrong dk, c lengths
            with self.assertRaises(AssertionError):
                KPKE_Decrypt(dk[:-1], c, name)
            with self.assertRaises(AssertionError):
                KPKE_Decrypt(dk, c[:-1], name)


if __name__ == "__main__":
    unittest.main(verbosity=2)
