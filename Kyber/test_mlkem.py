# Tests for mlkem.py
# run with:  python -m unittest discover -s Kyber -v

import os
import random
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from auxiliary import H, J, G
from kpke import PARAMS, ek_length, dk_length, ciphertext_length, KPKE_Encrypt
from mlkem import (
    mlkem_dk_length, shared_key_length, _split_dk, _select,
    check_ek, check_dk, check_decaps_input, check_key_pair,
    MLKEM_KeyGen_internal, MLKEM_Encaps_internal, MLKEM_Decaps_internal,
    MLKEM_KeyGen, MLKEM_Encaps, MLKEM_Decaps,
)


def rand_bytes(rng, size=32):
    return bytes(rng.randrange(256) for _ in range(size))


class TestHelpers(unittest.TestCase):

    def test_sizes(self):
        # (ek, dk, c) sizes from Table 3
        sizes = {
            "ML-KEM-512":  (800, 1632, 768),
            "ML-KEM-768":  (1184, 2400, 1088),
            "ML-KEM-1024": (1568, 3168, 1568),
        }
        for name, (ek, dk, c) in sizes.items():
            self.assertEqual(ek_length(name), ek)
            self.assertEqual(mlkem_dk_length(name), dk)
            self.assertEqual(ciphertext_length(name), c)
        self.assertEqual(shared_key_length(), 32)

    def test_unknown_param_set(self):
        for name in ("", "ML-KEM-256", "Kyber512"):
            with self.assertRaises(ValueError):
                mlkem_dk_length(name)
            with self.assertRaises(ValueError):
                MLKEM_KeyGen(name)

    def test_select(self):
        a, b = b"\x00\x0f\xf0\xff", b"\xa5\x5a\x33\xcc"
        self.assertEqual(_select(a, b, False), a)
        self.assertEqual(_select(a, b, True), b)

    def test_dk_layout(self):
        # dk = dk_pke || ek || H(ek) || z   (Algorithm 16)
        d, z = b"\x01" * 32, b"\x02" * 32
        for name, p in PARAMS.items():
            k = p["k"]
            ek, dk = MLKEM_KeyGen_internal(d, z, name)
            self.assertEqual(len(ek), ek_length(name))
            self.assertEqual(len(dk), mlkem_dk_length(name))

            dk_pke, ek_pke, h, z_out = _split_dk(dk, k)
            self.assertEqual(len(dk_pke), dk_length(name))
            self.assertEqual(ek_pke, ek)
            self.assertEqual(h, H(ek))
            self.assertEqual(z_out, z)


class TestInputChecks(unittest.TestCase):

    def test_good_inputs_pass(self):
        for name in PARAMS:
            ek, dk = MLKEM_KeyGen(name)
            _, c = MLKEM_Encaps(ek, name)
            check_ek(ek, name)
            check_decaps_input(dk, c, name)

    def test_ek_type_check(self):
        for name in PARAMS:
            ek, _ = MLKEM_KeyGen(name)
            for bad in (ek[:-1], ek + b"\x00", b"", list(ek), ek.hex()):
                with self.assertRaises(ValueError):
                    check_ek(bad, name)
                with self.assertRaises(ValueError):
                    MLKEM_Encaps(bad, name)

    def test_ek_modulus_check(self):
        for name, p in PARAMS.items():
            k = p["k"]
            ek, _ = MLKEM_KeyGen(name)

            # set the first coefficient to 0xFFF (4095 >= q)
            bad = bytearray(ek)
            bad[0] = 0xFF
            bad[1] |= 0x0F
            with self.assertRaises(ValueError):
                MLKEM_Encaps(bytes(bad), name)

            # same thing for the last coefficient of the last polynomial
            bad = bytearray(ek)
            bad[384 * k - 1] = 0xFF
            bad[384 * k - 2] |= 0xF0
            with self.assertRaises(ValueError):
                MLKEM_Encaps(bytes(bad), name)

            # rho isn't covered by the modulus check, so anything goes there
            ok = bytearray(ek)
            ok[-1] ^= 0xFF
            check_ek(bytes(ok), name)

    def test_ek_exactly_q(self):
        # q itself is out of range too, not just values >= 2^12
        name = "ML-KEM-512"
        ek, _ = MLKEM_KeyGen(name)
        bad = bytearray(ek)
        # 3329 = 0xD01 -> low byte 0x01, low nibble of next byte 0xD
        bad[0] = 0x01
        bad[1] = (bad[1] & 0xF0) | 0x0D
        with self.assertRaises(ValueError):
            check_ek(bytes(bad), name)

        # 3328 = q - 1 is fine
        bad[0] = 0x00
        check_ek(bytes(bad), name)

    def test_decaps_type_checks(self):
        for name in PARAMS:
            ek, dk = MLKEM_KeyGen(name)
            _, c = MLKEM_Encaps(ek, name)
            for bad_c in (c[:-1], c + b"\x00", b"", list(c)):
                with self.assertRaises(ValueError):
                    MLKEM_Decaps(dk, bad_c, name)
            for bad_dk in (dk[:-1], dk + b"\x00", b"", list(dk)):
                with self.assertRaises(ValueError):
                    MLKEM_Decaps(bad_dk, c, name)

    def test_decaps_hash_check(self):
        for name, p in PARAMS.items():
            k = p["k"]
            ek, dk = MLKEM_KeyGen(name)
            _, c = MLKEM_Encaps(ek, name)

            # flip a bit in the stored ek
            bad = bytearray(dk)
            bad[384 * k] ^= 0x01
            with self.assertRaises(ValueError):
                MLKEM_Decaps(bytes(bad), c, name)

            # flip a bit in the stored hash
            bad = bytearray(dk)
            bad[768 * k + 32] ^= 0x01
            with self.assertRaises(ValueError):
                MLKEM_Decaps(bytes(bad), c, name)

    def test_check_dk_alone(self):
        for name, p in PARAMS.items():
            _, dk = MLKEM_KeyGen(name)
            check_dk(dk, name)
            with self.assertRaises(ValueError):
                check_dk(dk[:-1], name)
            bad = bytearray(dk)
            bad[384 * p["k"]] ^= 0x01
            with self.assertRaises(ValueError):
                check_dk(bytes(bad), name)

    def test_wrong_param_set(self):
        ek, dk = MLKEM_KeyGen("ML-KEM-768")
        _, c = MLKEM_Encaps(ek, "ML-KEM-768")
        for other in ("ML-KEM-512", "ML-KEM-1024"):
            with self.assertRaises(ValueError):
                MLKEM_Encaps(ek, other)
            with self.assertRaises(ValueError):
                MLKEM_Decaps(dk, c, other)


class TestKeyPairCheck(unittest.TestCase):
    # section 7.1

    def test_good_pair(self):
        d, z = b"\x0a" * 32, b"\x0b" * 32
        for name in PARAMS:
            ek, dk = MLKEM_KeyGen_internal(d, z, name)
            check_key_pair(ek, dk, name)
            check_key_pair(ek, dk, name, d, z)
            ek, dk = MLKEM_KeyGen(name)
            check_key_pair(ek, dk, name)

    def test_seed_mismatch(self):
        d, z = b"\x0a" * 32, b"\x0b" * 32
        for name in PARAMS:
            ek, dk = MLKEM_KeyGen_internal(d, z, name)
            with self.assertRaises(ValueError):
                check_key_pair(ek, dk, name, b"\x0c" * 32, z)
            with self.assertRaises(ValueError):
                check_key_pair(ek, dk, name, d, b"\x0c" * 32)
            with self.assertRaises(ValueError):
                check_key_pair(ek, dk, name, d, None)

    def test_bad_ek_or_dk(self):
        for name, p in PARAMS.items():
            ek, dk = MLKEM_KeyGen(name)
            with self.assertRaises(ValueError):
                check_key_pair(ek[:-1], dk, name)
            with self.assertRaises(ValueError):
                check_key_pair(ek, dk[:-1], name)
            bad = bytearray(ek)
            bad[0], bad[1] = 0xFF, bad[1] | 0x0F  # coefficient >= q
            with self.assertRaises(ValueError):
                check_key_pair(bytes(bad), dk, name)

    def test_mismatched_pair(self):
        # both keys are fine on their own, they just don't belong together,
        # so only the pair-wise consistency step can catch it
        for name in PARAMS:
            ek1, _ = MLKEM_KeyGen(name)
            ek2, dk2 = MLKEM_KeyGen(name)
            check_ek(ek1, name)
            check_dk(dk2, name)
            with self.assertRaises(ValueError) as cm:
                check_key_pair(ek1, dk2, name)
            self.assertIn("pair-wise", str(cm.exception))

    def test_corrupted_dk_pke(self):
        # the hash check doesn't cover the dk_pke part of dk, so corrupting
        # s_hat is another one only the pair-wise check catches
        for name, p in PARAMS.items():
            ek, dk = MLKEM_KeyGen(name)
            bad = bytearray(dk)
            for i in range(0, 384 * p["k"], 3):
                bad[i] ^= 0x55
            check_dk(bytes(bad), name)
            with self.assertRaises(ValueError):
                check_key_pair(ek, bytes(bad), name)


class TestMLKEM(unittest.TestCase):

    def test_encaps_internal_matches_spec(self):
        # (K, r) = G(m || H(ek)), c = K-PKE.Encrypt(ek, m, r)
        m = b"\x42" * 32
        for name in PARAMS:
            ek, _ = MLKEM_KeyGen_internal(b"\x03" * 32, b"\x04" * 32, name)
            K, c = MLKEM_Encaps_internal(ek, m, name)
            K_exp, r = G(m + H(ek))
            self.assertEqual(K, K_exp)
            self.assertEqual(c, KPKE_Encrypt(ek, m, r, name))
            self.assertEqual(len(K), 32)
            self.assertEqual(len(c), ciphertext_length(name))

    def test_deterministic(self):
        d, z, m = b"\x11" * 32, b"\x22" * 32, b"\x33" * 32
        for name in PARAMS:
            ek, dk = MLKEM_KeyGen_internal(d, z, name)
            self.assertEqual(MLKEM_KeyGen_internal(d, z, name), (ek, dk))
            K, c = MLKEM_Encaps_internal(ek, m, name)
            self.assertEqual(MLKEM_Encaps_internal(ek, m, name), (K, c))
            self.assertEqual(MLKEM_Decaps_internal(dk, c, name), K)

    def test_roundtrip_random(self):
        rng = random.Random(8675309)
        for name in PARAMS:
            for trial in range(10):
                d, z, m = rand_bytes(rng), rand_bytes(rng), rand_bytes(rng)
                ek, dk = MLKEM_KeyGen_internal(d, z, name)
                K, c = MLKEM_Encaps_internal(ek, m, name)
                self.assertEqual(MLKEM_Decaps_internal(dk, c, name), K,
                                 f"{name} trial {trial}")

    def test_roundtrip_external(self):
        for name in PARAMS:
            ek, dk = MLKEM_KeyGen(name)
            K, c = MLKEM_Encaps(ek, name)
            self.assertEqual(len(K), 32)
            self.assertEqual(MLKEM_Decaps(dk, c, name), K)

    def test_encaps_is_randomized(self):
        for name in PARAMS:
            ek, dk = MLKEM_KeyGen(name)
            K1, c1 = MLKEM_Encaps(ek, name)
            K2, c2 = MLKEM_Encaps(ek, name)
            self.assertNotEqual(K1, K2)
            self.assertNotEqual(c1, c2)
            self.assertEqual(MLKEM_Decaps(dk, c1, name), K1)
            self.assertEqual(MLKEM_Decaps(dk, c2, name), K2)

    def test_implicit_rejection(self):
        # a tampered ciphertext should give J(z || c), not an error
        z = b"\x5c" * 32
        for name in PARAMS:
            ek, dk = MLKEM_KeyGen_internal(b"\x06" * 32, z, name)
            K, c = MLKEM_Encaps_internal(ek, b"\x07" * 32, name)

            for pos in (0, len(c) // 2, len(c) - 1):
                bad = bytearray(c)
                bad[pos] ^= 0x01
                bad = bytes(bad)
                K_bad = MLKEM_Decaps(dk, bad, name)
                self.assertNotEqual(K_bad, K)
                self.assertEqual(K_bad, J(z + bad), f"{name}, byte {pos}")

    def test_rejection_depends_on_z(self):
        # same keys except z -> valid c decaps the same, bad c differs
        d = b"\x08" * 32
        for name in PARAMS:
            ek, dk1 = MLKEM_KeyGen_internal(d, b"\x01" * 32, name)
            _, dk2 = MLKEM_KeyGen_internal(d, b"\x02" * 32, name)
            K, c = MLKEM_Encaps_internal(ek, b"\x09" * 32, name)
            self.assertEqual(MLKEM_Decaps(dk1, c, name), K)
            self.assertEqual(MLKEM_Decaps(dk2, c, name), K)

            bad = bytes([c[0] ^ 0x80]) + c[1:]
            self.assertNotEqual(MLKEM_Decaps(dk1, bad, name),
                                MLKEM_Decaps(dk2, bad, name))

    def test_wrong_key(self):
        for name in PARAMS:
            ek, _ = MLKEM_KeyGen(name)
            _, other_dk = MLKEM_KeyGen(name)
            K, c = MLKEM_Encaps(ek, name)
            self.assertNotEqual(MLKEM_Decaps(other_dk, c, name), K)

    def test_bad_internal_input_lengths(self):
        for name in PARAMS:
            ek, dk = MLKEM_KeyGen_internal(bytes(32), bytes(32), name)
            _, c = MLKEM_Encaps_internal(ek, bytes(32), name)

            with self.assertRaises(AssertionError):
                MLKEM_KeyGen_internal(bytes(31), bytes(32), name)
            with self.assertRaises(AssertionError):
                MLKEM_KeyGen_internal(bytes(32), bytes(33), name)

            with self.assertRaises(AssertionError):
                MLKEM_Encaps_internal(ek[:-1], bytes(32), name)
            with self.assertRaises(AssertionError):
                MLKEM_Encaps_internal(ek, bytes(31), name)

            with self.assertRaises(AssertionError):
                MLKEM_Decaps_internal(dk[:-1], c, name)
            with self.assertRaises(AssertionError):
                MLKEM_Decaps_internal(dk, c[:-1], name)


# kyber-py is an independent pure python ML-KEM (pip install kyber-py). If
# it's around we check our output against it byte for byte, otherwise skip.
try:
    from kyber_py.ml_kem import ML_KEM_512, ML_KEM_768, ML_KEM_1024
    REFERENCE = {
        "ML-KEM-512": ML_KEM_512,
        "ML-KEM-768": ML_KEM_768,
        "ML-KEM-1024": ML_KEM_1024,
    }
except ImportError:
    REFERENCE = None


@unittest.skipIf(REFERENCE is None, "kyber-py not installed")
class TestAgainstKyberPy(unittest.TestCase):

    TRIALS = 10

    def test_keygen_internal(self):
        rng = random.Random(1203)
        for name, ref in REFERENCE.items():
            for trial in range(self.TRIALS):
                d, z = rand_bytes(rng), rand_bytes(rng)
                self.assertEqual(MLKEM_KeyGen_internal(d, z, name),
                                 ref._keygen_internal(d, z),
                                 f"{name} trial {trial}")

    def test_encaps_internal(self):
        rng = random.Random(1204)
        for name, ref in REFERENCE.items():
            for trial in range(self.TRIALS):
                ek, _ = ref._keygen_internal(rand_bytes(rng), rand_bytes(rng))
                m = rand_bytes(rng)
                self.assertEqual(MLKEM_Encaps_internal(ek, m, name),
                                 ref._encaps_internal(ek, m),
                                 f"{name} trial {trial}")

    def test_decaps_valid(self):
        rng = random.Random(1205)
        for name, ref in REFERENCE.items():
            for trial in range(self.TRIALS):
                ek, dk = ref._keygen_internal(rand_bytes(rng), rand_bytes(rng))
                K, c = ref._encaps_internal(ek, rand_bytes(rng))
                self.assertEqual(MLKEM_Decaps(dk, c, name), K,
                                 f"{name} trial {trial}")

    def test_decaps_implicit_rejection(self):
        # tampered and completely random ciphertexts should hit the same
        # rejection key in both implementations
        rng = random.Random(1206)
        for name, ref in REFERENCE.items():
            ek, dk = ref._keygen_internal(rand_bytes(rng), rand_bytes(rng))
            _, c = ref._encaps_internal(ek, rand_bytes(rng))
            for trial in range(self.TRIALS):
                bad = bytearray(c)
                bad[rng.randrange(len(c))] ^= 1 << rng.randrange(8)
                for ct in (bytes(bad), rand_bytes(rng, len(c))):
                    self.assertEqual(MLKEM_Decaps(dk, ct, name),
                                     ref._decaps_internal(dk, ct),
                                     f"{name} trial {trial}")

    def test_cross_roundtrip(self):
        # our encaps -> their decaps, and their encaps -> our decaps
        for name, ref in REFERENCE.items():
            ek, dk = MLKEM_KeyGen(name)
            K, c = MLKEM_Encaps(ek, name)
            self.assertEqual(ref.decaps(dk, c), K)

            ek, dk = ref.keygen()
            K, c = ref.encaps(ek)
            self.assertEqual(MLKEM_Decaps(dk, c, name), K)


if __name__ == "__main__":
    unittest.main(verbosity=2)
