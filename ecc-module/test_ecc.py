import unittest
from ecc_implemented import ECCImplemented
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization


class TestECC(unittest.TestCase):

    def test_key_generation(self):
        print("\nTesting P-256 public and private key generation...", flush=True)
        ecc = ECCImplemented("P-256")
        self.assertIsNotNone(ecc.private_key)
        self.assertIsNotNone(ecc.public_key)
        print("PASS: Both public and private keys were generated.", flush=True)

    def test_curve_selection(self):
        print("\nTesting selection of P-256, P-384, and P-521 curves...", flush=True)
        ecc256 = ECCImplemented("P-256")
        ecc384 = ECCImplemented("P-384")
        ecc521 = ECCImplemented("P-521")

        self.assertIsInstance(ecc256.private_key.curve, ec.SECP256R1)
        self.assertIsInstance(ecc384.private_key.curve, ec.SECP384R1)
        self.assertIsInstance(ecc521.private_key.curve, ec.SECP521R1)
        print("PASS: All three keypairs use the requested curves.", flush=True)

    def test_ecdh_shared_secret(self):
        print("\nTesting ECDH shared-key agreement between Alice and Bob...", flush=True)
        alice = ECCImplemented("P-256")
        bob = ECCImplemented("P-256")

        shared_alice = alice.derive_shared_key(bob.public_key)
        shared_bob = bob.derive_shared_key(alice.public_key)

        self.assertEqual(shared_alice, shared_bob)
        print("PASS: Alice and Bob derived the same shared key.", flush=True)

    def test_ecdsa_sign_verify(self):
        print("\nTesting ECDSA signing and verification of an unchanged message...", flush=True)
        ecc = ECCImplemented("P-256")
        message = b"ECC test message"

        signature = ecc.sign(message)
        self.assertTrue(ecc.verify(message, signature))
        print("PASS: The valid signature was accepted.", flush=True)

    def test_modified_message_fails(self):
        print("\nTesting rejection of a modified message...", flush=True)
        ecc = ECCImplemented("P-256")
        message = b"original"
        signature = ecc.sign(message)

        self.assertFalse(ecc.verify(b"tampered", signature))
        print("PASS: Verification rejected the modified message.", flush=True)

    def test_modified_signature_fails(self):
        print("\nTesting rejection of a modified signature...", flush=True)
        ecc = ECCImplemented("P-256")
        message = b"hello"
        signature = ecc.sign(message)

        bad_signature = signature[:-1] + bytes([signature[-1] ^ 1])
        self.assertFalse(ecc.verify(message, bad_signature))
        print("PASS: Verification rejected the modified signature.", flush=True)

    def test_pem_export(self):
        print("\nTesting PEM export headers for public and private keys...", flush=True)
        ecc = ECCImplemented("P-256")
        pub_pem = ecc.get_public_key_pem()
        priv_pem = ecc.get_private_key_pem()

        self.assertTrue(pub_pem.startswith(b"-----BEGIN PUBLIC KEY-----"))
        self.assertTrue(priv_pem.startswith(b"-----BEGIN PRIVATE KEY-----"))
        print("PASS: Both exported keys have the expected PEM headers.", flush=True)

    def test_operations_on_all_curves(self):
        print("\nTesting ECDH and ECDSA operations on every supported curve...", flush=True)
        for curve in ECCImplemented.SUPPORTED_CURVES:
            with self.subTest(curve=curve):
                alice = ECCImplemented(curve)
                bob = ECCImplemented(curve)
                shared_key = alice.derive_shared_key(bob.public_key)
                self.assertEqual(shared_key, bob.derive_shared_key(alice.public_key))
                self.assertEqual(len(shared_key), 32)
                message = b"ECC operations across curves"
                signature = alice.sign(message)
                self.assertTrue(alice.verify(message, signature))
                self.assertFalse(alice.verify(b"modified", signature))
                print(f"PASS: {curve} key agreement, 32-byte derived key, signing, "
                      "verification, and modified-message rejection.", flush=True)

    def test_pem_round_trip(self):
        print("\nTesting exported key loading and use on every supported curve...", flush=True)
        for curve in ECCImplemented.SUPPORTED_CURVES:
            with self.subTest(curve=curve):
                ecc = ECCImplemented(curve)
                public_key = serialization.load_pem_public_key(ecc.get_public_key_pem())
                private_key = serialization.load_pem_private_key(
                    ecc.get_private_key_pem(), password=None
                )
                self.assertEqual(public_key.public_numbers(), ecc.public_key.public_numbers())
                self.assertEqual(private_key.private_numbers(), ecc.private_key.private_numbers())
                message = b"PEM round-trip test"
                signature = private_key.sign(message, ec.ECDSA(hashes.SHA256()))
                public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
                print(f"PASS: {curve} exported keys reload and sign/verify correctly.", flush=True)

    def test_key_size_measurements(self):
        print("\nTesting exported key size measurements on every supported curve...", flush=True)
        for curve in ECCImplemented.SUPPORTED_CURVES:
            with self.subTest(curve=curve):
                ecc = ECCImplemented(curve)
                self.assertEqual(ecc.get_public_key_size_bytes(), len(ecc.get_public_key_pem()))
                self.assertEqual(ecc.get_private_key_size_bytes(), len(ecc.get_private_key_pem()))
                print(f"PASS: {curve} size helpers match exported PEM lengths.", flush=True)

    def test_wrong_key_signature_fails(self):
        print("\nTesting rejection of signatures checked with a different key...", flush=True)
        for curve in ECCImplemented.SUPPORTED_CURVES:
            with self.subTest(curve=curve):
                alice = ECCImplemented(curve)
                bob = ECCImplemented(curve)
                message = b"Signed by Alice"
                self.assertFalse(bob.verify(message, alice.sign(message)))
                print(f"PASS: {curve} rejected a signature from another key.", flush=True)


if __name__ == "__main__":
    unittest.main()
