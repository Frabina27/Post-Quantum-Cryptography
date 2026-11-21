import unittest
from ecc_implemented import ECCImplemented
from cryptography.hazmat.primitives.asymmetric import ec


class TestECC(unittest.TestCase):

    def test_key_generation(self):
        ecc = ECCImplemented("P-256")
        self.assertIsNotNone(ecc.private_key)
        self.assertIsNotNone(ecc.public_key)

    def test_curve_selection(self):
        ecc256 = ECCImplemented("P-256")
        ecc384 = ECCImplemented("P-384")
        ecc521 = ECCImplemented("P-521")

        self.assertIsInstance(ecc256.private_key.curve, ec.SECP256R1)
        self.assertIsInstance(ecc384.private_key.curve, ec.SECP384R1)
        self.assertIsInstance(ecc521.private_key.curve, ec.SECP521R1)

    def test_ecdh_shared_secret(self):
        alice = ECCImplemented("P-256")
        bob = ECCImplemented("P-256")

        shared_alice = alice.derive_shared_key(bob.public_key)
        shared_bob = bob.derive_shared_key(alice.public_key)

        self.assertEqual(shared_alice, shared_bob)

    def test_ecdsa_sign_verify(self):
        ecc = ECCImplemented("P-256")
        message = b"ECC test message"

        signature = ecc.sign(message)
        self.assertTrue(ecc.verify(message, signature))

    def test_modified_message_fails(self):
        ecc = ECCImplemented("P-256")
        message = b"original"
        signature = ecc.sign(message)

        self.assertFalse(ecc.verify(b"tampered", signature))

    def test_modified_signature_fails(self):
        ecc = ECCImplemented("P-256")
        message = b"hello"
        signature = ecc.sign(message)

        bad_signature = signature[:-1] + b"\x00"
        self.assertFalse(ecc.verify(message, bad_signature))

    def test_pem_export(self):
        ecc = ECCImplemented("P-256")
        pub_pem = ecc.get_public_key_pem()
        priv_pem = ecc.get_private_key_pem()

        self.assertTrue(pub_pem.startswith(b"-----BEGIN PUBLIC KEY-----"))
        self.assertTrue(priv_pem.startswith(b"-----BEGIN PRIVATE KEY-----"))


if __name__ == "__main__":
    unittest.main()
