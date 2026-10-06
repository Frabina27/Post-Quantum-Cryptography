"""
Tests for the RSA Cryptographic Module.

Run with:

    python test_rsa.py
"""

from rsa_crypto import RSACrypto


def test_key_generation():
    """Test RSA key-pair generation."""

    rsa = RSACrypto(2048)

    assert rsa.private_key is not None
    assert rsa.public_key is not None

    print("[PASS] RSA key generation")


def test_encryption_decryption():
    """Test RSA-OAEP encryption and decryption."""

    rsa = RSACrypto(2048)

    original_message = b"Hello RSA!"

    ciphertext = rsa.encrypt(original_message)

    decrypted_message = rsa.decrypt(ciphertext)

    assert ciphertext != original_message
    assert decrypted_message == original_message

    print("[PASS] RSA encryption/decryption")


def test_signature():
    """Test RSA-PSS signature generation and verification."""

    rsa = RSACrypto(2048)

    message = b"Important authenticated message"

    signature = rsa.sign(message)

    valid = rsa.verify(message, signature)

    assert valid is True

    print("[PASS] RSA signature verification")


def test_modified_message():
    """
    Verify that changing the original message causes
    signature verification to fail.
    """

    rsa = RSACrypto(2048)

    original_message = b"Transfer $100"
    modified_message = b"Transfer $1000"

    signature = rsa.sign(original_message)

    valid = rsa.verify(
        modified_message,
        signature
    )

    assert valid is False

    print("[PASS] Modified message rejected")


def test_modified_signature():
    """
    Verify that a corrupted signature is rejected.
    """

    rsa = RSACrypto(2048)

    message = b"Test message"

    signature = rsa.sign(message)

    # Change one byte in the signature.
    corrupted_signature = bytearray(signature)
    corrupted_signature[0] ^= 1
    corrupted_signature = bytes(corrupted_signature)

    valid = rsa.verify(
        message,
        corrupted_signature
    )

    assert valid is False

    print("[PASS] Modified signature rejected")


def test_3072_bit_rsa():
    """Verify that RSA-3072 operations also work."""

    rsa = RSACrypto(3072)

    message = b"Testing RSA 3072"

    ciphertext = rsa.encrypt(message)

    decrypted = rsa.decrypt(ciphertext)

    signature = rsa.sign(message)

    valid = rsa.verify(
        message,
        signature
    )

    assert decrypted == message
    assert valid is True

    print("[PASS] RSA-3072 operations")


def test_key_serialization():
    """Test public/private key PEM serialization."""

    rsa = RSACrypto(2048)

    public_pem = rsa.get_public_key_pem()
    private_pem = rsa.get_private_key_pem()

    assert public_pem.startswith(
        b"-----BEGIN PUBLIC KEY-----"
    )

    assert private_pem.startswith(
        b"-----BEGIN PRIVATE KEY-----"
    )

    print("[PASS] RSA key serialization")


def run_tests():

    print("\nRunning RSA Module Tests")
    print("=" * 40)

    test_key_generation()
    test_encryption_decryption()
    test_signature()
    test_modified_message()
    test_modified_signature()
    test_3072_bit_rsa()
    test_key_serialization()

    print("=" * 40)
    print("All RSA tests passed!")


if __name__ == "__main__":
    run_tests()