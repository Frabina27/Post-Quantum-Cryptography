"""
RSA Cryptographic Module

Provides:
- RSA key-pair generation
- RSA-OAEP encryption/decryption
- RSA-PSS digital signatures
- Signature verification
- PEM key serialization

Encryption: RSA-OAEP with SHA-256
Signatures: RSA-PSS with SHA-256
"""

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature


class RSACrypto:
    """Class containing the project's RSA cryptographic operations."""

    def __init__(self, key_size=2048):
        """
        Create an RSA object and generate a key pair.

        Args:
            key_size (int): RSA key size in bits.
                            Recommended values: 2048 or 3072.
        """
        if key_size not in (2048, 3072):
            raise ValueError("RSA key size must be 2048 or 3072 bits.")

        self.key_size = key_size
        self.private_key = None
        self.public_key = None

        self.generate_keypair()

    def generate_keypair(self):
        """Generate an RSA private/public key pair."""

        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=self.key_size
        )

        self.public_key = self.private_key.public_key()

        return self.private_key, self.public_key

    def encrypt(self, plaintext):
        """
        Encrypt data using the RSA public key and OAEP padding.

        Args:
            plaintext (bytes): Data to encrypt.

        Returns:
            bytes: RSA ciphertext.
        """
        if not isinstance(plaintext, bytes):
            raise TypeError("Plaintext must be provided as bytes.")

        ciphertext = self.public_key.encrypt(
            plaintext,
            padding.OAEP(
                mgf=padding.MGF1(
                    algorithm=hashes.SHA256()
                ),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        return ciphertext

    def decrypt(self, ciphertext):
        """
        Decrypt RSA-OAEP ciphertext using the private key.

        Args:
            ciphertext (bytes): Encrypted data.

        Returns:
            bytes: Original plaintext.
        """
        if not isinstance(ciphertext, bytes):
            raise TypeError("Ciphertext must be provided as bytes.")

        plaintext = self.private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(
                    algorithm=hashes.SHA256()
                ),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        return plaintext

    def sign(self, message):
        """
        Digitally sign a message using RSA-PSS and SHA-256.

        Args:
            message (bytes): Message to sign.

        Returns:
            bytes: Digital signature.
        """
        if not isinstance(message, bytes):
            raise TypeError("Message must be provided as bytes.")

        signature = self.private_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(
                    hashes.SHA256()
                ),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        return signature

    def verify(self, message, signature):
        """
        Verify an RSA-PSS digital signature.

        Args:
            message (bytes): Original message.
            signature (bytes): Signature to verify.

        Returns:
            bool: True if valid, False otherwise.
        """
        if not isinstance(message, bytes):
            raise TypeError("Message must be provided as bytes.")

        try:
            self.public_key.verify(
                signature,
                message,
                padding.PSS(
                    mgf=padding.MGF1(
                        hashes.SHA256()
                    ),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )

            return True

        except InvalidSignature:
            return False

    def get_public_key_pem(self):
        """Return the public key serialized in PEM format."""

        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def get_private_key_pem(self):
        """
        Return the private key serialized in PEM format.

        The benchmark uses an unencrypted serialization so the
        storage size can be measured consistently.
        """

        return self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

    def get_public_key_size_bytes(self):
        """Return serialized public-key storage size in bytes."""

        return len(self.get_public_key_pem())

    def get_private_key_size_bytes(self):
        """Return serialized private-key storage size in bytes."""

        return len(self.get_private_key_pem())