from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.exceptions import InvalidSignature

# made it a class to match implementation style from RSA module
class ECCImplemented:

    # different elliptical curves that can be used
    SUPPORTED_CURVES = {
        "P-256": ec.SECP256R1(),
        "P-384": ec.SECP384R1(),
        "P-521": ec.SECP521R1(),
    }

    # curve type is a string parameter upon object initialization
    def __init__(self, curve_name="P-256"):
        if curve_name not in self.SUPPORTED_CURVES:
            raise ValueError(f"Unsupported curve '{curve_name}'. "
                             f"Choose from: {', '.join(self.SUPPORTED_CURVES.keys())}")

        self.curve_name = curve_name
        self.curve = self.SUPPORTED_CURVES[curve_name]

        self.private_key = None
        self.public_key = None

        self.generate_keypair()

    def generate_keypair(self):
        self.private_key = ec.generate_private_key(self.curve)
        self.public_key = self.private_key.public_key()
        return self.private_key, self.public_key


    # This is where ECDH key agreement happens yippee
    def derive_shared_key(self, peer_public_key):
        if not isinstance(peer_public_key, ec.EllipticCurvePublicKey):
            raise TypeError("peer_public_key must be an EC public key.")

        shared_secret = self.private_key.exchange(ec.ECDH(), peer_public_key)

        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"ecc-ecdh"
        ).derive(shared_secret)

        return derived_key

    # Here we have ECDSA signing :P
    def sign(self, message):
        if not isinstance(message, bytes):
            raise TypeError("Message must be provided as bytes.")

        return self.private_key.sign(
            message,
            ec.ECDSA(hashes.SHA256())
        )

    # ECDSA verification :D
    def verify(self, message, signature):
        if not isinstance(message, bytes):
            raise TypeError("Message must be provided as bytes.")

        try:
            self.public_key.verify(
                signature,
                message,
                ec.ECDSA(hashes.SHA256())
            )
            return True
        except InvalidSignature:
            return False

    # export the keys in PEM (privacy enhanced mail) format
    def get_public_key_pem(self):
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def get_private_key_pem(self):
        return self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

    # helper methods to get the size of keys
    def get_public_key_size_bytes(self):
        return len(self.get_public_key_pem())

    def get_private_key_size_bytes(self):
        return len(self.get_private_key_pem())
