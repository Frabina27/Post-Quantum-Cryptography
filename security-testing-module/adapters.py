import sys 
import oqs 

#Append path to access RSA 
sys.path.append("../rsa-module")
#sys.path.append("../kyber")
from rsa_crypto import RSACrypto

#RSA Adapter 
class RSAAdapter: 
    name = "RSA"
    def __init__(self): 
        self.rsa = RSACrypto()
    def sign(self,message): 
        return self.rsa.sign(message)
    def verify(self,message,signature): 
        try: 
            return bool(self.rsa.verify(message, signature)) 
        except Exception: 
            return False 
    def encrypt(self,original_message): 
        return self.rsa.encrypt(original_message)
    def decrypt(self,ciphertext):
        try: 
            self.rsa.decrypt(ciphertext)
        except Exception: 
            return False 


#MLDSAAdapter
class MLDSAAdapter: 
    name = "ML-DSA"
    def __init__(self,algorithm="ML-DSA-44"): 
        self.algorithm = algorithm 
        self.signer = oqs.Signature(self.algorithm)
        self.verifier = oqs.Signature(self.algorithm) 
        self.public_key = self.signer.generate_keypair()
        self.private_key = self.signer.export_secret_key()
    def sign(self,message): 
        return self.signer.sign(message)
    def verify(self,message,signature): 
        try:
            return bool(self.verifier.verify(message, signature, self.public_key))
        except Exception:
            return False