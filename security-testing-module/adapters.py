#pyright: reportMissingImports=false
import sys 
import oqs 
import os 
import struct 
import datetime 
from pathlib import Path
from cryptography import x509
from cryptography.x509.oid import NameOID


#Get the paths for all of the other modules 
base = Path(__file__).resolve().parent.parent   
sys.path.append(str(base))   
sys.path.append(str(base / "rsa-module"))
sys.path.append(str(base / "mldsa-module"))
sys.path.append(str(base / "ecc"))
sys.path.append(str(base / "hybrid-module"))   
sys.path.append(str(base / "Kyber")) 


from rsa_crypto import RSACrypto
from mldsa_project import SUPPORTED_ALGORITHMS, ensure_algorithm_available, verify_safely
from ecc_implemented import ECCImplemented
from kpke import PARAMS,KPKE_KeyGen, KPKE_Encrypt, KPKE_Decrypt
from pqpki.algorithms import get_algorithm, list_algorithms
from pqpki.ca import CertificateAuthority
from pqpki.csr import generate_csr
from pqpki.validate import validate_chain
import hybrid_sig
import hybrid_kem

#RSAAdapter 
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
            return self.rsa.decrypt(ciphertext)
        except Exception: 
            return False 


#MLDSAAdapter
class MLDSAAdapter: 
    name = "ML-DSA"
    def __init__(self,algorithm="ML-DSA-44"): 
        if algorithm not in SUPPORTED_ALGORITHMS: 
            raise ValueError(f"Unsupported Algorithm: {algorithm} pick one of {SUPPORTED_ALGORITHMS}")
        ensure_algorithm_available(algorithm)
        self.algorithm = algorithm 
        self.signer = oqs.Signature(self.algorithm)
        self.verifier = oqs.Signature(self.algorithm) 
        self.public_key = self.signer.generate_keypair()
        self.private_key = self.signer.export_secret_key()
    def sign(self,message): 
        return self.signer.sign(message)
    def verify(self,message,signature): 
        try:
            return verify_safely(self.verifier, message, signature, self.public_key)
        except Exception:
            return False

#ECCAdapter 
class ECCAdapter: 
    def __init__(self, curve_name="P-256"):   
        self.name = curve_name
        self.ecc = ECCImplemented(curve_name)
    def sign(self,message): 
        return self.ecc.sign(message)
    def verify(self,message,signature): 
        try: 
            return bool(self.ecc.verify(message, signature)) 
        except Exception: 
            return False 

#KyberAdapter
class KyberAdapter: 
    def __init__(self,param_set): 
        if param_set not in PARAMS:
            raise ValueError(f"unknown parameter set {param_set!r}, pick one of {sorted(PARAMS)}")
        self.param_set = param_set
        self.name = param_set
        self.ek, self.dk = KPKE_KeyGen(os.urandom(32), self.name)
    def encrypt(self,original_msg): 
        return KPKE_Encrypt(self.ek,original_msg,os.urandom(32),self.name)
    def decrypt(self,ct): 
        return KPKE_Decrypt(self.dk,ct,self.name)

#HybridSigAdapter
class HybridSigAdapter:
    def __init__(self, profile):
        self.name = profile
        self.pub, self.priv = hybrid_sig.generate_keypair(profile)

    def sign(self, message):
        return hybrid_sig.sign(self.priv, message)            

    def verify(self, message, signature):
        try:
            return bool(hybrid_sig.verify(self.pub, message, signature))
        except Exception:
            return False

    def verify_detailed(self, message, signature):
        return hybrid_sig.verify_detailed(self.pub, message, signature)

    def corrupt(self, sig, part):
        if part == "classical":
            bad = bytearray(sig.classical_sig_bytes)
            bad[5] ^= 0x01
            return hybrid_sig.HybridSignature(
                profile=sig.profile,
                classical_sig_bytes=bytes(bad),
                pq_sig_bytes=sig.pq_sig_bytes,
            )
        bad = bytearray(sig.pq_sig_bytes)
        bad[20] ^= 0x01
        return hybrid_sig.HybridSignature(
            profile=sig.profile,
            classical_sig_bytes=sig.classical_sig_bytes,
            pq_sig_bytes=bytes(bad),
        )

#HybirdKEMAdapter 
class HybridKEMAdapter:
    def __init__(self, profile):
        self.name = profile
        self.pub, self.priv = hybrid_kem.generate_keypair(profile)

    def encrypt(self, original_msg):
        return hybrid_kem.encrypt_message(self.pub, original_msg)      

    def decrypt(self, enc):
        try:
            return hybrid_kem.decrypt_message(self.priv, enc)
        except Exception:                                              
            return False

    def corrupt(self, enc, part):
        if part == "kem":
            ct = enc.hybrid_ciphertext
            bad = bytearray(ct.pq_ciphertext_bytes)
            bad[15] ^= 0x01
            new_ct = hybrid_kem.HybridCiphertext(
                profile=ct.profile,
                classical_ephemeral_pub_bytes=ct.classical_ephemeral_pub_bytes,
                pq_ciphertext_bytes=bytes(bad),
            )
            return enc.__class__(hybrid_ciphertext=new_ct, nonce=enc.nonce,
                                 encrypted_payload=enc.encrypted_payload)
        bad = bytearray(enc.encrypted_payload)
        bad[2] ^= 0xFF
        return enc.__class__(hybrid_ciphertext=enc.hybrid_ciphertext, nonce=enc.nonce,
                             encrypted_payload=bytes(bad))

#PKIAdapter
class PKIAdapter:
    def __init__(self, algorithm="ml-dsa-65"):
        if algorithm not in list_algorithms():
            raise ValueError(f"unknown algorithm {algorithm!r}, pick one of {list_algorithms()}")
        self.name = algorithm
        self.spec = get_algorithm(algorithm)

        #The root
        self.root_ca = CertificateAuthority.create_root("Test Root", algorithm,validity_days=3650)
        self.root = self.root_ca.certificate

        #The intermediate 
        intermediate_key = self.spec.generate_key()
        self.intermediate_csr = generate_csr("Test Intermediate", intermediate_key)

        self.intermediate_cert = self.root_ca.issue_intermediate(self.intermediate_csr, validity_days=1825, path_length=0)        
        self.intermediate_ca = CertificateAuthority(self.intermediate_cert, intermediate_key)

        #The leaf 
        self.leaf_key = self.spec.generate_key()
        self.leaf_csr = generate_csr("Test Leaf", self.leaf_key, san_dns=["service.example"])
        self.leaf = self.intermediate_ca.issue_end_entity(self.leaf_csr, validity_days=90,)
    
    def codes(self, result):
        return {f.partition(": ")[0] for f in result.failures}
    
    def validate(self):
        return self.codes(validate_chain(self.leaf, [self.intermediate_cert], [self.root]))

    def validate_expired(self):
        later = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=100)
        return self.codes(validate_chain(self.leaf, [self.intermediate_cert], [self.root], at_time=later))
    
    def validate_untrusted(self):
        other_root = CertificateAuthority.create_root("Other Root", self.name).certificate
        return self.codes(validate_chain(self.leaf, [self.intermediate_cert, self.root], [other_root]))
    
    def _build_cert(self, subject_cn, issuer_name, subject_key, signing_key):
        now = datetime.datetime.now(datetime.timezone.utc)
        return (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_cn)]))
            .issuer_name(issuer_name)
            .public_key(subject_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=30))
            .sign(signing_key, *self.spec.sign_args())
        )

    def validate_forged(self):
        attacker_key = self.spec.generate_key()
        forged = self._build_cert("Forged Leaf", self.intermediate_cert.subject, attacker_key, attacker_key)
        return self.codes(validate_chain(forged, [self.intermediate_cert], [self.root]))

    def validate_leaf_as_ca(self):
        child_key = self.spec.generate_key()
        child = self._build_cert("Child Of Leaf", self.leaf.subject, child_key, self.leaf_key)
        return self.codes(validate_chain(child, [self.leaf, self.intermediate_cert], [self.root]))