#pyright: reportMissingImports=false
import sys 
import oqs 
import os 
import datetime 
import subprocess
import tempfile
import time
from pathlib import Path
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519



#Get the paths for all of the other modules 
base = Path(__file__).resolve().parent.parent   
sys.path.append(str(base))   
sys.path.append(str(base / "rsa-module"))
sys.path.append(str(base / "mldsa-module"))
sys.path.append(str(base / "ecc"))
sys.path.append(str(base / "hybrid-module"))   
sys.path.append(str(base / "Kyber")) 
sys.path.append(str(base / "tanner")) 


from rsa_crypto import RSACrypto
from mldsa_project import ALGORITHMS, check_algorithm
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
    def __init__(self,key_size=2048):
        self.name = f"RSA-{key_size}"
        self.rsa = RSACrypto(key_size)
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
        if algorithm not in ALGORITHMS: 
            raise ValueError(f"Unsupported Algorithm: {algorithm} pick one of {ALGORITHMS}")
        check_algorithm(algorithm)
        self.algorithm = algorithm 
        self.signer = oqs.Signature(self.algorithm)
        self.verifier = oqs.Signature(self.algorithm) 
        self.public_key = self.signer.generate_keypair()
        self.private_key = self.signer.export_secret_key()
    def sign(self,message): 
        return self.signer.sign(message)
    def verify(self,message,signature): 
        try:
            return self.verify(self.verifier, message, signature, self.public_key)
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
    
class ClassicalPKIAdapter:
    #Path to open openssl.cnf so that the classical PKI menu can be used 
    cnf = f"{base}/tanner/openssl.cnf"
    password = "testpass"
    KEY_ARGS = {
        "RSA-2048": ["-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048"],
        "RSA-3072": ["-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:3072"],
        "ECDSA-P-256": ["-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256"],
        "ECDSA-P-384": ["-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-384"],
        "Ed25519": ["-algorithm", "ED25519"],
    }

    ERROR_CODES = [
        ("certificate has expired", "expired"),
        ("self-signed certificate in certificate chain", "no-trust-anchor"),
        ("unable to get local issuer certificate", "no-trust-anchor"),
        ("certificate signature failure", "signature"),
        ("invalid CA certificate", "not-a-ca"),
    ]

    def __init__(self, algorithm):
        if algorithm not in self.KEY_ARGS: 
            raise ValueError(f"Unsupported Algorithm: {algorithm} pick one of {self.KEY_ARGS}")
        self.name = algorithm
        self.key_args = self.KEY_ARGS[algorithm]
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)
        self.root_dir = self.dir / "root"
        self.inter_dir = self.dir / "intermediate"
        self.root_dir.mkdir()
        self.inter_dir.mkdir()

        #The root (create key and then certificate)
        self.root_crt = self._make_root(self.root_dir, "Test Root")

        #The intermediate (create key, cetrificate signing, and root signs it)
        self.inter_key = self.inter_dir / "ca.key"
        self._must(self._openssl(["genpkey", *self.key_args, "-aes256", "-pass", "env:PKEY_PASS", "-out", self.inter_key], password=self.password))
        inter_csr = self.inter_dir / "ca.csr"
        self._must(self._openssl(["req", "-new", "-config", self.cnf, "-key", self.inter_key, "-passin", "env:PKEY_PASS",
                                  "-subj", "/CN=Test Intermediate", "-out", inter_csr], password=self.password))
        self._init_ca_dir(self.root_dir)
        self.inter_crt = self.inter_dir / "ca.crt"
        self._must(self._openssl(["ca", "-batch", "-config", self.cnf, "-extensions", "v3_intermediate_ca", "-days", "1825", "-notext",
                                  "-cert", self.root_crt, "-keyfile", self.root_dir / "ca.key", "-passin", "env:PKEY_PASS",
                                  "-in", inter_csr, "-out", self.inter_crt], ca_dir=self.root_dir, password=self.password))

        #The leaf (gets certificate with the server certificate extension)
        self.leaf_key = self.dir / "leaf.key"
        self._must(self._openssl(["genpkey", *self.key_args, "-out", self.leaf_key]))
        leaf_csr = self.dir / "leaf.csr"
        self._must(self._openssl(["req", "-new", "-config", self.cnf, "-key", self.leaf_key, "-subj", "/CN=Test Leaf",
                                  "-addext", "subjectAltName=DNS:service.example", "-out", leaf_csr]))
        self._init_ca_dir(self.inter_dir)
        self.leaf_crt = self.dir / "leaf.crt"
        self._must(self._openssl(["ca", "-batch", "-config", self.cnf, "-extensions", "server_cert", "-days", "365", "-notext",
                                  "-cert", self.inter_crt, "-keyfile", self.inter_key, "-passin", "env:PKEY_PASS",
                                  "-in", leaf_csr, "-out", self.leaf_crt], ca_dir=self.inter_dir, password=self.password))

    #Runs openssl 
    def _openssl(self, args, ca_dir="root", password=None):
        env = os.environ.copy()
        env["CA_DIR"] = str(ca_dir)
        env["CRL_URL"] = f"http://127.0.0.1:8080/{Path(ca_dir).name}/ca.crl.der"
        if password is not None:
            env["PKEY_PASS"] = password
        args = [str(a) for a in args]
        return subprocess.run(["openssl"] + args, env=env, capture_output=True, text=True)

    def _must(self, result):
        if result.returncode != 0:
            raise RuntimeError(result.stderr)

    
    def _init_ca_dir(self, ca_dir):
        (ca_dir / "newcerts").mkdir(parents=True, exist_ok=True)
        (ca_dir / "index.txt").touch()
        if not (ca_dir / "crlnumber").exists():
            (ca_dir / "crlnumber").write_text("1000\n")

    def _make_root(self, ca_dir, cn):
        key = ca_dir / "ca.key"
        crt = ca_dir / "ca.crt"
        self._must(self._openssl(["genpkey", *self.key_args, "-aes256", "-pass", "env:PKEY_PASS", "-out", key], password=self.password))
        self._must(self._openssl(["req", "-x509", "-new", "-config", self.cnf, "-extensions", "v3_root_ca", "-key", key,
                                  "-passin", "env:PKEY_PASS", "-subj", f"/CN={cn}", "-days", "3650", "-out", crt],
                                 ca_dir=ca_dir, password=self.password))
        return crt

    def codes(self, result):
        if result.returncode == 0:
            return set()
        text = result.stdout + result.stderr
        found = {code for message, code in self.ERROR_CODES if message in text}
        return found or {"unknown: " + text.strip()}

    #Verify chain menu option 
    def _verify(self, cert, trusted, untrusted=(), extra=()):
        args = ["verify", "-CAfile", trusted]
        for u in untrusted:
            args += ["-untrusted", u]
        return self.codes(self._openssl(args + list(extra) + [cert]))

    def validate(self):
        return self._verify(self.leaf_crt, self.root_crt, [self.inter_crt])

    def validate_expired(self):
        #-attime = openssl's version of at_time (leaf lives 365 days)
        later = int(time.time()) + 400 * 24 * 3600
        return self._verify(self.leaf_crt, self.root_crt, [self.inter_crt], ["-attime", later])

    def validate_untrusted(self):
        other_dir = self.dir / "other"
        other_dir.mkdir()
        other_root = self._make_root(other_dir, "Other Root")
        return self._verify(self.leaf_crt, other_root, [self.inter_crt, self.root_crt])

    def _build_cert(self, subject_cn, issuer_name, subject_key, signing_key):
        now = datetime.datetime.now(datetime.timezone.utc)
        digest = None if isinstance(signing_key, ed25519.Ed25519PrivateKey) else hashes.SHA256()
        return (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_cn)]))
            .issuer_name(issuer_name)
            .public_key(subject_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=30))
            .sign(signing_key, digest)
        )

    def _load_key(self, path):
        return serialization.load_pem_private_key(path.read_bytes(), password=None)

    def _write(self, cert, name):
        path = self.dir / name
        path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        return path

    def validate_forged(self):
        attacker_path = self.dir / "attacker.key"
        self._must(self._openssl(["genpkey", *self.key_args, "-out", attacker_path]))
        attacker_key = self._load_key(attacker_path)
        inter = x509.load_pem_x509_certificate(self.inter_crt.read_bytes())
        forged = self._build_cert("Forged Leaf", inter.subject, attacker_key, attacker_key)
        return self._verify(self._write(forged, "forged.crt"), self.root_crt, [self.inter_crt])

    def validate_leaf_as_ca(self):
        child_path = self.dir / "child.key"
        self._must(self._openssl(["genpkey", *self.key_args, "-out", child_path]))
        child_key = self._load_key(child_path)
        leaf = x509.load_pem_x509_certificate(self.leaf_crt.read_bytes())
        child = self._build_cert("Child Of Leaf", leaf.subject, child_key, self._load_key(self.leaf_key))
        return self._verify(self._write(child, "child.crt"), self.root_crt, [self.leaf_crt, self.inter_crt])



