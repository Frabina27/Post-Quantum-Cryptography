#pyright: reportMissingImports=false
import sys 
from pathlib import Path

#Get the paths for all of the other modules 
base = Path(__file__).resolve().parent.parent   
sys.path.append(str(base / "Kyber"))


from functools import partial
from adapters import RSAAdapter, MLDSAAdapter, ECCAdapter, KyberAdapter, HybridSigAdapter, HybridKEMAdapter,PKIAdapter
from attacks import signature_attacks, encryption_attacks, hybrid_sig_attacks, hybrid_kem_attacks,pki_attacks
from mldsa_project import SUPPORTED_ALGORITHMS
from ecc_implemented import ECCImplemented
from kpke import PARAMS 
from pqpki.algorithms import list_algorithms
import hybrid_sig
import hybrid_kem


#Declare array that holds algorithm being tested and what attacks it will face and array for failures. 
targets = [("RSA", RSAAdapter, signature_attacks + encryption_attacks)]
targets += [(algorithm, partial(MLDSAAdapter, algorithm), signature_attacks) for algorithm in SUPPORTED_ALGORITHMS]
targets += [(f"ECC-{curve}", partial(ECCAdapter, curve), signature_attacks)for curve in ECCImplemented.SUPPORTED_CURVES]
targets += [(f"Kyber-{param_set}", partial(KyberAdapter, param_set), encryption_attacks) for param_set in PARAMS]
targets += [(f"Hybrid-Sig-{profile}", partial(HybridSigAdapter, profile), hybrid_sig_attacks) for profile in (hybrid_sig.PROFILE_ECDSA_MLDSA65, hybrid_sig.PROFILE_RSA_MLDSA65)]
targets += [(f"Hybrid-KEM-{profile}", partial(HybridKEMAdapter, profile), hybrid_kem_attacks) for profile in (hybrid_kem.PROFILE_X25519_MLKEM768, hybrid_kem.PROFILE_P256_MLKEM768)]
targets += [(f"PKI-{alg}", partial(PKIAdapter, alg), pki_attacks) for alg in list_algorithms()]

failures = []
   
#Loop through each algorithm (represented by adapter_class) and run attacks on them 
print(f"FUNCTIONAL / SECURITY TESTS:")
for label, adapter_class, attacks in targets:
    print(f"=== {label} ===")
    for attack in attacks:
        try:
            attack(adapter_class)
            print(f"[PASS] {attack.__name__}")
        except AssertionError:
            print(f"[FAIL] {attack.__name__}")
            failures.append((label,attack.__name__))
    print("\n")


if failures:
    print(f"{len(failures)} failure(s)")
    for algorithm, test in failures:
        print(f"- {algorithm}: {test}")
else: 
    print(f"All algorithm functions have passed")