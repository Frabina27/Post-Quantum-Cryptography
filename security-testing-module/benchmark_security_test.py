#pyright: reportMissingImports=false
import sys 
import os 
import csv 
from pathlib import Path
from time import perf_counter 
from statistics import mean

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


#Declare array that holds algorithm being tested and what attacks it will face.
targets = [(f"RSA-{size}", partial(RSAAdapter, size), signature_attacks + encryption_attacks) for size in [2048, 3072]]
targets += [(algorithm, partial(MLDSAAdapter, algorithm), signature_attacks) for algorithm in SUPPORTED_ALGORITHMS]
targets += [(f"ECC-{curve}", partial(ECCAdapter, curve), signature_attacks)for curve in ECCImplemented.SUPPORTED_CURVES]
targets += [(f"Kyber-{param_set}", partial(KyberAdapter, param_set), encryption_attacks) for param_set in PARAMS]
targets += [(f"Hybrid-Sig-{profile}", partial(HybridSigAdapter, profile), hybrid_sig_attacks) for profile in (hybrid_sig.PROFILE_ECDSA_MLDSA65, hybrid_sig.PROFILE_RSA_MLDSA65)]
targets += [(f"Hybrid-KEM-{profile}", partial(HybridKEMAdapter, profile), hybrid_kem_attacks) for profile in (hybrid_kem.PROFILE_X25519_MLKEM768, hybrid_kem.PROFILE_P256_MLKEM768)]
targets += [(f"PKI-{alg}", partial(PKIAdapter, alg), pki_attacks) for alg in list_algorithms()]

failures = []
results = []

def save_benchmark_results(): 
    base_dir = os.path.dirname(os.path.abspath(__file__))
    results_dir = os.path.join(base_dir, "results")

    os.makedirs(results_dir, exist_ok=True)

    output_file = os.path.join(results_dir,"security_attack_testing_benchmark.csv")

    fieldnames = [
        "algorithm",
        "family",
        "attack",
        "mean_ms",
        "result"
    ]

    with open(output_file, "w", newline="") as csv_file:
        writer = csv.DictWriter(
            csv_file,
            fieldnames=fieldnames
        )

        writer.writeheader()
        writer.writerows(results)

#Group each algorithm into corresponding families so it can be compared 
def family(label):
    if label.startswith("Hybrid-Sig"): 
        return "HYBIRD-SIG"
    if label.startswith("Hybrid-KEM"): 
        return "HYBIRD-KEM"
    if label.startswith("PKI"): 
        return "PKI"
    if label.startswith("Kyber"): 
        return "KEM"
    if label.startswith("ECC"): 
        return "ECC"
    if label.startswith("RSA"): 
        return "RSA"
    if label.startswith("ML-DSA"): 
        return "ML-DSA"
    return "OTHER"

 
def main(): 
    iterations = 100
   
    #Loop through each algorithm (represented by adapter_class) and run attacks on them 
    print("\n" + "=" * 65)
    print("SECURITY TEST ATTACK BENCHMARK RESULTS")
    print("=" * 65)
    for label, adapter_class, attacks in targets:
        print(f"=== {label} ===")
        for attack in attacks:
            times = []
            result = "PASS"
            for _ in range(iterations):
                start = perf_counter()
                try:
                    attack(adapter_class)
                except AssertionError:
                    result = "FAIL"
                end = perf_counter()
                times.append((end - start) * 1000)

            if result == "FAIL":
                failures.append((label,attack.__name__))

            results.append({
                "algorithm": label,
                "family": family(label),
                "attack": attack.__name__,
                "mean_ms": round(mean(times), 4),
                "result": result
            })
            print(f"[{result}] {attack.__name__}: {mean(times):.4f} ms")
        print("\n")



    if failures:
        print(f"{len(failures)} failure(s)")
        for algorithm, test in failures:
            print(f"- {algorithm}: {test}")
    else: 
        print(f"All algorithm functions have passed")

    save_benchmark_results()



if __name__ == "__main__":
    main()