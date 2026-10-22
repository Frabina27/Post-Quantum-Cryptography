from adapters import RSAAdapter, MLDSAAdapter
from attacks import signature_attacks, encryption_attacks

#Declare array that holds algorithm being tested and what attacks it will face and array for failures. 
targets = [(RSAAdapter, signature_attacks + encryption_attacks),(MLDSAAdapter, signature_attacks)]
failures = []

#Loop through each algorithm (represented by adapter_class) and run attacks on them 
print(f"FUNCTIONAL / SECURITY TESTS:")
for adapter_class, attacks in targets:
    print(f"=== {adapter_class.name} ===")
    for attack in attacks:
        try:
            attack(adapter_class)
            print(f"[PASS] {attack.__name__}")
        except AssertionError:
            print(f"[FAIL] {attack.__name__}")
            failures.append((adapter_class.name,attack.__name__))
    print("\n")


if failures:
    print(f"{len(failures)} failure(s)")
    for algorithm, test in failures:
        print(f"- {algorithm}: {test}")
else: 
    print(f"All algorithm functions have passed")