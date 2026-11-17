# ML-DSA (Dilithium) project file
# uses liboqs-python (the oqs package) to do keygen / sign / verify
# for ML-DSA-44, ML-DSA-65 and ML-DSA-87
#
# run this file to do a quick sign/verify demo on the algorithm(s)
# the timing stuff is in benchmark_mldsa.py

import sys
import oqs


ALGORITHMS = ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"]

TEST_MESSAGE = b"UTD Data and Applications Security - ML-DSA test message"


def check_algorithm(algorithm):
    # make sure liboqs was actually built with this algorithm
    enabled = oqs.get_enabled_sig_mechanisms()
    if algorithm not in enabled:
        print("Error: " + algorithm + " is not enabled in this liboqs build")
        print("Enabled signature algorithms are:")
        print(enabled)
        raise RuntimeError(algorithm + " is not available")


class MLDSA:

    def __init__(self, algorithm="ML-DSA-44"):

        if algorithm not in ALGORITHMS:
            raise ValueError("algorithm has to be one of " + str(ALGORITHMS))

        check_algorithm(algorithm)

        self.algorithm = algorithm
        self.public_key = None
        self.private_key = None

        # one oqs object for signing (holds the secret key) and one for verifying
        self.signer = oqs.Signature(algorithm)
        self.verifier = oqs.Signature(algorithm)

        self.generate_keypair()

    def generate_keypair(self):
        self.public_key = self.signer.generate_keypair()
        self.private_key = self.signer.export_secret_key()
        return self.public_key, self.private_key

    def sign(self, message):
        if not isinstance(message, bytes):
            raise TypeError("message has to be bytes")
        signature = self.signer.sign(message)
        return signature

    def verify(self, message, signature, public_key=None):
        # if no public key is passed in just use our own
        if public_key is None:
            public_key = self.public_key

        # the python wrapper can throw an error on really broken input
        # (like the wrong length) so we count that as the signature failing
        try:
            result = self.verifier.verify(message, signature, public_key)
        except (RuntimeError, ValueError):
            result = False

        if result:
            return True
        else:
            return False

    def get_public_key_size(self):
        return len(self.public_key)

    def get_private_key_size(self):
        return len(self.private_key)

    def close(self):
        # frees the memory liboqs uses for the secret key
        self.signer.free()
        self.verifier.free()


def run_demo(algorithm, message=TEST_MESSAGE):
    # quick demo: make keys, sign the message, check the signature works
    # (the tampering / attack tests are in security-testing-module so not doing them here)

    dsa = MLDSA(algorithm)
    signature = dsa.sign(message)
    ok = dsa.verify(message, signature)

    print("")
    print("=" * 60)
    print("ML-DSA DEMO: " + algorithm)
    print("=" * 60)
    print("Message size:     " + str(len(message)) + " bytes")
    print("Public key size:  " + str(dsa.get_public_key_size()) + " bytes")
    print("Private key size: " + str(dsa.get_private_key_size()) + " bytes")
    print("Signature size:   " + str(len(signature)) + " bytes")

    if ok:
        print("Signature verified: yes")
    else:
        print("Signature verified: NO")

    dsa.close()
    return ok


def main():
    # usage:  python mldsa_project.py            -> runs all 3
    #         python mldsa_project.py ML-DSA-65  -> just that one
    if len(sys.argv) > 1:
        algs = sys.argv[1:]
        for a in algs:
            if a not in ALGORITHMS:
                print("Unknown algorithm: " + a)
                print("Pick from: " + ", ".join(ALGORITHMS))
                sys.exit(1)
    else:
        algs = ALGORITHMS

    print("ML-DSA Project (Open Quantum Safe)")
    print("liboqs version:        " + oqs.oqs_version())
    print("liboqs-python version: " + oqs.oqs_python_version())

    all_good = True
    for alg in algs:
        if not run_demo(alg):
            all_good = False

    print("")
    if all_good:
        print("All ML-DSA signatures verified!")
    else:
        print("Something went wrong, see above")
        sys.exit(1)


if __name__ == "__main__":
    main()
