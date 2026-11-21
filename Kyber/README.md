# ML-KEM Kyber

This folder contains an original python implementation of ML-KEM, the post-quantum key encapsulation algorithm standardized in FIPS 203. A KEM allows two parties to agree on a shared 32-byte secret, and its security relies on the Module-LWE lattice problem, which is difficult for quantum computers to break. This implementation is done without external libraries, with the exception of hashlib. Function names are taken from the PDF for ease of verifying code.

## Files

`auxiliary.py` contains helper algorithms required for the main Kyber algorithm. This includes, hash functions, byte encoding/decoding, compression/decompression, samplers, NTT, and polynomial/matrix arithmetic.

`kpke.py` contains K-PKE, the public key encryption scheme that ML-KEM is built on. This file includes keygen, encryption, and decryption for ML-KEM 512, 768, and 1024.

`mlkem.py` contains the algorithm itself. It wraps K-PKE in the Fujisaki-Okamoto transform to perform encapsulation and decapsulation as well as ciphertext comparison.

`test_*.py` are unittest suites, and there is one for each of the aforementioned files.

`*.pdf` are reference documents with algorithm specs

## API

- MLKEM_KeyGen(param_set)
    - Returns (ek, dk), which are the public encapsulation key and private decapsulation key
- MLKEM_Encaps(ek, param_set)
    - Returns (K, c), which is a shared key and a ciphertext to send to the key holder
- ML_KEM_Decaps(dk, c, param_set)
    - Returns K, the shared key
- *_internal
    - Versions of the previous calls where you need to pass in randomness yourself. Useful for known-answer testing

## How to run

1. Go to repo root
2. Optionally install reference implementation. The `test_mlkem.py` files uses the existing `kyber-py` library to test the correctness of this implementation. The tests requiring the module are automatically skipped if the module is not installed.

`pip install kyber-py # or: pip install -r requirements.txt`

There are three things you can do from here:

1. Run the demo

`python3 Kyber/mlkem.py`

Expected output:

```
ML-KEM-512: ok (ek=800, dk=1632, c=768)
ML-KEM-768: ok (ek=1184, dk=2400, c=1088)
ML-KEM-1024: ok (ek=1568, dk=3168, c=1568)
```

2. Run the tests

`python3 -m unittest discover -s Kyber -v`

3. Use it in other code. The module can be imported from inside Kyber/ or if you have it on sys.path

Example:

```
from mlkem import MLKEM_KeyGen, MLKEM_Encaps, MLKEM_Decaps

ek, dk = MLKEM_KeyGen("ML-KEM-768")
K, c = MLKEM_Encaps(ek, "ML-KEM-768")      # sender
assert MLKEM_Decaps(dk, c, "ML-KEM-768") == K  # receiver
```

## Important note

This is an example implementation and does not run in constant-time. Do not use for protecting real secrets.