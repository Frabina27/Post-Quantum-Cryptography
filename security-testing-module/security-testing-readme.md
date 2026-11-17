# Security Attack Testing Module 

## Project Overview

I worked on implementing the Security Test Attack modules where I performed attacks on each module/algorithm and verified that it failed correctly. The tests I implmented fall into three categories: encryption, signature, and public key infrastructure (PKI). 

## Setup 
### Mac
-Run Inside of Terminal: 
    brew install cmake ninja
    python3 -m venv .venv
    source .venv/bin/activate
    pip install cryptography liboqs-python
### Windows
-Install `git`, `cmake`, and a C compiler (Visual Studio Build Tools) first,
then:
-Run Inside of Terminal: 
    py -m venv .venv
    .venv\Scripts\activate
    pip install cryptography liboqs-python

## Run the tests
-Inside of Terminal: 
    Macbook: source .venv/bin/activate 
    Windows: .venv\Scripts\activate
    cd security-testing-module
    python run-test-attacks.py

## Files and What They Do

| File | Purpose |
|---|---|
| `run-test-attacks.py` | Main code that loops through each module and runs the designated test attack. |
| `adapters.py` | Made similar methods fall under the same function name to make it easier to implement in attacks.py |
| `attacks.py` | Consists of the different attacks, such as corrupted_ciphertext, altering message, invalid certificate, etc. |
| `benchmark-security-test.py` | Measures how long each security test attack takes for each module. |
| `security_attack_testing_benchmark.csv` | Stores the benchmark results so the module and security test can be compared. |
| `security-testing-readme.md` | Explains my module, how it works, and how to run it. |