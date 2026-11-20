# Security Attack Testing Module 

## Project Overview

I worked on implementing the Security Test Attack modules where I performed attacks on each module/algorithm and verified that it failed correctly. The tests I implmented fall into three categories: encryption, signature, and public key infrastructure (PKI). 

## Setup

### Mac

1. Install the required build tools:

   ```bash
   brew install cmake ninja
   ```

2. Create a virtual environment:

   ```bash
   python3 -m venv .venv
   ```

3. Activate the virtual environment:

   ```bash
   source .venv/bin/activate
   ```

4. Install the required Python packages:

   ```bash
   pip install cryptography liboqs-python
   ```

### Windows

1. Install the required dependencies:
   - Git
   - CMake
   - A C compiler (Visual Studio Build Tools)

2. Create a virtual environment:

   ```powershell
   py -m venv .venv
   ```

3. Activate the virtual environment:

   ```powershell
   .venv\Scripts\activate
   ```

4. Install the required Python packages:

   ```powershell
   pip install cryptography liboqs-python
   ```


## Run the Security Test Attack Module

1. Activate the virtual environment:

   **Mac:**
   ```bash
   source .venv/bin/activate
   ```

   **Windows:**
   ```powershell
   .venv\Scripts\activate
   ```

2. Navigate to the security testing module:

   ```bash
   cd security-testing-module
   ```

3. Run the security test attacks:

   ```bash
   python run-test-attacks.py
   ```

## Run the Security Test Attack Benchmarks

1. Activate the virtual environment (if not already activated):

   **Mac:**
   ```bash
   source .venv/bin/activate
   ```

   **Windows:**
   ```powershell
   .venv\Scripts\activate
   ```

2. Navigate to the security testing module:

   ```bash
   cd security-testing-module
   ```

3. Run the benchmark tests:

   ```bash
   python run-test-attacks.py
   ```



## Files and What They Do

| File | Purpose |
|---|---|
| `run-test-attacks.py` | Main code that loops through each module and runs the designated test attack. |
| `adapters.py` | Made similar methods fall under the same function name to make it easier to implement in attacks.py |
| `attacks.py` | Consists of the different attacks, such as corrupted_ciphertext, altering message, invalid certificate, etc. |
| `benchmark-security-test.py` | Measures how long each security test attack takes for each module. |
| `security_attack_testing_benchmark.csv` | Stores the benchmark results so the module and security test can be compared. |
| `security-testing-readme.md` | Explains my module, how it works, and how to run it. |