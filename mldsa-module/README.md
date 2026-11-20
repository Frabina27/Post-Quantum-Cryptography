# ML-DSA (Dilithium) Module
This module demonstrates ML-DSA, a post-quantum digital signature algorithm. It uses liboqs-python to generate keys, sign a test message, and verify the signature.

The script supports ML-DSA-44, ML-DSA-65, and ML-DSA-87.
## Requirements
- Python 3.11 or newer
- Windows, macOS, or Linux with a working liboqs installation
- liboqs-python (listed in this folder's requirements.txt)
- Git, CMake, and a C compiler may be needed if liboqs has to be built during installation
## Installation
Clone the repository if you have not already:
```git clone https://github.com/Frabina27/Post-Quantum-Cryptography.git```
```cd Post-Quantum-Cryptography/mldsa-module```
Install the Python dependency:
```python -m pip install -r requirements.txt```
liboqs-python also needs the underlying liboqs library. If it is not already installed, the Python wrapper may attempt to download and build it on first use.
## Running the Module
From the mldsa-module folder, run:
```python mldsa_project.py```
This runs the demo for all three supported ML-DSA algorithms.

To run only one algorithm, use its name as an argument. For example:
```python mldsa_project.py ML-DSA-65```
The program generates a key pair, signs a sample message, and checks whether the signature is valid. It prints the key and signature sizes along with the verification result. A successful run should show `Signature verified: yes.`

On the first run, `liboqs-python` may automatically download and install the required `liboqs` library, which can produce a large amount of terminal output. This is a one-time setup process and may require CMake and C/C++ build tools. Subsequent runs should display only the ML-DSA test results and any minor library messages.

## Benchmarking
The module also includes a separate benchmarking script to measure the performance of ML-DSA-44, ML-DSA-65, and ML-DSA-87.
To run the benchmarks:
```bash
python benchmark_mldsa.py
```
By default, the script performs 1,000 iterations for key generation, signing, and verification. It calculates the mean, median, standard deviation, and operations per second for each algorithm.
To run fewer iterations:
```bash
python benchmark_mldsa.py --iterations 100
```
To benchmark only one algorithm:
```bash
python benchmark_mldsa.py --algorithm ML-DSA-65
```
The results are displayed in the terminal and saved to `results/mldsa_benchmark.csv`.
Benchmarking is optional and runs separately from the main demonstration. Results may vary depending on the computer being used.

No login credentials are needed.
Limitations
- The module runs separately from the other parts of the group project.
- Tampering and attack tests are handled in the separate security-testing-module, not in this demo script.
