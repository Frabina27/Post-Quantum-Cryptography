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

No login credentials are needed.
Limitations
- This is a basic demonstration using a predefined test message, not a full application.
- The module runs separately from the other parts of the group project.
- Tampering and attack tests are handled in the separate security-testing-module, not in this demo script.
- It is intended for educational use only.
