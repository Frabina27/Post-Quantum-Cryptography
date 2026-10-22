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
