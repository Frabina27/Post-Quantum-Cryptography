from utils import INTER, ROOT, ask_password, ask_path, console, get_choice, pause, render_menu, run_openssl

INSPECT_MAIN_OPTIONS = [
    ("1", "Inspect X.509 Certificate (.crt / .pem)"),
    ("2", "Inspect Certificate Signing Request (.csr)"),
    ("3", "Inspect Private or Public Key (.key / .pub)"),
    ("4", "Verify Certificate Trust Chain"),
]

def inspect_cert():
    cert = ask_path("Path to certificate")
    run_openssl(["x509", "-in", cert, "-noout", "-text"])
    pause()

def inspect_csr():
    csr = ask_path("Path to CSR")
    if run_openssl(["req", "-in", csr, "-noout", "-text", "-verify"]):
        console.print("[bold green]CSR signature is valid[/bold green]")
    pause()

def inspect_key():
    path = ask_path("Path to key")
    pem = path.read_text(errors = "ignore")

    # public keys and unencrypted keys don't need a password
    if "PUBLIC KEY" in pem:
        run_openssl(["pkey", "-pubin", "-in", path, "-noout", "-text"])
    elif "ENCRYPTED" in pem:
        pwd = ask_password("Key password")
        run_openssl(["pkey", "-in", path, "-passin", "env:PKEY_PASS", "-noout", "-text"], password = pwd)
    else:
        run_openssl(["pkey", "-in", path, "-noout", "-text"])
    pause()

def verify_chain():
    cert = ask_path("Path to certificate")
    root_crt = ask_path("Trusted root CA", default = ROOT / "ca.crt")

    args = ["verify", "-CAfile", root_crt]
    if (INTER / "ca.crt").exists():
        inter_crt = ask_path("Intermediate CA", default = INTER / "ca.crt")
        args += ["-untrusted", inter_crt]

    if run_openssl(args + [cert]):
        console.print("[bold green]Certificate chain is valid[/bold green]")
    pause()

def render():
    console.clear()
    while True:
        render_menu("Inspect & Validate", INSPECT_MAIN_OPTIONS)

        match get_choice(len(INSPECT_MAIN_OPTIONS)):
            case "0":
                return
            case "1":
                inspect_cert()
            case "2":
                inspect_csr()
            case "3":
                inspect_key()
            case "4":
                verify_chain()
