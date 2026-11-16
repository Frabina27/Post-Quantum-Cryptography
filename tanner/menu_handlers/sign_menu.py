from menu_handlers.ca_menu import ok_to_overwrite
from utils import INTER, ROOT, STORE, ask_password, ask_path, console, get_choice, openssl_output, pause, render_menu, run_openssl

SIGN_MAIN_OPTIONS = [
    ("1", "Sign a File (Detached Digital Signature)"),
    ("2", "Verify File Signature (Public Key)"),
    ("3", "Verify Signature and Signer CA Trust Chain"),
]

DIGEST_OPTIONS = [
    ("1", "SHA-256 (Default)"),
    ("2", "SHA-384"),
    ("3", "SHA-512"),
]

DIGESTS = {"1": "sha256", "2": "sha384", "3": "sha512"}

def select_digest(context: str):
    console.clear()
    render_menu(f"{context} - Select Hash Digest", DIGEST_OPTIONS, back_text = "Return to Signing Menu")
    return DIGESTS.get(get_choice(len(DIGEST_OPTIONS)))

def is_ed25519(key, password = None, public = False):
    if public:
        args = ["pkey", "-pubin", "-in", key, "-noout", "-text_pub"]
    else:
        args = ["pkey", "-in", key, "-passin", "env:PKEY_PASS", "-noout", "-text_pub"]

    output = openssl_output(args, password = password)
    if output is None:
        return None
    return output.startswith("ED25519")

def sign_file():
    file = ask_path("Path to file to sign")
    key = ask_path("Path to private key")

    pwd = ""
    if "ENCRYPTED" in key.read_text(errors = "ignore"):
        pwd = ask_password("Key password")

    ed25519 = is_ed25519(key, password = pwd)
    if ed25519 is None:
        console.print("[bold red]Could not read the private key (wrong password?)[/bold red]")
        pause()
        return

    sig = file.with_name(file.name + ".sig")
    if not ok_to_overwrite(sig):
        pause()
        return

    # ed25519 can't be used with dgst, it hashes the file itself
    if ed25519:
        args = ["pkeyutl", "-sign", "-rawin", "-inkey", key, "-passin", "env:PKEY_PASS", "-in", file, "-out", sig]
    else:
        digest = select_digest("Sign File")
        if digest is None:
            return
        args = ["dgst", f"-{digest}", "-sign", key, "-passin", "env:PKEY_PASS", "-out", sig, file]

    if run_openssl(args, password = pwd, status = "Signing File..."):
        console.print(f"\n[bold green]Signature Created: {sig}[/bold green]")
    pause()

def check_signature(file, sig, pub):
    ed25519 = is_ed25519(pub, public = True)
    if ed25519 is None:
        console.print("[bold red]Could not read the public key[/bold red]")
        return False

    if ed25519:
        args = ["pkeyutl", "-verify", "-rawin", "-pubin", "-inkey", pub, "-sigfile", sig, "-in", file]
    else:
        digest = select_digest("Verify Signature")
        if digest is None:
            return None
        args = ["dgst", f"-{digest}", "-verify", pub, "-signature", sig, file]

    return run_openssl(args, status = "Verifying Signature...")

def verify_with_key():
    file = ask_path("Path to signed file")
    sig = ask_path("Path to signature", default = file.with_name(file.name + ".sig"))
    pub = ask_path("Path to public key")

    ok = check_signature(file, sig, pub)
    if ok is None:
        return
    if ok:
        console.print("[bold green]Signature is valid[/bold green]")
    else:
        console.print("[bold red]Signature is NOT valid[/bold red]")
    pause()

def verify_with_chain():
    file = ask_path("Path to signed file")
    sig = ask_path("Path to signature", default = file.with_name(file.name + ".sig"))
    cert = ask_path("Path to signer certificate")

    args = ["verify", "-crl_check", "-CAfile", ROOT / "ca.crt"]
    if (INTER / "ca.crt").exists():
        args += ["-untrusted", INTER / "ca.crt"]
    for crl in [ROOT / "ca.crl", INTER / "ca.crl"]:
        if crl.exists():
            args += ["-CRLfile", crl]

    if not run_openssl(args + [cert], status = "Checking Trust Chain and CRL..."):
        console.print("[bold red]Signer certificate is NOT trusted (untrusted, revoked, or its CA has no CRL yet)[/bold red]")
        pause()
        return

    pub = STORE / "signer.pub"
    if not run_openssl(["x509", "-in", cert, "-pubkey", "-noout", "-out", pub], status = "Extracting Public Key..."):
        pause()
        return

    ok = check_signature(file, sig, pub)
    pub.unlink(missing_ok = True)
    if ok is None:
        return
    if ok:
        console.print("[bold green]Signature is valid and the signer is trusted[/bold green]")
    else:
        console.print("[bold red]Signature is NOT valid[/bold red]")
    pause()

def render():
    console.clear()
    while True:
        render_menu("Digital Signatures & Verification", SIGN_MAIN_OPTIONS)

        match get_choice(len(SIGN_MAIN_OPTIONS)):
            case "0":
                return
            case "1":
                sign_file()
            case "2":
                verify_with_key()
            case "3":
                verify_with_chain()
