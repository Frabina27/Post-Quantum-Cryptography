from rich.prompt import Confirm, Prompt
from utils import CNF, INTER, ROOT, ask_password, ask_path, console, get_choice, init_ca_dir, pause, render_menu, run_openssl

CA_MAIN_OPTIONS = [
    ("1", "Root CA Operations"),
    ("2", "Intermediate CA Operations"),
]

ROOT_CA_OPTIONS = [
    ("1", "Create New Private Key"),
    ("2", "Reuse Existing Private Key"),
    ("3", "Generate Self-Signed Root Certificate"),
]

INTERMEDIATE_CA_OPTIONS = [
    ("1", "Generate Intermediate Private Key"),
    ("2", "Generate Intermediate CSR"),
    ("3", "Sign Intermediate CSR with Root CA"),
    ("4", "Assemble Complete CA Bundle (Chain)"),
]

ALGO_OPTIONS = [
    ("1", "RSA 4096 (High-Security Classical)"),
    ("2", "RSA 3072 (NIST Recommended Classical Minimum)"),
    ("3", "RSA 2048 (Legacy Classical)"),
    ("4", "ECDSA P-256 (prime256v1)"),
    ("5", "ECDSA P-384 (secp384r1)"),
    ("6", "Ed25519 (RFC 8032 Edwards Curve)"),
]

# genpkey args for each algorithm option
ALGO_ARGS = {
    "1": ["-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:4096"],
    "2": ["-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:3072"],
    "3": ["-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048"],
    "4": ["-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256"],
    "5": ["-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-384"],
    "6": ["-algorithm", "ED25519"],
}

def select_algorithm(context: str):
    console.clear()
    render_menu(f"{context} - Key Algorithm", ALGO_OPTIONS, back_text = "Return to Previous Menu")
    return ALGO_ARGS.get(get_choice(len(ALGO_OPTIONS)))

def ok_to_overwrite(path):
    if not path.exists():
        return True
    return Confirm.ask(f"[yellow]{path} already exists. Overwrite?[/yellow]", default = False)

def generate_ca_key(ca_dir, context: str):
    algo = select_algorithm(context)
    if algo is None:
        return

    key = ca_dir / "ca.key"
    if not ok_to_overwrite(key):
        pause()
        return

    pwd = ask_password(confirm = True)
    if pwd is None:
        pause()
        return

    ca_dir.mkdir(parents = True, exist_ok = True)
    if run_openssl(["genpkey", *algo, "-aes256", "-pass", "env:PKEY_PASS", "-out", key], password = pwd, status = "Generating Private Key..."):
        console.print(f"\n[bold green]Key Generated: {key}[/bold green]")
    pause()

def reuse_root_key():
    src = ask_path("Path to existing private key")
    key = ROOT / "ca.key"
    if not ok_to_overwrite(key):
        pause()
        return

    old_pwd = ask_password("Current key password (blank if unencrypted)")
    new_pwd = ask_password("New Root CA key password", confirm = True)
    if new_pwd is None:
        pause()
        return

    # read the old key and re-encrypt it with the new password
    ROOT.mkdir(parents = True, exist_ok = True)
    args = ["pkey", "-in", src, "-passin", "env:OLD_PASS", "-aes256", "-passout", "env:PKEY_PASS", "-out", key]
    if run_openssl(args, password = new_pwd, env_extra = {"OLD_PASS": old_pwd}, status = "Importing Private Key..."):
        console.print(f"\n[bold green]Key Imported: {key}[/bold green]")
    pause()

def generate_root_cert():
    cn = Prompt.ask("Root CA Common Name", default = "Classical Root CA")
    pwd = ask_password("Root CA key password")
    cert = ROOT / "ca.crt"
    if not ok_to_overwrite(cert):
        pause()
        return

    init_ca_dir(ROOT)
    args = ["req", "-x509", "-new", "-config", CNF, "-extensions", "v3_root_ca",
            "-key", ROOT / "ca.key", "-passin", "env:PKEY_PASS",
            "-subj", f"/CN={cn}", "-days", "3650", "-out", cert]
    if run_openssl(args, password = pwd, status = "Generating Root Certificate..."):
        console.print(f"\n[bold green]Root Certificate Generated: {cert}[/bold green]")
    pause()

def generate_intermediate_csr():
    cn = Prompt.ask("Intermediate CA Common Name", default = "Classical Intermediate CA")
    pwd = ask_password("Intermediate CA key password")
    csr = INTER / "ca.csr"

    args = ["req", "-new", "-config", CNF, "-key", INTER / "ca.key", "-passin", "env:PKEY_PASS",
            "-subj", f"/CN={cn}", "-out", csr]
    if run_openssl(args, password = pwd, status = "Generating CSR..."):
        console.print(f"\n[bold green]CSR Generated: {csr}[/bold green]")
    pause()

def sign_intermediate_csr():
    pwd = ask_password("Root CA key password")
    cert = INTER / "ca.crt"
    if not ok_to_overwrite(cert):
        pause()
        return

    # root signs it, so the root's database gets the record
    init_ca_dir(INTER)
    args = ["ca", "-batch", "-config", CNF, "-extensions", "v3_intermediate_ca", "-days", "1825", "-notext",
            "-cert", ROOT / "ca.crt", "-keyfile", ROOT / "ca.key", "-passin", "env:PKEY_PASS",
            "-in", INTER / "ca.csr", "-out", cert]
    if run_openssl(args, password = pwd, ca_dir = ROOT, status = "Signing Intermediate CSR..."):
        console.print(f"\n[bold green]Intermediate Certificate Issued: {cert}[/bold green]")
    pause()

def assemble_chain():
    root_crt = ROOT / "ca.crt"
    inter_crt = INTER / "ca.crt"
    chain = INTER / "chain.crt"

    if not root_crt.exists() or not inter_crt.exists():
        console.print("[bold red]Need both the root and intermediate certificates first![/bold red]")
        pause()
        return

    # chain is just intermediate then root in one file
    chain.write_text(inter_crt.read_text() + root_crt.read_text())
    if run_openssl(["verify", "-CAfile", root_crt, inter_crt]):
        console.print(f"\n[bold green]CA Bundle Assembled: {chain}[/bold green]")
    pause()

def root_ca_menu():
    console.clear()
    while True:
        render_menu("Root CA Operations", ROOT_CA_OPTIONS, back_text = "Return to CA Menu")

        match get_choice(len(ROOT_CA_OPTIONS)):
            case "0":
                return
            case "1":
                generate_ca_key(ROOT, "Root CA Private Key")
            case "2":
                reuse_root_key()
            case "3":
                generate_root_cert()

def intermediate_ca_menu():
    console.clear()
    while True:
        render_menu("Intermediate CA Operations", INTERMEDIATE_CA_OPTIONS, back_text = "Return to CA Menu")

        match get_choice(len(INTERMEDIATE_CA_OPTIONS)):
            case "0":
                return
            case "1":
                generate_ca_key(INTER, "Intermediate CA Private Key")
            case "2":
                generate_intermediate_csr()
            case "3":
                sign_intermediate_csr()
            case "4":
                assemble_chain()

def render():
    console.clear()
    while True:
        render_menu("Certificate Authority (CA)", CA_MAIN_OPTIONS)

        match get_choice(len(CA_MAIN_OPTIONS)):
            case "0":
                return
            case "1":
                root_ca_menu()
            case "2":
                intermediate_ca_menu()
