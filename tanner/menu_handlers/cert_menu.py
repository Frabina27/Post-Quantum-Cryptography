from rich.prompt import Prompt

from menu_handlers.ca_menu import ok_to_overwrite, select_algorithm
from utils import CERTS, CNF, CUSTOM, INTER, ROOT, ask_password, ask_path, console, get_choice, init_ca_dir, pause, render_menu, run_openssl

CERT_MAIN_OPTIONS = [
    ("1", "Issue Server Certificate (TLS with SANs)"),
    ("2", "Issue Client Certificate (mTLS / User Identity)"),
    ("3", "Issue Code-Signing Certificate"),
    ("4", "Issue Standalone Self-Signed Certificate"),
    ("5", "Sign Existing CSR with CA"),
]

SIGNING_CA_OPTIONS = [
    ("1", "Sign with Intermediate CA (Recommended)"),
    ("2", "Sign with Root CA"),
    ("3", "Sign with Custom CA"),
]

def select_signing_ca(cert_type: str):
    console.clear()
    render_menu(f"{cert_type} - Select Signing CA", SIGNING_CA_OPTIONS, back_text = "Return to Previous Menu")

    # returns (database dir, ca cert, ca key) or None if they picked 0
    match get_choice(len(SIGNING_CA_OPTIONS)):
        case "1":
            return INTER, INTER / "ca.crt", INTER / "ca.key"
        case "2":
            return ROOT, ROOT / "ca.crt", ROOT / "ca.key"
        case "3":
            ca_crt = ask_path("Path to CA certificate")
            ca_key = ask_path("Path to CA private key")
            return CUSTOM, ca_crt, ca_key
    return None

def san_list(text):
    # "a.com, IP:10.0.0.1" -> "DNS:a.com,IP:10.0.0.1"
    sans = []
    for name in text.split(","):
        name = name.strip()
        if not name:
            continue
        if ":" not in name:
            name = "DNS:" + name
        sans.append(name)
    return ",".join(sans)

def clean_up(*files):
    # don't leave half-made keys and csrs around when a step fails
    for f in files:
        f.unlink(missing_ok = True)
    console.print("[dim]Removed the files created for this certificate.[/dim]")

def check_ca(ca, pwd):
    # make sure the ca cert and key are usable before we generate anything
    ca_dir, ca_crt, ca_key = ca
    if not ca_crt.exists():
        console.print(f"[bold red]CA certificate not found: {ca_crt}[/bold red]")
        return False
    return run_openssl(["pkey", "-in", ca_key, "-passin", "env:PKEY_PASS", "-noout"], password = pwd, status = "Checking CA Key...")

def sign_csr(ca, csr, cert, extensions, pwd):
    ca_dir, ca_crt, ca_key = ca
    init_ca_dir(ca_dir)
    args = ["ca", "-batch", "-config", CNF, "-extensions", extensions, "-days", "365", "-notext",
            "-cert", ca_crt, "-keyfile", ca_key, "-passin", "env:PKEY_PASS",
            "-in", csr, "-out", cert]
    return run_openssl(args, password = pwd, ca_dir = ca_dir, status = "Signing Certificate...")

def issue_cert(cert_type: str, extensions: str, ask_sans = False):
    ca = select_signing_ca(cert_type)
    if ca is None:
        return
    algo = select_algorithm(cert_type)
    if algo is None:
        return

    cn = Prompt.ask("Common Name (also used as the file name)")
    sans = ""
    if ask_sans:
        sans = san_list(Prompt.ask("Subject Alt Names, comma separated", default = cn))

    key = CERTS / f"{cn}.key"
    csr = CERTS / f"{cn}.csr"
    cert = CERTS / f"{cn}.crt"
    if not ok_to_overwrite(cert):
        pause()
        return

    pwd = ask_password("Signing CA key password")
    if not check_ca(ca, pwd):
        pause()
        return

    # end-entity key, not encrypted
    CERTS.mkdir(parents = True, exist_ok = True)
    if not run_openssl(["genpkey", *algo, "-out", key], status = "Generating Private Key..."):
        pause()
        return

    # csr
    args = ["req", "-new", "-config", CNF, "-key", key, "-subj", f"/CN={cn}", "-out", csr]
    if sans:
        args += ["-addext", f"subjectAltName={sans}"]
    if not run_openssl(args, status = "Generating CSR..."):
        clean_up(key)
        pause()
        return

    # have the ca sign it
    if sign_csr(ca, csr, cert, extensions, pwd):
        console.print(f"\n[bold green]{cert_type} Issued: {cert}[/bold green]")
        console.print(f"[green]Private Key: {key}[/green]")
    else:
        clean_up(key, csr)
    pause()

def issue_self_signed():
    algo = select_algorithm("Standalone Self-Signed Certificate")
    if algo is None:
        return

    cn = Prompt.ask("Common Name (also used as the file name)")
    sans = san_list(Prompt.ask("Subject Alt Names, comma separated", default = cn))
    key = CERTS / f"{cn}.key"
    cert = CERTS / f"{cn}.crt"
    if not ok_to_overwrite(cert):
        pause()
        return

    CERTS.mkdir(parents = True, exist_ok = True)
    if not run_openssl(["genpkey", *algo, "-out", key], status = "Generating Private Key..."):
        pause()
        return

    # no ca, the key signs its own cert
    args = ["req", "-x509", "-new", "-config", CNF, "-extensions", "server_cert",
            "-key", key, "-subj", f"/CN={cn}", "-days", "365",
            "-addext", f"subjectAltName={sans}", "-out", cert]
    if run_openssl(args, status = "Generating Self-Signed Certificate..."):
        console.print(f"\n[bold green]Self-Signed Certificate Generated: {cert}[/bold green]")
        console.print(f"[green]Private Key: {key}[/green]")
    else:
        clean_up(key)
    pause()

def sign_existing_csr():
    ca = select_signing_ca("Existing CSR Signing")
    if ca is None:
        return

    csr = ask_path("Path to CSR")
    name = Prompt.ask("Output certificate name", default = csr.stem)
    cert = CERTS / f"{name}.crt"
    if not ok_to_overwrite(cert):
        pause()
        return

    pwd = ask_password("Signing CA key password")
    CERTS.mkdir(parents = True, exist_ok = True)
    if sign_csr(ca, csr, cert, "usr_cert", pwd):
        console.print(f"\n[bold green]Certificate Issued: {cert}[/bold green]")
    pause()

def render():
    console.clear()
    while True:
        render_menu("Issue End-Entity Certificates", CERT_MAIN_OPTIONS)

        match get_choice(len(CERT_MAIN_OPTIONS)):
            case "0":
                return
            case "1":
                issue_cert("Server Certificate (TLS)", "server_cert", ask_sans = True)
            case "2":
                issue_cert("Client Certificate (mTLS)", "client_cert")
            case "3":
                issue_cert("Code-Signing Certificate", "code_sign")
            case "4":
                issue_self_signed()
            case "5":
                sign_existing_csr()
