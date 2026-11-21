from menu_handlers.cert_menu import select_signing_ca
from utils import CNF, INTER, ROOT, ask_password, ask_path, console, get_choice, init_ca_dir, pause, render_menu, run_openssl

REVOKE_MAIN_OPTIONS = [
    ("1", "Revoke a Certificate"),
    ("2", "Generate / Update Certificate Revocation List (CRL)"),
    ("3", "Inspect Active CRL"),
    ("4", "Verify Certificate Against CRL"),
]

def revoke_cert():
    ca = select_signing_ca("Revoke - Select Issuing CA")
    if ca is None:
        return
    ca_dir, ca_crt, ca_key = ca

    cert = ask_path("Path to certificate to revoke")

    if not run_openssl(["verify", "-partial_chain", "-CAfile", ca_crt, cert], status = "Checking Issuer..."):
        console.print("[bold red]That certificate wasn't issued by this CA.[/bold red]")
        pause()
        return

    pwd = ask_password("CA key password")
    init_ca_dir(ca_dir)
    args = ["ca", "-config", CNF, "-revoke", cert, "-cert", ca_crt, "-keyfile", ca_key, "-passin", "env:PKEY_PASS"]
    if run_openssl(args, password = pwd, ca_dir = ca_dir, status = "Revoking Certificate..."):
        console.print(f"\n[bold green]Certificate Revoked: {cert}[/bold green]")
        console.print("[green]Generate a new CRL to publish the revocation.[/green]")
    pause()

def generate_crl():
    ca = select_signing_ca("CRL - Select CA")
    if ca is None:
        return
    ca_dir, ca_crt, ca_key = ca

    pwd = ask_password("CA key password")
    crl = ca_dir / "ca.crl"
    init_ca_dir(ca_dir)
    args = ["ca", "-config", CNF, "-gencrl", "-cert", ca_crt, "-keyfile", ca_key, "-passin", "env:PKEY_PASS", "-out", crl]
    if not run_openssl(args, password = pwd, ca_dir = ca_dir, status = "Generating CRL..."):
        pause()
        return

    # DER copy is what gets published at the certs' CRL distribution point
    if run_openssl(["crl", "-in", crl, "-outform", "DER", "-out", ca_dir / "ca.crl.der"]):
        console.print(f"\n[bold green]CRL Generated: {crl}[/bold green]")
        console.print(f"[green]Publish: {ca_dir / 'ca.crl.der'}[/green]")
    pause()

def inspect_crl():
    ca = select_signing_ca("Inspect CRL - Select CA")
    if ca is None:
        return

    crl = ca[0] / "ca.crl"
    if not crl.exists():
        console.print(f"[bold red]No CRL yet: {crl}[/bold red]")
        pause()
        return

    run_openssl(["crl", "-in", crl, "-noout", "-text"])
    pause()

def verify_against_crl():
    ca = select_signing_ca("Verify Against CRL - Select Issuing CA")
    if ca is None:
        return
    ca_dir, ca_crt, ca_key = ca

    crl = ca_dir / "ca.crl"
    if not crl.exists():
        console.print(f"[bold red]No CRL yet: {crl}[/bold red]")
        pause()
        return

    cert = ask_path("Path to certificate")

    # intermediate needs the root to complete the chain
    if ca_dir == INTER:
        if (ROOT / "ca.crl").exists():
            args = ["verify", "-crl_check_all", "-CAfile", ROOT / "ca.crt", "-untrusted", ca_crt, "-CRLfile", ROOT / "ca.crl"]
        else:
            args = ["verify", "-crl_check", "-CAfile", ROOT / "ca.crt", "-untrusted", ca_crt]
    else:
        args = ["verify", "-crl_check", "-CAfile", ca_crt]

    if run_openssl(args + ["-CRLfile", crl, cert], status = "Checking CRL..."):
        console.print("[bold green]Certificate is valid and not revoked[/bold green]")
    else:
        console.print("[bold red]Certificate failed the CRL check (see the reason above)[/bold red]")
    pause()

def render():
    console.clear()
    while True:
        render_menu("Certificate Revocation & CRL", REVOKE_MAIN_OPTIONS)

        match get_choice(len(REVOKE_MAIN_OPTIONS)):
            case "0":
                return
            case "1":
                revoke_cert()
            case "2":
                generate_crl()
            case "3":
                inspect_crl()
            case "4":
                verify_against_crl()
