from utils import console, get_choice, pause, render_menu

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
    while True:
        render_menu(f"{cert_type} - Select Signing CA", SIGNING_CA_OPTIONS, back_text = "Return to Certificate Menu")

        match get_choice(len(SIGNING_CA_OPTIONS)):
            case "0":
                return
            case "1":
                console.print(f"\n[bold green]Selected: {cert_type} signed by Intermediate CA[/bold green]")
                pause()
                return
            case "2":
                console.print(f"\n[bold green]Selected: {cert_type} signed by Root CA[/bold green]")
                pause()
                return
            case "3":
                console.print(f"\n[bold green]Selected: {cert_type} signed by Custom CA[/bold green]")
                pause()
                return

def render():
    console.clear()
    while True:
        render_menu("Issue End-Entity Certificates", CERT_MAIN_OPTIONS)

        match get_choice(len(CERT_MAIN_OPTIONS)):
            case "0":
                return
            case "1":
                select_signing_ca("Server Certificate (TLS)")
            case "2":
                select_signing_ca("Client Certificate (mTLS)")
            case "3":
                select_signing_ca("Code-Signing Certificate")
            case "4":
                console.print("\n[bold green]Selected: Issue Standalone Self-Signed Certificate[/bold green]")
                pause()
            case "5":
                select_signing_ca("Existing CSR Signing")
