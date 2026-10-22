from utils import console, get_choice, pause, render_menu

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

def select_algorithm(context: str):
    console.clear()
    while True:
        render_menu(f"{context} - Key Algorithm", ALGO_OPTIONS, back_text = "Return to Previous Menu")

        match get_choice(len(ALGO_OPTIONS)):
            case "0":
                return
            case "1":
                console.print(f"\n[bold green]Selected: RSA 4096 for {context}[/bold green]")
                pause()
                return
            case "2":
                console.print(f"\n[bold green]Selected: RSA 3072 for {context}[/bold green]")
                pause()
                return
            case "3":
                console.print(f"\n[bold green]Selected: RSA 2048 for {context}[/bold green]")
                pause()
                return
            case "4":
                console.print(f"\n[bold green]Selected: ECDSA P-256 for {context}[/bold green]")
                pause()
                return
            case "5":
                console.print(f"\n[bold green]Selected: ECDSA P-384 for {context}[/bold green]")
                pause()
                return
            case "6":
                console.print(f"\n[bold green]Selected: Ed25519 for {context}[/bold green]")
                pause()
                return

def root_ca_menu():
    console.clear()
    while True:
        render_menu("Root CA Operations", ROOT_CA_OPTIONS, back_text = "Return to CA Menu")

        match get_choice(len(ROOT_CA_OPTIONS)):
            case "0":
                return
            case "1":
                select_algorithm("Root CA Private Key")
            case "2":
                console.print("\n[bold green]Selected: Reuse Existing Private Key for Root CA[/bold green]")
                pause()
            case "3":
                console.print("\n[bold green]Selected: Generate Self-Signed Root Certificate[/bold green]")
                pause()

def intermediate_ca_menu():
    console.clear()
    while True:
        render_menu("Intermediate CA Operations", INTERMEDIATE_CA_OPTIONS, back_text = "Return to CA Menu")

        match get_choice(len(INTERMEDIATE_CA_OPTIONS)):
            case "0":
                return
            case "1":
                select_algorithm("Intermediate CA Private Key")
            case "2":
                console.print("\n[bold green]Selected: Generate Intermediate CSR[/bold green]")
                pause()
            case "3":
                console.print("\n[bold green]Selected: Sign Intermediate CSR with Root CA[/bold green]")
                pause()
            case "4":
                console.print("\n[bold green]Selected: Assemble Complete CA Bundle (Chain)[/bold green]")
                pause()

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
