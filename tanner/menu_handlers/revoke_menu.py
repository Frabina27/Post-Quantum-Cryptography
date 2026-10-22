from utils import console, get_choice, pause, render_menu

REVOKE_MAIN_OPTIONS = [
    ("1", "Revoke a Certificate"),
    ("2", "Generate / Update Certificate Revocation List (CRL)"),
    ("3", "Inspect Active CRL"),
    ("4", "Verify Certificate Against CRL"),
]

def render():
    console.clear()
    while True:
        render_menu("Certificate Revocation & CRL", REVOKE_MAIN_OPTIONS)

        match get_choice(len(REVOKE_MAIN_OPTIONS)):
            case "0":
                return
            case "1":
                console.print("\n[bold green]Selected: Revoke a Certificate[/bold green]")
                pause()
            case "2":
                console.print("\n[bold green]Selected: Generate / Update Certificate Revocation List (CRL)[/bold green]")
                pause()
            case "3":
                console.print("\n[bold green]Selected: Inspect Active CRL[/bold green]")
                pause()
            case "4":
                console.print("\n[bold green]Selected: Verify Certificate Against CRL[/bold green]")
                pause()
