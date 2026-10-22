from utils import console, get_choice, pause, render_menu

INSPECT_MAIN_OPTIONS = [
    ("1", "Inspect X.509 Certificate (.crt / .pem)"),
    ("2", "Inspect Certificate Signing Request (.csr)"),
    ("3", "Inspect Private or Public Key (.key / .pub)"),
    ("4", "Verify Certificate Trust Chain"),
]

def render():
    console.clear()
    while True:
        render_menu("Inspect & Validate", INSPECT_MAIN_OPTIONS)

        match get_choice(len(INSPECT_MAIN_OPTIONS)):
            case "0":
                return
            case "1":
                console.print("\n[bold green]Selected: Inspect X.509 Certificate[/bold green]")
                pause()
            case "2":
                console.print("\n[bold green]Selected: Inspect Certificate Signing Request (CSR)[/bold green]")
                pause()
            case "3":
                console.print("\n[bold green]Selected: Inspect Private or Public Key[/bold green]")
                pause()
            case "4":
                console.print("\n[bold green]Selected: Verify Certificate Trust Chain[/bold green]")
                pause()
