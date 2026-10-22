from utils import console, get_choice, pause, render_menu

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

def select_digest_and_sign():
    console.clear()
    while True:
        render_menu("Sign File - Select Hash Digest", DIGEST_OPTIONS, back_text = "Return to Signing Menu")

        match get_choice(len(DIGEST_OPTIONS)):
            case "0":
                return
            case "1":
                console.print("\n[bold green]Selected: Sign File with SHA-256 digest[/bold green]")
                pause()
                return
            case "2":
                console.print("\n[bold green]Selected: Sign File with SHA-384 digest[/bold green]")
                pause()
                return
            case "3":
                console.print("\n[bold green]Selected: Sign File with SHA-512 digest[/bold green]")
                pause()
                return

def render():
    console.clear()
    while True:
        render_menu("Digital Signatures & Verification", SIGN_MAIN_OPTIONS)

        match get_choice(len(SIGN_MAIN_OPTIONS)):
            case "0":
                return
            case "1":
                select_digest_and_sign()
            case "2":
                console.print("\n[bold green]Selected: Verify File Signature (Public Key)[/bold green]")
                pause()
            case "3":
                console.print("\n[bold green]Selected: Verify Signature and Signer CA Trust Chain[/bold green]")
                pause()
