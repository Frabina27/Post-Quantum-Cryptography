# ui stuff
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt

# utils
import os
import subprocess
from utils import get_choice

console = Console()

def main_menu():
    menu =  Table(show_header = False, box = None, padding = (0,2))
    panel = Panel(menu, title = "[bold red]Classical PKI[/bold red]", subtitle = "[dim]Main Menu[/dim]")

    menu.add_column("Option", style = "bold cyan", justify = "right")
    menu.add_column("Selection", style = "white")

    menu.add_row("[1]", "Create New Private Key")
    menu.add_row("[2]", "Reuse Existing Private Key")
    menu.add_row("[0]", "Return to Main Menu")

    console.print(panel)

def generate_key():
    # set key password
    pwd = Prompt.ask("Enter private key password", password = True)
    if pwd != Prompt.ask("Confirm private key password", password = True):
        console.print("[bold red]Password Mismatch! Try again.[/bold red]")
        return
    env = os.environ.copy()
    env["PKEY_PASS"] = pwd

    # generate key
    with console.status("[bold green] Generating Private Key...[bold green]"):
        result = subprocess.run(["openssl", "genpkey", "-aes256", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:4096", "-out", "root.key", "-pass", "env:PKEY_PASS"], env = env, capture_output = True, text = True)

    if result.returncode == 0:
        console.print("[bold green]Key Generated![/bold green]")
    else:
        console.print(f"[bold red]Key Generation Error: {result.stderr}[/bold red]")

def render():
    console.clear()
    while True:
        main_menu()

        match get_choice(2):
            case "0":
                return
            case "1":
                console.print("generate")
            case "2":
                console.print("reuse")

        console.print("\n[dim]Press Enter to return to the main menu...[/dim]")
        input()
        console.clear()