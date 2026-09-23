# ui stuff
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

# utils
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