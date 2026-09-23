# ui stuff
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

# choice hanglers
from menu_handlers import menu_1

# utils
from utils import get_choice

console = Console()

def main_menu(): # build main menu
    menu =  Table(show_header = False, box = None, padding = (0,2))
    panel = Panel(menu, title = "[bold red]Classical PKI[/bold red]", subtitle = "[dim]Main Menu[/dim]")

    menu.add_column("Option", style = "bold cyan", justify = "right")
    menu.add_column("Selection", style = "white")

    menu.add_row("[1]", "Generate Root Certificate")

    menu.add_row("[0]", "Exit", style="red")

    console.print(panel)

def render(): # render main menu
    console.clear()
    while True:
        main_menu()

        match get_choice(1):
            case "0":
                exit(0)
            case "1":
                menu_1.render()

        console.print("\n[dim]Press Enter to return to the main menu...[/dim]")
        input()
        console.clear()