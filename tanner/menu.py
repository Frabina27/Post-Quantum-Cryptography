# ui stuff
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt

# choice hanglers
from menu_handlers import menu_1

console = Console()

def main_menu(): # build main menu
    menu =  Table(show_header = False, box = None, padding = (0,2))
    panel = Panel(menu, title = "[bold red]Classical PKI[/bold red]", subtitle = "[dim]Main Menu[/dim]")

    menu.add_column("Option", style = "bold cyan", justify = "right")
    menu.add_column("Selection", style = "white")

    menu.add_row("[1]", "Generate Root Certificate")

    console.print(panel)

def render(): # render main menu
    console.clear()
    while True:
        main_menu()

        choice = Prompt.ask("[maroon]Enter your choice:[/maroon]", choices = ["1"])

        match choice:
            case "1":
                menu_1.menu()


        console.print("\n[dim]Press Enter to return to the main menu...[/dim]")
        input()
        console.clear()