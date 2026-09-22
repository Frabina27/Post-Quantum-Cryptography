from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt

console = Console()

def main_menu():
    menu =  Table(show_header = False, box = None, padding = (0,2))
    panel = Panel(menu, title = "[bold red]Classical PKI[/bold red]", subtitle = "[dim]Main Menu[/dim]")

    menu.add_column("Option", style = "bold cyan", justify = "right")
    menu.add_column("Selection", style = "white")

    menu.add_row("[1]", "Generate Root CA")

    console.print(panel)

def main():
    console.clear()
    while True:
        main_menu()
        console.print("\n[dim]Press Enter to return to the main menu...[/dim]")
        input()
        console.clear()

if __name__ == "__main__":
    main()