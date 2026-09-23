from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()

def menu():
    menu =  Table(show_header = False, box = None, padding = (0,2))
    panel = Panel(menu, title = "[bold red]Classical PKI[/bold red]", subtitle = "[dim]Main Menu[/dim]")

    menu.add_column("Option", style = "bold cyan", justify = "right")
    menu.add_column("Selection", style = "white")

    menu.add_row("[1]", "Create New Private Key")
    menu.add_row("[2]", "Reuse Existing Private Key")

    console.print(panel)

# create new private key

# reuse existing private key