# ui stuff
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table

console = Console()

def render_menu(subtitle: str, options: list[tuple[str, str]], back_text: str = "Return to Main Menu", back_key: str = "0", title: str = "Classical PKI"):
    menu = Table(show_header = False, box = None, padding = (0, 2))
    panel = Panel(menu, title = f"[bold red]{title}[/bold red]", subtitle = f"[dim]{subtitle}[/dim]")

    menu.add_column("Option", style = "bold cyan", justify = "right")
    menu.add_column("Selection", style = "white")

    for key, label in options:
        menu.add_row(f"[{key}]", label)

    if back_text:
        menu.add_row(f"[{back_key}]", back_text, style = "red")

    console.print(panel)

def get_choice(choices_or_max):
    if isinstance(choices_or_max, int):
        choices = [str(x) for x in range(choices_or_max + 1)]
    else:
        choices = [str(x) for x in choices_or_max]

    return Prompt.ask("[maroon]Enter your choice:[/maroon]", choices = choices)

def pause(message: str = "Press Enter to return to the menu..."):
    console.print(f"\n[dim]{message}[/dim]")
    input()
    console.clear()
