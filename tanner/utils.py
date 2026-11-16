# ui stuff
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table

# openssl stuff
import os
import subprocess
from pathlib import Path

console = Console()

# where everything gets saved
BASE = Path(__file__).resolve().parent
CNF = BASE / "openssl.cnf"
STORE = BASE / "pki_store"
ROOT = STORE / "root"
INTER = STORE / "intermediate"
CUSTOM = STORE / "custom"
CERTS = STORE / "certs"

# certs point here for their CRL, serve it with: python3 -m http.server 8080 -d pki_store
CRL_BASE_URL = "http://127.0.0.1:8080"

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

def run_openssl(args, password = None, ca_dir = ROOT, status = "Running OpenSSL...", env_extra = None):
    env = os.environ.copy()
    env["CA_DIR"] = str(ca_dir)
    env["CRL_URL"] = f"{CRL_BASE_URL}/{Path(ca_dir).name}/ca.crl.der"
    if password is not None:
        env["PKEY_PASS"] = password
    if env_extra:
        env.update(env_extra)

    args = [str(a) for a in args]
    if args[0] == "verify":
        # only trust the CA files we pass in, not the system's root store
        args[1:1] = ["-no-CApath", "-no-CAstore"]

    # openssl wipes the -out file even when it fails, so write to a temp file first
    out = tmp = None
    if "-out" in args:
        i = args.index("-out") + 1
        out = args[i]
        tmp = out + ".tmp"
        args[i] = tmp

    with console.status(f"[bold green]{status}[/bold green]"):
        result = subprocess.run(["openssl"] + args, env = env, capture_output = True, text = True)

    if result.stdout:
        console.print(result.stdout, markup = False, highlight = False)

    if result.returncode != 0:
        console.print("[bold red]OpenSSL Error:[/bold red]")
        console.print(result.stderr, style = "red", markup = False, highlight = False)
        if tmp:
            Path(tmp).unlink(missing_ok = True)
        return False

    if tmp:
        os.replace(tmp, out)
    return True

def ask_password(label = "Enter private key password", confirm = False):
    pwd = Prompt.ask(label, password = True)
    if confirm and pwd != Prompt.ask("Confirm password", password = True):
        console.print("[bold red]Password Mismatch! Try again.[/bold red]")
        return None
    return pwd

def ask_path(label, default = None):
    while True:
        if default:
            answer = Prompt.ask(label, default = str(default))
        else:
            answer = Prompt.ask(label)
        path = Path(answer).expanduser()
        if path.is_file():
            return path
        console.print(f"[bold red]File not found: {path}[/bold red]")

def init_ca_dir(ca_dir):
    (ca_dir / "newcerts").mkdir(parents = True, exist_ok = True)
    (ca_dir / "index.txt").touch()
    if not (ca_dir / "crlnumber").exists():
        (ca_dir / "crlnumber").write_text("1000\n")

def openssl_output(args, password = None):
    env = os.environ.copy()
    if password is not None:
        env["PKEY_PASS"] = password

    result = subprocess.run(["openssl"] + [str(a) for a in args], env = env, capture_output = True, text = True)
    if result.returncode != 0:
        return None
    return result.stdout
