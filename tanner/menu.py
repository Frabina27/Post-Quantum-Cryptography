from menu_handlers import ca_menu, cert_menu, inspect_menu, revoke_menu, sign_menu
from utils import console, get_choice, render_menu

MAIN_MENU_OPTIONS = [
    ("1", "Certificate Authority (CA) Management"),
    ("2", "Issue End-Entity Certificates"),
    ("3", "Certificate Revocation & CRL"),
    ("4", "Digital Signatures & Verification"),
    ("5", "Inspect & Validate"),
]

def render():
    console.clear()
    while True:
        render_menu("Main Menu", MAIN_MENU_OPTIONS, back_text = "Exit")

        match get_choice(len(MAIN_MENU_OPTIONS)):
            case "0":
                console.clear()
                exit(0)
            case "1":
                ca_menu.render()
            case "2":
                cert_menu.render()
            case "3":
                revoke_menu.render()
            case "4":
                sign_menu.render()
            case "5":
                inspect_menu.render()

        console.clear()