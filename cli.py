"""Menu-driven command-line interface (user interaction layer)."""

import getpass
import logging
import sys
import time

from . import __version__, audit, config, generator, strength
from .exceptions import (
    InvalidMasterPasswordError,
    VaultCorruptedError,
    VaultError,
)
from .logger import get_logger
from .validators import validate_int_range, validate_master_password
from .vault import Vault

log = logging.getLogger(__name__)
MASK = "********"


# ---------------------------------------------------------------- input helpers
def read_secret(prompt: str) -> str:
    """Hidden input on a real terminal; plain input when piped (used in demos/tests)."""
    if sys.stdin.isatty():
        return getpass.getpass(prompt)
    return input(prompt)


def read_text(prompt: str) -> str:
    return input(prompt).strip()


def confirm(prompt: str) -> bool:
    return read_text(f"{prompt} [y/N]: ").lower() in ("y", "yes")


def print_table(entries) -> None:
    if not entries:
        print("  (no entries)")
        return
    print(f"  {'ID':<9}{'Site':<24}{'Username':<26}{'Password':<10}")
    print("  " + "-" * 68)
    for e in entries:
        print(f"  {e.id:<9}{e.site[:22]:<24}{e.username[:24]:<26}{MASK:<10}")


# ------------------------------------------------------------------ application
class App:
    def __init__(self, vault: Vault, idle_timeout: int = config.IDLE_TIMEOUT_SECONDS,
                 retry_delay: float = 1.0):
        self.vault = vault
        self.idle_timeout = idle_timeout
        self.retry_delay = retry_delay
        self._last_activity = time.monotonic()
        self._running = True
        # menu choice -> (label, handler): a dictionary keeps the menu data-driven
        self.actions = {
            "1": ("Add a new entry", self.add_entry),
            "2": ("List all entries", self.list_entries),
            "3": ("Search entries", self.search_entries),
            "4": ("View / reveal an entry", self.view_entry),
            "5": ("Update an entry", self.update_entry),
            "6": ("Delete an entry", self.delete_entry),
            "7": ("Generate a password", self.generate),
            "8": ("Check password strength", self.check_password),
            "9": ("Security audit", self.run_audit),
            "10": ("Change master password", self.change_master),
            "11": ("Erase vault (forgot master password)", self.erase_vault),
            "0": ("Lock and exit", self.quit),
        }

    # ------------------------------------------------------------- session flow
    def run(self) -> int:
        print(f"\n=== SecureVault v{__version__} - offline encrypted password manager ===")
        try:
            if not self.authenticate():
                return 1
            self.menu_loop()
        except (KeyboardInterrupt, EOFError):
            print("\nInterrupted - locking vault.")
        finally:
            self.vault.lock()
        return 0

    def authenticate(self) -> bool:
        if not self.vault.exists():
            return self.first_run_setup()
        for attempt in range(1, config.MAX_LOGIN_ATTEMPTS + 1):
            password = read_secret("Master password: ")
            try:
                self.vault.unlock(password)
                print("Vault unlocked.")
                return True
            except InvalidMasterPasswordError:
                left = config.MAX_LOGIN_ATTEMPTS - attempt
                print(f"Incorrect master password. Attempts left: {left}")
                time.sleep(self.retry_delay * attempt)      # growing delay slows guessing
            except VaultCorruptedError as err:
                print(f"Error: {err}")
                return False
        print("Too many failed attempts.")
        print("Forgot the password? Data is encrypted with it, so it cannot be recovered.")
        if read_text("Type ERASE to wipe the vault and start fresh (or Enter to exit): ") == "ERASE":
            self.vault.reset()
            return self.first_run_setup()
        return False

    def first_run_setup(self) -> bool:
        print("No vault found - let's create one.")
        print(f"Master password: min {config.MIN_MASTER_LENGTH} characters, letters and digits.")
        while True:
            first = read_secret("Choose master password: ")
            try:
                validate_master_password(first)
            except VaultError as err:
                print(f"  {err}")
                continue
            if first != read_secret("Confirm master password: "):
                print("  Passwords did not match. Try again.")
                continue
            self.vault.create(first)
            print("Vault created and unlocked.")
            return True

    def menu_loop(self) -> None:
        while self._running and self.vault.is_unlocked:
            if time.monotonic() - self._last_activity > self.idle_timeout:
                print("\nAuto-locked after inactivity.")
                return
            self.show_menu()
            choice = read_text("Choose an option: ")
            self._last_activity = time.monotonic()
            action = self.actions.get(choice)
            if action is None:
                print("Invalid option - enter a number from the menu.")
                continue
            try:
                action[1]()
            except VaultError as err:              # expected, user-facing errors
                print(f"Error: {err}")
            except Exception:                      # unexpected: log details, stay alive
                log.exception("Unexpected error in menu action %s", choice)
                print("Something went wrong. Details were written to the log.")

    def show_menu(self) -> None:
        print("\n--------------- MENU ---------------")
        for key, (label, _) in self.actions.items():
            print(f" {key:>2}. {label}")

    # ----------------------------------------------------------------- actions
    def add_entry(self) -> None:
        site = read_text("Site / app name: ")
        username = read_text("Username / email: ")
        if confirm("Generate a strong password for you?"):
            length = validate_int_range(read_text("Length (8-64) [16]: ") or "16", 8, 64, "Length")
            password = generator.generate_password(length)
            print(f"Generated password: {password}")
        else:
            password = read_secret("Password: ")
            result = strength.check_strength(password)
            print(f"Strength: {result.label} ({result.entropy_bits} bits)")
            if result.score <= 1 and not confirm("This password is weak. Save anyway?"):
                print("Cancelled.")
                return
        notes = read_text("Notes (optional): ")
        entry = self.vault.add_entry(site, username, password, notes)
        print(f"Saved '{entry.site}' with id {entry.id}.")

    def list_entries(self) -> None:
        print_table(self.vault.list_entries())

    def search_entries(self) -> None:
        query = read_text("Search text: ")
        print_table(self.vault.search(query))

    def view_entry(self) -> None:
        entry = self.vault.get_entry(read_text("Entry id: "))
        if not self.vault.verify_master_password(read_secret("Re-enter master password to reveal: ")):
            print("Incorrect master password.")
            return
        print(f"\n  Site     : {entry.site}\n  Username : {entry.username}")
        print(f"  Password : {entry.password}\n  Notes    : {entry.notes or '-'}")
        print(f"  Updated  : {entry.updated_at}  (password age {entry.password_age_days()} days)")

    def update_entry(self) -> None:
        entry = self.vault.get_entry(read_text("Entry id to update: "))
        print("Press Enter to keep the current value.")
        site = read_text(f"Site [{entry.site}]: ") or None
        user = read_text(f"Username [{entry.username}]: ") or None
        pw = read_secret("New password (hidden, Enter to keep): ") or None
        notes = read_text("Notes (Enter to keep): ") or None
        self.vault.update_entry(entry.id, site, user, pw, notes)
        print("Entry updated.")

    def delete_entry(self) -> None:
        entry = self.vault.get_entry(read_text("Entry id to delete: "))
        if confirm(f"Permanently delete '{entry.site}'?"):
            self.vault.delete_entry(entry.id)
            print("Entry deleted.")
        else:
            print("Cancelled.")

    def generate(self) -> None:
        length = validate_int_range(read_text("Length (8-64) [16]: ") or "16", 8, 64, "Length")
        symbols = confirm("Include symbols?")
        clear = confirm("Exclude look-alike characters (I, l, 1, O, 0)?")
        password = generator.generate_password(length, use_symbols=symbols, exclude_ambiguous=clear)
        result = strength.check_strength(password)
        print(f"Generated: {password}")
        print(f"Strength : {result.label} ({result.entropy_bits} bits)")

    def check_password(self) -> None:
        result = strength.check_strength(read_secret("Password to test: "))
        print(f"Score {result.score}/4 - {result.label} - {result.entropy_bits} bits of entropy")
        for tip in result.feedback:
            print(f"  - {tip}")

    def run_audit(self) -> None:
        report = audit.run_audit(self.vault.list_entries())
        print(f"\nVault health: {report.health_score}/100  ({report.total} entries)")
        print(f"  Weak passwords   : {len(report.weak)}")
        for e in report.weak:
            print(f"     - {e.site} ({e.username})")
        print(f"  Reused passwords : {sum(len(g) for g in report.reused)}")
        for group in report.reused:
            print("     - shared by: " + ", ".join(e.site for e in group))
        print(f"  Older than {config.PASSWORD_MAX_AGE_DAYS} days: {len(report.old)}")
        for e in report.old:
            print(f"     - {e.site} ({e.password_age_days()} days)")

    def change_master(self) -> None:
        old = read_secret("Current master password: ")
        new = read_secret("New master password: ")
        if new != read_secret("Confirm new master password: "):
            print("Passwords did not match.")
            return
        self.vault.change_master_password(old, new)
        print("Master password changed. Vault re-encrypted.")

    def erase_vault(self) -> None:
        print("WARNING: this permanently deletes ALL stored passwords.")
        if read_text("Type ERASE to confirm: ") == "ERASE":
            self.vault.reset()
            print("Vault erased. Restart the program to create a new one.")
            self._running = False
        else:
            print("Cancelled.")

    def quit(self) -> None:
        print("Vault locked. Goodbye!")
        self._running = False


def main() -> int:
    get_logger(config.log_path())
    return App(Vault(config.vault_path())).run()
