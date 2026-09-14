import random
import os
import hashlib
from getpass import getpass
from difflib import get_close_matches
from cryptography.fernet import Fernet
import pyperclip

# --- Vault folder next to the script ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
VAULT_DIR = os.path.join(BASE_DIR, "vault")
os.makedirs(VAULT_DIR, exist_ok=True)
PASS_FILE   = os.path.join(VAULT_DIR, "passwords.enc")
KEY_FILE    = os.path.join(VAULT_DIR, "secret.key")
MASTER_FILE = os.path.join(VAULT_DIR, "master.hash")

# --- Character sets ---
low_a = "abcdefghijklmnopqrstuvwxyz"
up_a  = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
n_a   = "0123456789"
sp_a  = "-_=+@%.,:~/"

# ================== GENERATION ==================
def generate_password(length, u=False, n=False, s=False):
    result = [random.choice(low_a)]
    cat = [low_a]
    if u:
        cat.append(up_a)
        result.append(random.choice(up_a))
    if n:
        cat.append(n_a)
        result.append(random.choice(n_a))
    if s:
        cat.append(sp_a)
        result.append(random.choice(sp_a))
    pool = "".join(cat)
    while len(result) < length:
        result.append(random.choice(pool))
    random.shuffle(result)
    return "".join(result)

# ================== ENCRYPTION KEY ==================
def get_key():
    """Reads the encryption key or creates a new one if the file doesn't exist."""
    if not os.path.exists(KEY_FILE):
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as f:
            f.write(key)
        return key
    with open(KEY_FILE, "rb") as f:
        return f.read()

# ================== READ / WRITE PASSWORDS ==================
def load_entries():
    """Returns a list of (name, password) from the encrypted file."""
    if not os.path.exists(PASS_FILE):
        return []
    with open(PASS_FILE, "rb") as f:
        encrypted = f.read()
    if not encrypted:
        return []
    fernet = Fernet(get_key())
    try:
        text = fernet.decrypt(encrypted).decode("utf-8")
    except Exception:
        print("⚠ Failed to decrypt the file (it might be corrupted).")
        return []
    entries = []
    for line in text.split("\n"):
        if "|" in line:
            name, pwd = line.split("|", 1)
            entries.append((name, pwd))
    return entries

def save_entries(entries):
    """Writes the list to the encrypted file."""
    text = "\n".join(f"{n}|{p}" for n, p in entries)
    fernet = Fernet(get_key())
    encrypted = fernet.encrypt(text.encode("utf-8"))
    with open(PASS_FILE, "wb") as f:
        f.write(encrypted)

# ================== MASTER PASSWORD ==================
def setup_master_password():
    """First run — create a master password and save its hash."""
    while True:
        p1 = getpass("Set master password:  ")
        p2 = getpass("Repeat password:  ")
        if p1 != p2:
            print("Passwords do not match, try again.\n")
            continue
        if len(p1) < 4:
            print("Too short (min. 4 characters).\n")
            continue
        h = hashlib.sha256(p1.encode("utf-8")).hexdigest()
        with open(MASTER_FILE, "w") as f:
            f.write(h)
        print("✔ Master password set.\n")
        return

def verify_master_password():
    """Verifies the master password before reading."""
    if not os.path.exists(MASTER_FILE):
        print("Master password is not set.")
        return False
    with open(MASTER_FILE, "r") as f:
        stored = f.read().strip()
    pw = getpass("Enter master password: ")
    h = hashlib.sha256(pw.encode("utf-8")).hexdigest()
    if h == stored:
        return True
    print("✘ Incorrect password.")
    return False

def change_master_password():
    """Changes the master password after verifying the old one."""
    print("\n--- 🔑 Change Master Password ---")
    if not verify_master_password():
        return
    p1 = getpass("New password: ")
    p2 = getpass("Repeat new password: ")
    if p1 != p2:
        print("✘ Passwords do not match.")
        return
    if len(p1) < 4:
        print("✘ Too short (min. 4).")
        return
    new_hash = hashlib.sha256(p1.encode("utf-8")).hexdigest()
    with open(MASTER_FILE, "w") as f:
        f.write(new_hash)
    print("✔ Master password changed.")

# ================== SEARCH ==================
def fuzzy_search(entries, query):
    """Search by partial name. Returns similar entries."""
    names = [e[0] for e in entries]
    # 1) exact substrings (substring in name)
    substr = [n for n in names if query.lower() in n.lower()]
    # 2) similar (fuzzy search)
    similar = get_close_matches(query, names, n=5, cutoff=0.4)
    # combine without duplicates, preserve order
    combined = list(dict.fromkeys(substr + similar))
    return [(n, p) for n, p in entries if n in combined]

# ================== MODES ==================
def create_mode():
    print("\n--- ➕ Create Password ---")
    while True:
        raw_input = input("Password length (or '0' to cancel): ").strip()
        if raw_input == "0" or raw_input.lower() == "q":
            print("Cancelled.")
            return
        try:
            length = int(raw_input)
            if length <= 0:
                print("Length must be greater than 0!")
                continue
            break
        except ValueError:
            print("Enter a number!")
    u = input("Uppercase letters? (y/n): ").strip().lower() == "y"
    n = input("Numbers? (y/n): ").strip().lower() == "y"
    s = input("Special characters? (y/n): ").strip().lower() == "y"
    password = generate_password(length, u=u, n=n, s=s)
    print(f"\n🔑 Your password: {password}\n")
    save = input("Save? (y/n): ").strip().lower()
    if save != "y":
        return
    name = input("Name (e.g., google): ").strip()
    if not name:
        print("Name cannot be empty.")
        return
    entries = load_entries()
    entries.append((name, password))
    save_entries(entries)
    print("✔ Saved.")

def add_mode():
    print("\n--- ➕ Add Existing Password ---")
    while True:
        add_pass = input("Enter password: ")
        if not add_pass:
            print("Password cannot be empty.")
            continue
        break
    password = add_pass
    print(f"\n🔑 Your password: {password}\n")
    save = input("Save? (y/n): ").strip().lower()
    if save != "y":
        return
    name = input("Name (e.g., google): ").strip()
    if not name:
        print("Name cannot be empty.")
        return
    entries = load_entries()
    entries.append((name, password))
    save_entries(entries)
    print("✔ Saved.")

def read_mode():
    if not verify_master_password():
        return
    while True:
        entries = load_entries()
        if not entries:
            print("File is empty.")
            return
        query = input("\nSearch by name (Enter — show all, '0' — menu): ").strip()
        if query == "0":
            break
        results = fuzzy_search(entries, query) if query else entries
        if not results:
            print("Nothing found.")
            continue
        print("\n--- 📖 Found Passwords ---")
        for i, (name, pwd) in enumerate(results, start=1):
            print(f"  {i}. {name}: {pwd}")
        if len(results) == 1:
            copy = input("\nCopy password to clipboard? (y/n): ").strip().lower()
            if copy == "y":
                pyperclip.copy(results[0][1])
                print("✔ Copied. Paste it where needed using Ctrl+V.")

def delete_mode():
    print("\n--- 🗑 Delete Password ---")
    if not verify_master_password():
        return
    while True:
        entries = load_entries()
        if not entries:
            print("File is empty.")
            return
        print("\nEntries:")
        for i, (name, _) in enumerate(entries, start=1):
            print(f"  {i}. {name}")
        try:
            idx = int(input("\nNumber to delete (0 — return to menu): "))
        except ValueError:
            print("Enter a number.")
            continue
        if idx == 0:
            print("Returning to menu.")
            break
        if idx < 1 or idx > len(entries):
            print("Invalid number.")
            continue
        name, _ = entries[idx - 1]
        confirm = input(f"Are you sure you want to delete '{name}'? (y/n): ").strip().lower()
        if confirm == "y":
            entries.pop(idx - 1)
            save_entries(entries)
            print(f"✔ '{name}' deleted.")
        else:
            print("Cancelled.")

# ================== MAIN MENU ==================
def main():
    print("=" * 45)
    print("         🔐 PASSWORD MANAGER")
    print("=" * 45)
    if not os.path.exists(MASTER_FILE):
        print("\nFirst run. Need to create a master password.\n")
        setup_master_password()
    while True:
        print("\n1 — Create password")
        print("2 — Add existing password")
        print("3 — Read passwords")
        print("4 — Delete password")
        print("5 — Change master password")
        print("6 — Exit")
        choice = input("Your choice: ").strip()
        if choice == "1":
            create_mode()
        elif choice == "2":
            add_mode()
        elif choice == "3":
            read_mode()
        elif choice == "4":
            delete_mode()
        elif choice == "5":
            change_master_password()
        elif choice == "6":
            print("Goodbye! 👋")
            return
        else:
            print("Unknown command.")

if __name__ == "__main__":
    main()