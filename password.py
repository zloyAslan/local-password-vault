import random

import os

import hashlib

from getpass import getpass

from difflib import get_close_matches

from cryptography.fernet import Fernet

import pyperclip


# --- Папка vault поруч зі скриптом ---

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

VAULT_DIR = os.path.join(BASE_DIR, "vault")

os.makedirs(VAULT_DIR, exist_ok=True)


PASS_FILE   = os.path.join(VAULT_DIR, "passwords.enc")

KEY_FILE    = os.path.join(VAULT_DIR, "secret.key")

MASTER_FILE = os.path.join(VAULT_DIR, "master.hash")


# --- Набори символів ---

low_a = "abcdefghijklmnopqrstuvwxyz"

up_a  = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

n_a   = "0123456789"

sp_a  = "-_=+@%.,:~/"



# ================== ГЕНЕРАЦІЯ ==================


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



# ================== КЛЮЧ ШИФРУВАННЯ ==================


def get_key():

    """Читає ключ шифрування або створює новий, якщо файлу немає."""

    if not os.path.exists(KEY_FILE):

        key = Fernet.generate_key()

        with open(KEY_FILE, "wb") as f:

            f.write(key)

        return key

    with open(KEY_FILE, "rb") as f:

        return f.read()



# ================== ЧИТАННЯ / ЗАПИС ПАРОЛІВ ==================


def load_entries():

    """Повертає список (назва, пароль) із зашифрованого файлу."""

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

        print("⚠ Не вдалося розшифрувати файл (можливо, він пошкоджений).")

        return []


    entries = []

    for line in text.split("\n"):

        if "|" in line:

            name, pwd = line.split("|", 1)

            entries.append((name, pwd))

    return entries



def save_entries(entries):

    """Записує список у зашифрований файл."""

    text = "\n".join(f"{n}|{p}" for n, p in entries)

    fernet = Fernet(get_key())

    encrypted = fernet.encrypt(text.encode("utf-8"))


    with open(PASS_FILE, "wb") as f:

        f.write(encrypted)



# ================== МАЙСТЕР-ПАРОЛЬ ==================


def setup_master_password():

    """Перший запуск — створюємо майстер-пароль і зберігаємо його хеш."""

    while True:

        p1 = getpass("Встановіть майстер-пароль: ")

        p2 = getpass("Повторіть пароль: ")

        if p1 != p2:

            print("Паролі не співпадають, спробуйте ще.\n")

            continue

        if len(p1) < 4:

            print("Занадто короткий (мін. 4 символи).\n")

            continue

        h = hashlib.sha256(p1.encode("utf-8")).hexdigest()

        with open(MASTER_FILE, "w") as f:

            f.write(h)

        print("✔ Майстер-пароль встановлено.\n")

        return



def verify_master_password():

    """Перевіряє майстер-пароль перед читанням."""

    if not os.path.exists(MASTER_FILE):

        print("Майстер-пароль не встановлено.")

        return False

    with open(MASTER_FILE, "r") as f:

        stored = f.read().strip()


    pw = getpass("Введіть майстер-пароль: ")

    h = hashlib.sha256(pw.encode("utf-8")).hexdigest()


    if h == stored:

        return True

    print("✘ Невірний пароль.")

    return False


def change_master_password():

    """Змінює майстер-пароль після перевірки старого."""

    print("\n--- 🔑 Зміна майстер-пароля ---")


    if not verify_master_password():

        return


    p1 = getpass("Новий пароль: ")

    p2 = getpass("Повторіть новий пароль: ")


    if p1 != p2:

        print("✘ Паролі не співпадають.")

        return

    if len(p1) < 4:

        print("✘ Занадто короткий (мін. 4).")

        return


    new_hash = hashlib.sha256(p1.encode("utf-8")).hexdigest()

    with open(MASTER_FILE, "w") as f:

        f.write(new_hash)

    print("✔ Майстер-пароль змінено.")



# ================== ПОШУК ==================


def fuzzy_search(entries, query):

    """Пошук за частковою назвою. Повертає схожі записи."""

    names = [e[0] for e in entries]


    # 1) точні підрядки (підрядок у назві)

    substr = [n for n in names if query.lower() in n.lower()]


    # 2) схожі (нечіткий пошук)

    similar = get_close_matches(query, names, n=5, cutoff=0.4)


    # об'єднати без дублів, зберегти порядок

    combined = list(dict.fromkeys(substr + similar))


    return [(n, p) for n, p in entries if n in combined]



# ================== РЕЖИМИ ==================


def create_mode():

    print("\n--- ➕ Створення пароля ---")

    

    while True:

        raw_input = input("Довжина пароля (або '0' для скасування): ").strip()

        if raw_input == "0" or raw_input.lower() == "q":

            print("Скасовано.")

            return


        try:

            length = int(raw_input)

            if length <= 0:

                print("Довжина має бути більше 0!")

                continue

            break

        except ValueError:

            print("Введіть число!")


    u = input("Великі літери? (y/n): ").strip().lower() == "y"

    n = input("Цифри? (y/n): ").strip().lower() == "y"

    s = input("Спецсимволи? (y/n): ").strip().lower() == "y"


    password = generate_password(length, u=u, n=n, s=s)

    print(f"\n🔑 Ваш пароль: {password}\n")


    save = input("Зберегти? (y/n): ").strip().lower()

    if save != "y":

        return


    name = input("Назва (напр. google): ").strip()

    if not name:

        print("Назва не може бути порожньою.")

        return


    entries = load_entries()

    entries.append((name, password))

    save_entries(entries)

    print("✔ Збережено.")


def add_mode():

    print("\n--- ➕ Додавання пароля ---")


    while True:

        add_pass = input("Введіть пароль: ")

        if not add_pass:

            print("Пароль не може бути порожнім.")

            continue

        break


    password = add_pass

    print(f"\n🔑 Ваш пароль: {password}\n")


    save = input("Зберегти? (y/n): ").strip().lower()

    if save != "y":

        return


    name = input("Назва (напр. google): ").strip()

    if not name:

        print("Назва не може бути порожньою.")

        return


    entries = load_entries()

    entries.append((name, password))

    save_entries(entries)

    print("✔ Збережено.")



def read_mode():

    if not verify_master_password():

        return


    while True:

        entries = load_entries()

        if not entries:

            print("Файл порожній.")

            return


        query = input("\nПошук за назвою (Enter — показати всі, '0' — меню): ").strip()

        if query == "0":

            break


        results = fuzzy_search(entries, query) if query else entries


        if not results:

            print("Нічого не знайдено.")

            continue


        print("\n--- 📖 Знайдені паролі ---")

        for i, (name, pwd) in enumerate(results, start=1):

            print(f"  {i}. {name}: {pwd}")


        if len(results) == 1:

            copy = input("\nСкопіювати пароль у буфер? (y/n): ").strip().lower()

            if copy == "y":

                pyperclip.copy(results[0][1])

                print("✔ Скопійовано. Встав де треба через Ctrl+V.")


def delete_mode():

    print("\n--- 🗑 Видалення пароля ---")


    if not verify_master_password():

        return


    while True:

        entries = load_entries()

        if not entries:

            print("Файл порожній.")

            return


        print("\nЗаписи:")

        for i, (name, _) in enumerate(entries, start=1):

            print(f"  {i}. {name}")


        try:

            idx = int(input("\nНомер для видалення (0 — повернутися в меню): "))

        except ValueError:

            print("Введіть число.")

            continue


        if idx == 0:

            print("Вихід у меню.")

            break

        if idx < 1 or idx > len(entries):

            print("Невірний номер.")

            continue


        name, _ = entries[idx - 1]


        confirm = input(f"Точно видалити '{name}'? (y/n): ").strip().lower()

        if confirm == "y":

            entries.pop(idx - 1)

            save_entries(entries)

            print(f"✔ '{name}' видалено.")

        else:

            print("Скасовано.")



# ================== ГОЛОВНЕ МЕНЮ ==================


def main():

    print("=" * 45)

    print("         🔐 МЕНЕДЖЕР ПАРОЛІВ")

    print("=" * 45)


    if not os.path.exists(MASTER_FILE):

        print("\nПерший запуск. Треба створити майстер-пароль.\n")

        setup_master_password()


    while True:

        print("\n1 — Створити пароль")

        print("2 — Додати існуючий пароль")

        print("3 — Прочитати паролі")

        print("4 — Видалити пароль")

        print("5 — Змінити майстер-пароль")

        print("6 — Вихід")

        choice = input("Ваш вибір: ").strip()


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

            print("Бувай! 👋")

            return

        else:

            print("Невідома команда.")



if __name__ == "__main__":

    main()

