# 🔐 local-password-vault

**local-password-vault** is a secure command-line password manager written in **Python 3.14**. It allows you to safely store, generate, and manage your credentials directly within the terminal using encryption. All data is stored strictly locally.

## ✨ Features
The application features a simple and intuitive text-based user interface in Ukrainian, operated via menu navigation:
1. **Strong Password Generation** — Creates random passwords of a specified length using various character types (letters, numbers, symbols).
2. **Add Custom Password** — Saves a new service/login with on-the-fly encryption.
3. **View & Decrypt** — Securely displays stored credentials (integrates with `pyperclip` for seamless clipboard copying).
4. **Delete Password** — Removes obsolete entries from the database.
5. **Change Master Password** — Updates the main access key to your vault.

*Bonus*: Powered by the `difflib` module, the application supports smart search and can recognize correct service names even if you make a typo!

## 🛡 Security & Tech Stack
* **Encryption**: Uses the **AES-128** algorithm in CBC mode (via the symmetric `Fernet` method from the `cryptography` library).
* **Hashing**: The master password is protected using secure hash functions from the `hashlib` module.
* **Hidden Input**: Password entry in the console is fully masked thanks to `getpass`.

## 🚀 How to Run Locally

### 📋 Requirements
You will need **Python 3.14+** installed on your system.

### 🔧 Installation & Setup
1. Clone this repository:
   ```bash
   git clone https://github.com
   cd local-password-vault
   ```
2. Install the required external dependencies:
   ```bash
   pip install cryptography pyperclip
   ```

### 💻 Running the Application
Launch the password manager by running the following command in your terminal:
```bash
python main.py
```

## 🔒 Security Notice
This project is designed for secure local data storage. However, the author is not responsible for any data loss if the master password is forgotten. Always make backups of your encrypted database file.

## 📝 License
This project is distributed under a free Open Source license. You are welcome to use, modify, and distribute this code.
