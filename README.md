# SecureVault - Offline Encrypted Password Manager

> Course project for **CSE1021 - Introduction to Problem Solving and Programming** (VITyarthi *Build Your Own Project*)
> **Author:** Katam Lakshman Reddy  |  **Reg. No.:** 26BCY10119

## Overview
SecureVault is a menu-driven command-line application written in Python. It stores website credentials in one **encrypted vault file** on your own computer. Everything is unlocked with a single master password, which is never saved anywhere. Besides storing passwords it can **generate** strong ones, **rate** their strength and **audit** the whole vault for weak, reused and old passwords.

The project applies core problem-solving concepts: breaking a problem into modules, choosing suitable data structures (dictionaries, lists, sets), designing algorithms (search, sorting, entropy calculation, pattern detection), input validation, exception handling and testing.

## Features
| Module | What it does |
|---|---|
| **1. Vault & authentication** | Create vault on first run, unlock with master password, add / list / search / view / update / delete entries, change master password, erase vault |
| **2. Password generator** | Secure random passwords (8-64 chars), choose symbols, exclude look-alike characters, guaranteed mix of character types |
| **3. Strength & security audit** | Entropy-based score (0-4) with advice; audit for weak, reused and >90-day-old passwords; vault health score |

Security features: scrypt key derivation - Fernet (AES + HMAC) authenticated encryption - tamper detection - atomic saves - owner-only file permissions - hidden password input - re-enter master password to reveal a password - 3 login attempts with growing delay - idle auto-lock (5 min) - event log without secrets.

## Technologies / Tools Used
- Python 3.10+ (standard library: `hashlib`, `secrets`, `json`, `logging`, `dataclasses`, `unittest`)
- [`cryptography`](https://pypi.org/project/cryptography/) library (Fernet)
- Git and GitHub for version control

## Project Structure
```
securevault/
|-- main.py                  # entry point
|-- requirements.txt
|-- statement.md             # problem statement, scope, users, features
|-- securevault/
|   |-- cli.py               # menu-driven user interface
|   |-- vault.py             # encrypted storage + CRUD
|   |-- crypto_utils.py      # scrypt + Fernet helpers
|   |-- generator.py         # secure password generator
|   |-- strength.py          # entropy / pattern based strength checker
|   |-- audit.py             # weak / reused / old password audit
|   |-- models.py            # Entry dataclass
|   |-- validators.py        # input validation
|   |-- exceptions.py        # custom exception hierarchy
|   |-- config.py            # paths and limits
|   `-- logger.py            # rotating log file
|-- tests/                   # 39 unit tests
`-- docs/                    # diagrams and screenshots
```

## Installation & Running
```bash
# 1. get the code
git clone <your-repo-url>
cd securevault

# 2. (optional) virtual environment
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate

# 3. install dependency
pip install -r requirements.txt

# 4. run
python main.py
```
On first run you are asked to create a master password (min. 10 characters, letters and digits). The vault is stored in `~/.securevault/vault.json`; set the environment variable `SECUREVAULT_HOME` to use another folder.

### Using the program
Choose a number from the menu: `1` add entry - `2` list - `3` search - `4` reveal (asks master password again) - `5` update - `6` delete - `7` generate password - `8` check strength - `9` security audit - `10` change master password - `11` erase vault - `0` lock and exit.

**Forgot the master password?** The data is encrypted with it, so it cannot be recovered by design. After three failed attempts (or via menu option 11) you can type `ERASE` to wipe the vault and start a new one.

## Testing
```bash
python -m unittest discover -s tests -t . -v
```
39 tests cover encryption, the vault (create, unlock, CRUD, tamper detection, master-password change, reset), the generator, the strength checker, the audit and input validation. Test runs use cheap scrypt settings so they finish in about a tenth of a second.

## Screenshots
| | |
|---|---|
| ![setup](docs/screenshots/s1_setup_and_add_entries.png) | ![audit](docs/screenshots/s3_generate_strength_audit.png) |
| ![reveal](docs/screenshots/s2_list_search_reveal.png) | ![tests](docs/screenshots/s6_unit_tests.png) |

Design diagrams (architecture, workflow, use case, sequence, class, ER) are in `docs/diagrams/`.

## Limitations & Future Work
Clipboard copy with auto-clear, GUI / mobile front-end, encrypted backup export, breached-password (k-anonymity) check, two-factor unlock.

## Licence
Educational project - free to read and learn from.
