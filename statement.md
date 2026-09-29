# Project Statement - SecureVault

## Problem Statement
People today hold dozens of online accounts, but human memory cannot manage that many strong, unique passwords. As a result most people reuse the same password across sites, choose short and predictable ones, or keep them in plain-text notes and spreadsheets. A single leaked password then exposes many accounts. Commercial password managers solve this but usually depend on cloud services, accounts and subscriptions, which many students and privacy-conscious users do not want or need.

**SecureVault** is an offline, command-line password manager written in Python that lets a user generate, store, search and audit credentials in a single vault file that is encrypted with a key derived from one master password.

## Scope of the Project
**In scope**
- Creating a local vault protected by a master password
- Storing, viewing, searching, updating and deleting credentials (CRUD)
- Generating cryptographically secure random passwords
- Measuring password strength (entropy, common-password and pattern checks)
- Auditing the vault for weak, reused and old passwords
- Changing the master password (with re-encryption) and erasing the vault
- Logging of security-relevant events (without secrets)
- Automated unit tests

**Out of scope** (listed as future enhancements): cloud sync, browser auto-fill, graphical or mobile interface, multi-user support, clipboard integration.

## Target Users
- Students and beginners who want a safe place for their many account passwords
- Privacy-conscious users who prefer data to stay on their own machine
- Learners of programming / cybersecurity who want a small, readable example of applied cryptography, modular design and testing

## High-Level Features
1. **Vault & credential management** - create vault, unlock, add / list / search / view / update / delete entries, change master password, erase vault
2. **Password generator** - configurable length and character sets, guaranteed character variety, optional removal of look-alike characters
3. **Strength analysis & security audit** - entropy estimate, 0-4 score with feedback, health score for the whole vault (weak, reused, old passwords)
4. **Security by design** - scrypt key derivation, authenticated encryption (Fernet), atomic file writes, re-authentication before revealing a password, retry limits with growing delay, idle auto-lock, log that never contains secrets
