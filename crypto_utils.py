"""Cryptographic helpers.

* Key derivation: scrypt (memory-hard, slows down brute-force guessing).
* Encryption:     Fernet = AES-128-CBC + HMAC-SHA256 (authenticated encryption),
                  so any tampering with the file is detected on decryption.
"""

import base64
import hashlib
import os

from cryptography.fernet import Fernet, InvalidToken

from .exceptions import DecryptionError

SALT_SIZE = 16
DEFAULT_KDF = {"n": 2**15, "r": 8, "p": 1}


def generate_salt() -> bytes:
    """Random salt so identical master passwords give different keys."""
    return os.urandom(SALT_SIZE)


def derive_key(master_password: str, salt: bytes, params: dict | None = None) -> bytes:
    """Stretch the master password into a 32-byte Fernet key."""
    p = params or DEFAULT_KDF
    raw = hashlib.scrypt(
        master_password.encode("utf-8"),
        salt=salt,
        n=int(p["n"]),
        r=int(p["r"]),
        p=int(p["p"]),
        dklen=32,
        maxmem=256 * 1024 * 1024,
    )
    return base64.urlsafe_b64encode(raw)


def encrypt(key: bytes, plaintext: bytes) -> bytes:
    return Fernet(key).encrypt(plaintext)


def decrypt(key: bytes, token: bytes) -> bytes:
    try:
        return Fernet(key).decrypt(token)
    except (InvalidToken, ValueError):
        raise DecryptionError("Decryption failed.") from None
