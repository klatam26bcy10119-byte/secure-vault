"""Encrypted vault: storage plus create / read / update / delete of entries.

File format (JSON on disk)::

    {"version": 1, "kdf": {"n":..,"r":..,"p":..}, "salt": "<b64>", "data": "<Fernet token>"}

Only ``data`` holds secrets and it is fully encrypted. The master password itself
is never stored; a wrong password simply fails authenticated decryption.
"""

import base64
import hmac
import json
import logging
import os
from pathlib import Path

from . import crypto_utils
from .exceptions import (
    DecryptionError,
    EntryNotFoundError,
    InvalidMasterPasswordError,
    VaultCorruptedError,
    VaultExistsError,
    VaultLockedError,
    VaultNotFoundError,
)
from .models import Entry, _now
from .validators import validate_master_password, validate_required

log = logging.getLogger(__name__)
FORMAT_VERSION = 1
SORT_FIELDS = ("site", "username", "updated_at")


class Vault:
    def __init__(self, path, kdf_params: dict | None = None):
        self.path = Path(path)
        self._kdf = dict(kdf_params or crypto_utils.DEFAULT_KDF)
        self._entries: dict[str, Entry] = {}   # id -> Entry (hash map: O(1) lookup)
        self._key: bytes | None = None
        self._salt: bytes | None = None

    # ---- state -----------------------------------------------------------
    @property
    def is_unlocked(self) -> bool:
        return self._key is not None

    def exists(self) -> bool:
        return self.path.is_file()

    def _require_unlocked(self) -> None:
        if not self.is_unlocked:
            raise VaultLockedError("Vault is locked. Unlock it first.")

    # ---- lifecycle -------------------------------------------------------
    def create(self, master_password: str) -> None:
        """Create a brand-new empty vault protected by ``master_password``."""
        if self.exists():
            raise VaultExistsError("A vault already exists at this location.")
        validate_master_password(master_password)
        self._salt = crypto_utils.generate_salt()
        self._key = crypto_utils.derive_key(master_password, self._salt, self._kdf)
        self._entries = {}
        self._save()
        log.info("Vault created")

    def unlock(self, master_password: str) -> None:
        """Decrypt the vault into memory. Raises on wrong password/corruption."""
        if not self.exists():
            raise VaultNotFoundError("No vault found. Create one first.")
        doc = self._read_file()
        try:
            salt = base64.b64decode(doc["salt"])
            kdf = doc["kdf"]
            token = doc["data"].encode("ascii")
            key = crypto_utils.derive_key(master_password, salt, kdf)
        except (KeyError, ValueError, TypeError):
            raise VaultCorruptedError("Vault file is damaged.") from None
        try:
            plaintext = crypto_utils.decrypt(key, token)
        except DecryptionError:
            log.warning("Unlock failed: wrong master password or tampered file")
            raise InvalidMasterPasswordError(
                "Wrong master password (or the vault file was modified)."
            ) from None
        try:
            payload = json.loads(plaintext.decode("utf-8"))
            entries = [Entry.from_dict(e) for e in payload["entries"]]
        except (ValueError, KeyError, TypeError):
            raise VaultCorruptedError("Vault contents are damaged.") from None
        self._salt, self._kdf, self._key = salt, dict(kdf), key
        self._entries = {e.id: e for e in entries}
        log.info("Vault unlocked (%d entries)", len(self._entries))

    def lock(self) -> None:
        """Forget the key and decrypted data held in memory."""
        self._key = None
        self._salt = None
        self._entries = {}

    def verify_master_password(self, master_password: str) -> bool:
        """Re-check the master password (used before revealing a secret)."""
        self._require_unlocked()
        candidate = crypto_utils.derive_key(master_password, self._salt, self._kdf)
        return hmac.compare_digest(candidate, self._key)   # constant-time compare

    def change_master_password(self, old: str, new: str) -> None:
        """Re-encrypt the vault under a new master password (needs the old one)."""
        self._require_unlocked()
        if not self.verify_master_password(old):
            raise InvalidMasterPasswordError("Current master password is incorrect.")
        validate_master_password(new)
        self._salt = crypto_utils.generate_salt()          # fresh salt every change
        self._key = crypto_utils.derive_key(new, self._salt, self._kdf)
        self._save()
        log.info("Master password changed")

    def reset(self) -> None:
        """Permanently erase the vault (the only 'recovery' for a lost password)."""
        self.lock()
        if self.exists():
            self.path.unlink()
        log.warning("Vault reset: all data erased")

    # ---- CRUD ------------------------------------------------------------
    def add_entry(self, site: str, username: str, password: str, notes: str = "") -> Entry:
        self._require_unlocked()
        entry = Entry(
            site=validate_required(site, "Site"),
            username=validate_required(username, "Username"),
            password=validate_required(password, "Password", max_len=256),
            notes=(notes or "").strip()[:500],
        )
        self._entries[entry.id] = entry
        self._save()
        log.info("Entry added: %s (%s)", entry.site, entry.id)
        return entry

    def get_entry(self, entry_id: str) -> Entry:
        self._require_unlocked()
        try:
            return self._entries[entry_id.strip()]
        except KeyError:
            raise EntryNotFoundError(f"No entry with id '{entry_id}'.") from None

    def update_entry(self, entry_id: str, site=None, username=None, password=None, notes=None) -> Entry:
        entry = self.get_entry(entry_id)
        if site is not None:
            entry.site = validate_required(site, "Site")
        if username is not None:
            entry.username = validate_required(username, "Username")
        if password is not None:
            new_pw = validate_required(password, "Password", max_len=256)
            if new_pw != entry.password:
                entry.password = new_pw
                entry.password_changed_at = _now()
        if notes is not None:
            entry.notes = notes.strip()[:500]
        entry.updated_at = _now()
        self._save()
        log.info("Entry updated: %s (%s)", entry.site, entry.id)
        return entry

    def delete_entry(self, entry_id: str) -> None:
        entry = self.get_entry(entry_id)
        del self._entries[entry.id]
        self._save()
        log.info("Entry deleted: %s (%s)", entry.site, entry.id)

    def list_entries(self, sort_by: str = "site") -> list[Entry]:
        self._require_unlocked()
        if sort_by not in SORT_FIELDS:
            sort_by = "site"
        return sorted(self._entries.values(), key=lambda e: getattr(e, sort_by).lower())

    def search(self, query: str) -> list[Entry]:
        """Case-insensitive substring search over site, username and notes."""
        self._require_unlocked()
        q = query.strip().lower()
        if not q:
            return []
        return [
            e for e in self.list_entries()
            if q in e.site.lower() or q in e.username.lower() or q in e.notes.lower()
        ]

    # ---- persistence -----------------------------------------------------
    def _read_file(self) -> dict:
        try:
            doc = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            raise VaultCorruptedError("Vault file could not be read.") from None
        if not isinstance(doc, dict) or doc.get("version") != FORMAT_VERSION:
            raise VaultCorruptedError("Unsupported or damaged vault file.")
        return doc

    def _save(self) -> None:
        """Encrypt and write atomically (temp file + rename) so a crash can't corrupt it."""
        payload = json.dumps({"entries": [e.to_dict() for e in self._entries.values()]})
        token = crypto_utils.encrypt(self._key, payload.encode("utf-8"))
        doc = {
            "version": FORMAT_VERSION,
            "kdf": self._kdf,
            "salt": base64.b64encode(self._salt).decode("ascii"),
            "data": token.decode("ascii"),
        }
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(doc), encoding="utf-8")
        try:
            os.chmod(tmp, 0o600)          # owner-only permissions (ignored on Windows)
        except OSError:
            pass
        os.replace(tmp, self.path)
