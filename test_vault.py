import json
import tempfile
import unittest
from pathlib import Path

from securevault.exceptions import (
    EntryNotFoundError, InvalidMasterPasswordError, ValidationError,
    VaultCorruptedError, VaultExistsError, VaultLockedError, VaultNotFoundError,
)
from securevault.vault import Vault
from tests.helpers import FAST_KDF, MASTER


class VaultTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "vault.json"
        self.vault = Vault(self.path, FAST_KDF)
        self.vault.create(MASTER)

    def tearDown(self):
        self.tmp.cleanup()

    def reopen(self, password=MASTER):
        v = Vault(self.path, FAST_KDF)
        v.unlock(password)
        return v

    # --- lifecycle
    def test_create_twice_fails(self):
        with self.assertRaises(VaultExistsError):
            Vault(self.path, FAST_KDF).create(MASTER)

    def test_weak_master_rejected(self):
        with self.assertRaises(ValidationError):
            Vault(Path(self.tmp.name) / "x.json", FAST_KDF).create("short1")

    def test_unlock_missing_vault(self):
        with self.assertRaises(VaultNotFoundError):
            Vault(Path(self.tmp.name) / "none.json", FAST_KDF).unlock(MASTER)

    def test_wrong_password_rejected(self):
        with self.assertRaises(InvalidMasterPasswordError):
            self.reopen("Wrong-Pass123")

    def test_locked_vault_blocks_access(self):
        self.vault.lock()
        with self.assertRaises(VaultLockedError):
            self.vault.list_entries()

    # --- CRUD
    def test_add_and_persist(self):
        e = self.vault.add_entry("GitHub", "lakshman", "S3cure!Pass#1", "work")
        again = self.reopen()
        self.assertEqual(again.get_entry(e.id).password, "S3cure!Pass#1")

    def test_file_contains_no_plaintext(self):
        self.vault.add_entry("BankSite", "myuser", "SuperSecretPW!9")
        raw = self.path.read_text()
        for secret in ("BankSite", "myuser", "SuperSecretPW!9"):
            self.assertNotIn(secret, raw)

    def test_update_entry_tracks_password_change(self):
        e = self.vault.add_entry("Site", "u", "OldPass#123")
        before = e.password_changed_at
        self.vault.update_entry(e.id, password="NewPass#456")
        self.assertEqual(self.vault.get_entry(e.id).password, "NewPass#456")
        self.assertGreaterEqual(self.vault.get_entry(e.id).password_changed_at, before)

    def test_delete_entry(self):
        e = self.vault.add_entry("Site", "u", "Pass#12345")
        self.vault.delete_entry(e.id)
        with self.assertRaises(EntryNotFoundError):
            self.vault.get_entry(e.id)

    def test_validation_errors(self):
        with self.assertRaises(ValidationError):
            self.vault.add_entry("", "u", "p")
        with self.assertRaises(ValidationError):
            self.vault.add_entry("s", "u", "  ")

    def test_list_sorted_and_search(self):
        self.vault.add_entry("zoom", "a@x.com", "Pass#12345")
        self.vault.add_entry("Amazon", "b@x.com", "Pass#12346", "shopping")
        self.assertEqual([e.site for e in self.vault.list_entries()], ["Amazon", "zoom"])
        self.assertEqual([e.site for e in self.vault.search("SHOP")], ["Amazon"])
        self.assertEqual(self.vault.search("   "), [])

    # --- master password / tamper / reset
    def test_change_master_password(self):
        e = self.vault.add_entry("Site", "u", "Pass#12345")
        self.vault.change_master_password(MASTER, "Brand-New-Pass77")
        with self.assertRaises(InvalidMasterPasswordError):
            self.reopen(MASTER)
        self.assertEqual(self.reopen("Brand-New-Pass77").get_entry(e.id).site, "Site")

    def test_change_master_requires_correct_old(self):
        with self.assertRaises(InvalidMasterPasswordError):
            self.vault.change_master_password("Nope-Nope-123", "Brand-New-Pass77")

    def test_verify_master_password(self):
        self.assertTrue(self.vault.verify_master_password(MASTER))
        self.assertFalse(self.vault.verify_master_password("bad-guess-12"))

    def test_tampering_detected(self):
        self.vault.add_entry("Site", "u", "Pass#12345")
        doc = json.loads(self.path.read_text())
        data = list(doc["data"])
        data[40] = "A" if data[40] != "A" else "B"
        doc["data"] = "".join(data)
        self.path.write_text(json.dumps(doc))
        with self.assertRaises(InvalidMasterPasswordError):
            self.reopen()

    def test_corrupted_file(self):
        self.path.write_text("not json at all")
        with self.assertRaises(VaultCorruptedError):
            self.reopen()

    def test_reset_erases_vault(self):
        self.vault.reset()
        self.assertFalse(self.path.exists())
        self.assertFalse(self.vault.is_unlocked)


if __name__ == "__main__":
    unittest.main()
