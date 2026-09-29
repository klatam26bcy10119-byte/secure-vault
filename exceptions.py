"""Custom exception hierarchy.

Every error the application raises on purpose derives from ``VaultError`` so the
CLI can catch one base class and show a friendly message instead of a traceback.
"""


class VaultError(Exception):
    """Base class for all SecureVault errors."""


class ValidationError(VaultError):
    """User supplied input failed validation."""


class VaultNotFoundError(VaultError):
    """No vault file exists at the expected location."""


class VaultExistsError(VaultError):
    """A vault already exists, so a new one cannot be created over it."""


class VaultLockedError(VaultError):
    """An operation needing the decrypted vault was attempted while locked."""


class VaultCorruptedError(VaultError):
    """The vault file is malformed and cannot be parsed."""


class InvalidMasterPasswordError(VaultError):
    """Wrong master password (or the encrypted data was tampered with)."""


class DecryptionError(VaultError):
    """Low-level decryption failure raised by ``crypto_utils``."""


class EntryNotFoundError(VaultError):
    """No entry exists with the requested id."""
