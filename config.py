"""Central configuration: file locations and security limits."""

import os
from pathlib import Path

IDLE_TIMEOUT_SECONDS = 300        # auto-lock after 5 minutes without activity
MAX_LOGIN_ATTEMPTS = 3            # wrong master passwords allowed per session
PASSWORD_MAX_AGE_DAYS = 90        # passwords older than this are flagged
MIN_MASTER_LENGTH = 10


def data_dir() -> Path:
    """Folder holding the vault and log. Override with SECUREVAULT_HOME."""
    base = os.environ.get("SECUREVAULT_HOME")
    folder = Path(base) if base else Path.home() / ".securevault"
    folder.mkdir(parents=True, exist_ok=True)
    return folder


def vault_path() -> Path:
    return data_dir() / "vault.json"


def log_path() -> Path:
    return data_dir() / "securevault.log"
