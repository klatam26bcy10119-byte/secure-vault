"""Data model for a single stored credential."""

import uuid
from dataclasses import asdict, dataclass, field, fields
from datetime import datetime, timezone


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass
class Entry:
    """One saved login: site, username, password and optional notes."""

    site: str
    username: str
    password: str
    notes: str = ""
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:8])
    created_at: str = field(default_factory=_now)
    updated_at: str = field(default_factory=_now)
    password_changed_at: str = field(default_factory=_now)

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "Entry":
        """Build an Entry, ignoring unknown keys so older/newer files still load."""
        known = {f.name for f in fields(cls)}
        return cls(**{k: v for k, v in data.items() if k in known})

    def password_age_days(self, now: datetime | None = None) -> int:
        """Whole days since the password was last set or changed."""
        now = now or datetime.now(timezone.utc)
        changed = datetime.fromisoformat(self.password_changed_at)
        return (now - changed).days
