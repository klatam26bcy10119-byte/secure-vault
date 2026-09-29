"""Vault security audit: weak, reused and old passwords (part of module 3)."""

import hashlib
from dataclasses import dataclass, field
from datetime import datetime

from .config import PASSWORD_MAX_AGE_DAYS
from .models import Entry
from .strength import check_strength


@dataclass
class AuditReport:
    total: int = 0
    weak: list = field(default_factory=list)      # entries with score <= 1
    reused: list = field(default_factory=list)    # groups of entries sharing a password
    old: list = field(default_factory=list)       # entries older than the limit

    @property
    def problem_entries(self) -> set:
        ids = {e.id for e in self.weak} | {e.id for e in self.old}
        for group in self.reused:
            ids |= {e.id for e in group}
        return ids

    @property
    def health_score(self) -> int:
        """0-100: share of entries with no detected problem."""
        if self.total == 0:
            return 100
        return round(100 * (1 - len(self.problem_entries) / self.total))


def run_audit(entries: list[Entry], max_age_days: int = PASSWORD_MAX_AGE_DAYS,
              now: datetime | None = None) -> AuditReport:
    report = AuditReport(total=len(entries))
    groups: dict[str, list[Entry]] = {}          # digest -> entries (hash map)

    for entry in entries:
        if check_strength(entry.password).score <= 1:
            report.weak.append(entry)
        if entry.password_age_days(now) > max_age_days:
            report.old.append(entry)
        digest = hashlib.sha256(entry.password.encode("utf-8")).hexdigest()
        groups.setdefault(digest, []).append(entry)

    report.reused = [g for g in groups.values() if len(g) > 1]
    return report
