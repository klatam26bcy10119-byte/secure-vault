"""Password strength analysis (part of module 3)."""

import itertools
import math
from dataclasses import dataclass, field

COMMON_PASSWORDS = frozenset({
    "password", "123456", "12345678", "123456789", "qwerty", "abc123", "letmein",
    "admin", "welcome", "iloveyou", "monkey", "dragon", "football", "111111",
    "123123", "password1", "passw0rd", "qwerty123", "000000", "1q2w3e4r",
    "sunshine", "princess", "login", "master", "hello123", "admin123",
    "changeme", "trustno1", "superman", "batman", "starwars", "india123",
})
LABELS = ("Very Weak", "Weak", "Fair", "Strong", "Very Strong")
SYMBOL_CHARS = set("!@#$%^&*()-_=+[]{};:,.?/\\|<>~`'\"")


@dataclass
class StrengthResult:
    score: int                         # 0 (worst) .. 4 (best)
    label: str
    entropy_bits: float
    feedback: list = field(default_factory=list)


def pool_size(password: str) -> int:
    """Size of the alphabet an attacker must search, based on character types used."""
    size = 0
    if any(c.islower() for c in password):
        size += 26
    if any(c.isupper() for c in password):
        size += 26
    if any(c.isdigit() for c in password):
        size += 10
    if any(not c.isalnum() for c in password):
        size += 32
    return size


def estimate_entropy(password: str) -> float:
    """Entropy in bits = length x log2(alphabet size)."""
    if not password:
        return 0.0
    return round(len(password) * math.log2(pool_size(password)), 1)


def has_repeats(password: str, run: int = 3) -> bool:
    """True if any character repeats ``run`` or more times in a row (e.g. 'aaa')."""
    return any(len(list(group)) >= run for _, group in itertools.groupby(password))


def has_sequence(password: str, run: int = 4) -> bool:
    """True if ``run`` consecutive characters ascend/descend (e.g. '1234', 'dcba')."""
    p = password.lower()
    for i in range(len(p) - run + 1):
        diffs = {ord(p[i + j + 1]) - ord(p[i + j]) for j in range(run - 1)}
        if diffs == {1} or diffs == {-1}:
            return True
    return False


def check_strength(password: str) -> StrengthResult:
    """Score a password from 0 to 4 and explain how to improve it."""
    feedback = []
    entropy = estimate_entropy(password)

    if entropy < 28:
        score = 0
    elif entropy < 36:
        score = 1
    elif entropy < 60:
        score = 2
    elif entropy < 80:
        score = 3
    else:
        score = 4

    if len(password) < 8:
        score = min(score, 1)
        feedback.append("Use at least 8 characters (12+ is better).")
    if password.lower() in COMMON_PASSWORDS:
        score = 0
        feedback.append("This is a very common password - attackers try it first.")
    if has_repeats(password):
        score = max(score - 1, 0)
        feedback.append("Avoid repeating the same character (e.g. 'aaa').")
    if has_sequence(password):
        score = max(score - 1, 0)
        feedback.append("Avoid sequences such as '1234' or 'abcd'.")
    if password and pool_size(password) < 62:
        feedback.append("Mix upper/lower case letters, digits and symbols.")

    return StrengthResult(score, LABELS[score], entropy, feedback)
