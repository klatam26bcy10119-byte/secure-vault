"""Cryptographically secure random password generator (module 2)."""

import secrets
import string

from .validators import validate_int_range
from .exceptions import ValidationError

LOWER = string.ascii_lowercase
UPPER = string.ascii_uppercase
DIGITS = string.digits
SYMBOLS = "!@#$%^&*()-_=+[]{};:,.?"
AMBIGUOUS = set("Il1O0o")
MIN_LENGTH, MAX_LENGTH = 8, 64


def generate_password(
    length: int = 16,
    use_upper: bool = True,
    use_lower: bool = True,
    use_digits: bool = True,
    use_symbols: bool = True,
    exclude_ambiguous: bool = False,
) -> str:
    """Return a random password guaranteed to contain every selected character type."""
    length = validate_int_range(length, MIN_LENGTH, MAX_LENGTH, "Length")
    pools = []
    for enabled, chars in ((use_lower, LOWER), (use_upper, UPPER),
                           (use_digits, DIGITS), (use_symbols, SYMBOLS)):
        if enabled:
            pools.append([c for c in chars if not (exclude_ambiguous and c in AMBIGUOUS)])
    if not pools:
        raise ValidationError("Select at least one character type.")

    chars = [secrets.choice(pool) for pool in pools]              # one of each type
    everything = [c for pool in pools for c in pool]
    chars += [secrets.choice(everything) for _ in range(length - len(chars))]
    secrets.SystemRandom().shuffle(chars)                          # hide the pattern
    return "".join(chars)
