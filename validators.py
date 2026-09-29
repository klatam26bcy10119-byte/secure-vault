"""Input validation helpers. Each returns the cleaned value or raises."""

from .config import MIN_MASTER_LENGTH
from .exceptions import ValidationError


def validate_required(value: str, field_name: str, max_len: int = 100) -> str:
    """Trim whitespace; reject empty or over-long text."""
    cleaned = (value or "").strip()
    if not cleaned:
        raise ValidationError(f"{field_name} cannot be empty.")
    if len(cleaned) > max_len:
        raise ValidationError(f"{field_name} must be at most {max_len} characters.")
    return cleaned


def validate_master_password(password: str) -> str:
    """Master password rules: minimum length, at least one letter and one digit."""
    if len(password) < MIN_MASTER_LENGTH:
        raise ValidationError(
            f"Master password must be at least {MIN_MASTER_LENGTH} characters long."
        )
    if not any(c.isalpha() for c in password) or not any(c.isdigit() for c in password):
        raise ValidationError("Master password must contain letters and digits.")
    return password


def validate_int_range(raw: str, low: int, high: int, field_name: str = "Value") -> int:
    """Convert text to an int within [low, high]."""
    try:
        number = int(str(raw).strip())
    except ValueError:
        raise ValidationError(f"{field_name} must be a whole number.") from None
    if not low <= number <= high:
        raise ValidationError(f"{field_name} must be between {low} and {high}.")
    return number
