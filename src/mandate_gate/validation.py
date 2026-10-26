"""Small strict validators shared by every parser in the package.

Everything that crosses a trust boundary (agent output, wire messages,
mandates) is checked with these. The rule is: exact keys, exact types, bounded
sizes. Anything else is rejected rather than coerced.
"""

from __future__ import annotations

import re
from typing import Any, Mapping, Sequence

ID_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
NONCE_RE = re.compile(r"^[A-Za-z0-9_-]{16,64}$")
IDEM_RE = re.compile(r"^[A-Za-z0-9_-]{8,64}$")
MERCHANT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 .&'_-]{0,63}$")
CURRENCY_RE = re.compile(r"^[A-Z]{3}$")

MAX_AMOUNT_CENTS = 10**9  # $10,000,000: far above any sane single purchase
MAX_TIMESTAMP = 4_102_444_800  # 2100-01-01


class ValidationError(ValueError):
    """Raised by every parser in the package on any schema violation."""


def is_int(value: Any) -> bool:
    """True for real ints only. ``bool`` is an int subclass and is excluded."""
    return isinstance(value, int) and not isinstance(value, bool)


def require_exact_keys(obj: Any, expected: Sequence[str], what: str) -> Mapping[str, Any]:
    if not isinstance(obj, dict):
        raise ValidationError(f"{what}: must be an object")
    keys = set(obj.keys())
    want = set(expected)
    if not all(isinstance(k, str) for k in keys):
        raise ValidationError(f"{what}: keys must be strings")
    missing = want - keys
    extra = keys - want
    if missing:
        raise ValidationError(f"{what}: missing fields {sorted(missing)}")
    if extra:
        raise ValidationError(f"{what}: unexpected fields {sorted(extra)}")
    return obj


def require_str(value: Any, regex: "re.Pattern[str]", what: str) -> str:
    if not isinstance(value, str) or not regex.fullmatch(value):
        raise ValidationError(f"{what}: invalid")
    return value


def require_int(value: Any, lo: int, hi: int, what: str) -> int:
    if not is_int(value) or not (lo <= value <= hi):
        raise ValidationError(f"{what}: must be an integer in [{lo}, {hi}]")
    return value


def require_text(value: Any, max_len: int, what: str) -> str:
    """Free text: printable characters only (no control or zero-width chars)."""
    if (
        not isinstance(value, str)
        or not (1 <= len(value) <= max_len)
        or not value.isprintable()
    ):
        raise ValidationError(f"{what}: must be 1-{max_len} printable characters")
    return value
