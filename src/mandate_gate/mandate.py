"""The user-signed mandate: the *consent* and *delegated authority* record.

A mandate states, in the user's own signature, what one named agent may spend:
per-transaction cap, cumulative cap, allowed categories and a validity window.
A missing, expired, altered or foreign mandate means deny.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Tuple

from .categories import CATEGORIES
from .envelope import make_envelope
from .signing import DOMAIN_MANDATE, KeyPair, sign
from .validation import (
    CURRENCY_RE,
    ID_RE,
    MAX_AMOUNT_CENTS,
    MAX_TIMESTAMP,
    ValidationError,
    require_exact_keys,
    require_int,
    require_str,
)

MANDATE_FIELDS = (
    "mandate_id",
    "user_id",
    "agent_id",
    "currency",
    "per_txn_cap_cents",
    "cumulative_cap_cents",
    "allowed_categories",
    "not_before",
    "expires_at",
)


class MandateError(ValidationError):
    pass


@dataclass(frozen=True)
class Mandate:
    mandate_id: str
    user_id: str
    agent_id: str
    currency: str
    per_txn_cap_cents: int
    cumulative_cap_cents: int
    allowed_categories: Tuple[str, ...]
    not_before: int
    expires_at: int

    def to_payload(self) -> Dict[str, Any]:
        return {
            "mandate_id": self.mandate_id,
            "user_id": self.user_id,
            "agent_id": self.agent_id,
            "currency": self.currency,
            "per_txn_cap_cents": self.per_txn_cap_cents,
            "cumulative_cap_cents": self.cumulative_cap_cents,
            "allowed_categories": sorted(self.allowed_categories),
            "not_before": self.not_before,
            "expires_at": self.expires_at,
        }


def parse_mandate(payload: Any) -> Mandate:
    """Strictly parse a mandate payload. Call this only after verification."""
    try:
        obj = require_exact_keys(payload, MANDATE_FIELDS, "mandate")
        cats = obj["allowed_categories"]
        if (
            not isinstance(cats, list)
            or not cats
            or len(cats) > len(CATEGORIES)
            or not all(isinstance(c, str) and c in CATEGORIES for c in cats)
            or len(set(cats)) != len(cats)
        ):
            raise MandateError("mandate: allowed_categories must be unique known categories")
        per_txn = require_int(obj["per_txn_cap_cents"], 1, MAX_AMOUNT_CENTS, "per_txn_cap_cents")
        cumulative = require_int(
            obj["cumulative_cap_cents"], 1, MAX_AMOUNT_CENTS, "cumulative_cap_cents"
        )
        if per_txn > cumulative:
            raise MandateError("mandate: per-transaction cap exceeds cumulative cap")
        not_before = require_int(obj["not_before"], 0, MAX_TIMESTAMP, "not_before")
        expires_at = require_int(obj["expires_at"], 0, MAX_TIMESTAMP, "expires_at")
        if expires_at <= not_before:
            raise MandateError("mandate: expires_at must be after not_before")
        return Mandate(
            mandate_id=require_str(obj["mandate_id"], ID_RE, "mandate_id"),
            user_id=require_str(obj["user_id"], ID_RE, "user_id"),
            agent_id=require_str(obj["agent_id"], ID_RE, "agent_id"),
            currency=require_str(obj["currency"], CURRENCY_RE, "currency"),
            per_txn_cap_cents=per_txn,
            cumulative_cap_cents=cumulative,
            allowed_categories=tuple(sorted(cats)),
            not_before=not_before,
            expires_at=expires_at,
        )
    except MandateError:
        raise
    except ValidationError as exc:
        raise MandateError(str(exc)) from exc


def sign_mandate(user_keys: KeyPair, mandate: Mandate) -> Dict[str, Any]:
    """Produce the wire message a user hands to the gate (and their agent)."""
    payload = mandate.to_payload()
    return make_envelope(payload, sign(user_keys.private, DOMAIN_MANDATE, payload), mandate.user_id)
