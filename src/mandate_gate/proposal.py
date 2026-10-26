"""A purchase proposal: what an agent asks the gate to authorize."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict

from .canonical import hash_obj
from .categories import CATEGORIES
from .envelope import make_envelope
from .signing import DOMAIN_PROPOSAL, KeyPair, sign
from .validation import (
    CURRENCY_RE,
    ID_RE,
    IDEM_RE,
    MAX_AMOUNT_CENTS,
    MAX_TIMESTAMP,
    MERCHANT_RE,
    NONCE_RE,
    ValidationError,
    require_exact_keys,
    require_int,
    require_str,
    require_text,
)

PROPOSAL_FIELDS = (
    "agent_id",
    "mandate_id",
    "merchant",
    "category",
    "amount_cents",
    "currency",
    "item",
    "nonce",
    "idempotency_key",
    "timestamp",
)


class ProposalError(ValidationError):
    pass


@dataclass(frozen=True)
class Proposal:
    agent_id: str
    mandate_id: str
    merchant: str
    category: str
    amount_cents: int
    currency: str
    item: str
    nonce: str
    idempotency_key: str
    timestamp: int

    def to_payload(self) -> Dict[str, Any]:
        return {name: getattr(self, name) for name in PROPOSAL_FIELDS}


def parse_proposal(payload: Any) -> Proposal:
    """Strictly parse a proposal payload (exact keys, exact types, bounded)."""
    try:
        obj = require_exact_keys(payload, PROPOSAL_FIELDS, "proposal")
        category = obj["category"]
        if not isinstance(category, str) or category not in CATEGORIES:
            raise ProposalError("proposal: unknown category")
        return Proposal(
            agent_id=require_str(obj["agent_id"], ID_RE, "agent_id"),
            mandate_id=require_str(obj["mandate_id"], ID_RE, "mandate_id"),
            merchant=require_str(obj["merchant"], MERCHANT_RE, "merchant"),
            category=category,
            amount_cents=require_int(obj["amount_cents"], 1, MAX_AMOUNT_CENTS, "amount_cents"),
            currency=require_str(obj["currency"], CURRENCY_RE, "currency"),
            item=require_text(obj["item"], 120, "item"),
            nonce=require_str(obj["nonce"], NONCE_RE, "nonce"),
            idempotency_key=require_str(obj["idempotency_key"], IDEM_RE, "idempotency_key"),
            timestamp=require_int(obj["timestamp"], 0, MAX_TIMESTAMP, "timestamp"),
        )
    except ProposalError:
        raise
    except ValidationError as exc:
        raise ProposalError(str(exc)) from exc


def intent_hash(p: Proposal) -> str:
    """Identity of the *intent*: everything except per-attempt fields.

    A legitimate retry re-signs with a fresh nonce and timestamp but keeps the
    same intent. Reusing an idempotency key with a different intent is a
    conflict, not a retry.
    """
    return hash_obj(
        {
            "agent_id": p.agent_id,
            "mandate_id": p.mandate_id,
            "merchant": p.merchant,
            "category": p.category,
            "amount_cents": p.amount_cents,
            "currency": p.currency,
            "item": p.item,
            "idempotency_key": p.idempotency_key,
        }
    )


def sign_proposal(agent_keys: KeyPair, proposal: Proposal) -> Dict[str, Any]:
    payload = proposal.to_payload()
    return make_envelope(
        payload, sign(agent_keys.private, DOMAIN_PROPOSAL, payload), proposal.agent_id
    )
