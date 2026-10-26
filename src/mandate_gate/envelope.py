"""The wire format: ``{"payload": {...}, "signature": "...", "signer": "..."}``."""

from __future__ import annotations

from typing import Any, Dict, Tuple

from .validation import ID_RE, ValidationError, require_exact_keys, require_str

ENVELOPE_FIELDS = ("payload", "signature", "signer")
_MAX_SIGNATURE_LEN = 200


def parse_envelope(msg: Any, what: str) -> Tuple[Dict[str, Any], str, str]:
    """Validate the envelope shape only. Content is parsed after verification."""
    obj = require_exact_keys(msg, ENVELOPE_FIELDS, what)
    payload = obj["payload"]
    signature = obj["signature"]
    if not isinstance(payload, dict):
        raise ValidationError(f"{what}: payload must be an object")
    if not isinstance(signature, str) or len(signature) > _MAX_SIGNATURE_LEN:
        raise ValidationError(f"{what}: signature must be a short string")
    signer = require_str(obj["signer"], ID_RE, f"{what} signer")
    return payload, signature, signer


def make_envelope(payload: Dict[str, Any], signature: str, signer: str) -> Dict[str, Any]:
    return {"payload": payload, "signature": signature, "signer": signer}
