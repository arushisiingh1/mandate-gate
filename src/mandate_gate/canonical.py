"""Canonical JSON: the single byte encoding used for signing and hashing.

Two properties matter. The encoding is deterministic (sorted keys, no
whitespace, ASCII escapes), and it refuses floats. Money is integer cents, so
``19.99`` versus ``1999e-2`` ambiguities cannot exist in a signed payload.

This is canonical *JSON*, not an RFC 9421 HTTP message signature. See the
README's "real versus simulated" table.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any


class CanonicalError(ValueError):
    pass


_MAX_DEPTH = 8


def _check(obj: Any, depth: int = 0) -> None:
    if depth > _MAX_DEPTH:
        raise CanonicalError("nesting too deep")
    if obj is None or isinstance(obj, (bool, str, int)):
        return
    if isinstance(obj, float):
        raise CanonicalError("floats are not allowed in signed payloads; use integer cents")
    if isinstance(obj, (list, tuple)):
        for item in obj:
            _check(item, depth + 1)
        return
    if isinstance(obj, dict):
        for key, value in obj.items():
            if not isinstance(key, str):
                raise CanonicalError("object keys must be strings")
            _check(value, depth + 1)
        return
    raise CanonicalError(f"unsupported type {type(obj).__name__}")


def canonical_bytes(obj: Any) -> bytes:
    _check(obj)
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def hash_obj(obj: Any) -> str:
    return sha256_hex(canonical_bytes(obj))
