"""Ed25519 signing over canonical JSON, with domain separation.

Every signature covers ``DOMAIN || canonical_json(payload)``. The domain tag
means a signature made over a *mandate* can never verify as a signature over a
*proposal* (or the reverse), even if the bytes were somehow identical.
"""

from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from .canonical import canonical_bytes

DOMAIN_PROPOSAL = b"mandate-gate/v1/proposal\n"
DOMAIN_MANDATE = b"mandate-gate/v1/mandate\n"


@dataclass(frozen=True)
class KeyPair:
    private: Ed25519PrivateKey
    public_b64: str


def _public_b64(private: Ed25519PrivateKey) -> str:
    raw = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return base64.b64encode(raw).decode("ascii")


def generate_keypair() -> KeyPair:
    private = Ed25519PrivateKey.generate()
    return KeyPair(private, _public_b64(private))


def keypair_from_seed(seed: bytes) -> KeyPair:
    """Deterministic key for demos and tests ONLY. Never use for real keys."""
    private = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(seed).digest())
    return KeyPair(private, _public_b64(private))


def sign(private: Ed25519PrivateKey, domain: bytes, payload: Any) -> str:
    signature = private.sign(domain + canonical_bytes(payload))
    return base64.b64encode(signature).decode("ascii")


def is_valid_public_key(public_b64: Any) -> bool:
    try:
        raw = base64.b64decode(public_b64, validate=True)
        Ed25519PublicKey.from_public_bytes(raw)
        return len(raw) == 32
    except Exception:
        return False


def verify(public_b64: Any, domain: bytes, payload: Any, signature_b64: Any) -> bool:
    """Return True only for a valid signature. Never raises."""
    try:
        if not isinstance(public_b64, str) or not isinstance(signature_b64, str):
            return False
        signature = base64.b64decode(signature_b64, validate=True)
        if len(signature) != 64:
            return False
        public = Ed25519PublicKey.from_public_bytes(
            base64.b64decode(public_b64, validate=True)
        )
        public.verify(signature, domain + canonical_bytes(payload))
        return True
    except Exception:
        return False
