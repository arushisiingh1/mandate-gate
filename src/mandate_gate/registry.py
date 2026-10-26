"""Key registry: which public key belongs to which agent or user.

SIMULATED: this is a local JSON file. There is no identity proofing and no
binding between a human and their key. The gate treats the registry as the
source of truth, so a real deployment would back this with something that does
that binding.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Optional, Tuple

from .signing import is_valid_public_key
from .validation import ID_RE


class RegistryError(Exception):
    pass


@dataclass
class _Entry:
    public_b64: str
    kind: str
    revoked: bool = False


class KeyRegistry:
    KINDS = ("agent", "user")

    def __init__(self, path: Optional[Path] = None):
        self._entries: Dict[str, _Entry] = {}
        self._path = Path(path) if path else None
        if self._path and self._path.exists():
            self._load()

    def register(self, principal_id: str, public_b64: str, kind: str) -> None:
        if not isinstance(principal_id, str) or not ID_RE.fullmatch(principal_id):
            raise RegistryError("invalid principal id")
        if kind not in self.KINDS:
            raise RegistryError(f"kind must be one of {self.KINDS}")
        if not is_valid_public_key(public_b64):
            raise RegistryError("invalid public key")
        if principal_id in self._entries:
            # No silent key replacement: rotating a key is a deliberate act.
            raise RegistryError(f"{principal_id!r} is already registered")
        self._entries[principal_id] = _Entry(public_b64, kind)

    def revoke(self, principal_id: str) -> None:
        entry = self._entries.get(principal_id)
        if entry is None:
            raise RegistryError("unknown principal")
        entry.revoked = True

    def lookup(self, principal_id: str, kind: str) -> Tuple[str, Optional[str]]:
        """Return ``(status, public_key)``.

        status is one of ``ok``, ``unknown``, ``wrong_kind``, ``revoked``. The
        key is returned only when status is ``ok``.
        """
        entry = self._entries.get(principal_id)
        if entry is None:
            return "unknown", None
        if entry.kind != kind:
            return "wrong_kind", None
        if entry.revoked:
            return "revoked", None
        return "ok", entry.public_b64

    def save(self) -> None:
        if not self._path:
            raise RegistryError("registry has no path")
        data = {
            pid: {"public_key": e.public_b64, "kind": e.kind, "revoked": e.revoked}
            for pid, e in sorted(self._entries.items())
        }
        self._path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")

    def _load(self) -> None:
        assert self._path is not None
        raw = json.loads(self._path.read_text())
        for pid, item in raw.items():
            self.register(pid, item["public_key"], item["kind"])
            if item.get("revoked"):
                self.revoke(pid)
