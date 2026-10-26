"""Hash-chained, append-only audit log.

Each record commits to the previous record's hash, so editing, deleting or
reordering any record breaks every hash after it and ``verify`` reports where.

LIMIT: this is a single-process log with no external anchoring. Someone who can
rewrite the whole file can recompute the whole chain, and truncating the tail
is undetectable unless the latest head hash was published elsewhere. Publish
``head_hash`` somewhere the attacker cannot reach if that matters.
"""

from __future__ import annotations

import json
import os
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

from .canonical import canonical_bytes, sha256_hex

GENESIS_HASH = "0" * 64


class AuditError(Exception):
    pass


@dataclass(frozen=True)
class VerifyResult:
    ok: bool
    records: int
    head_hash: str
    error: Optional[str] = None
    bad_seq: Optional[int] = None


def _record_hash(prev_hash: str, seq: int, body: Dict[str, Any]) -> str:
    return sha256_hex(prev_hash.encode("ascii") + canonical_bytes({"seq": seq, "body": body}))


def verify_records(records: List[Dict[str, Any]]) -> VerifyResult:
    prev = GENESIS_HASH
    for index, rec in enumerate(records):
        try:
            if rec["seq"] != index:
                return VerifyResult(False, index, prev, "sequence number out of order", index)
            if rec["prev_hash"] != prev:
                return VerifyResult(False, index, prev, "prev_hash does not match chain", index)
            expected = _record_hash(prev, rec["seq"], rec["body"])
            if rec["hash"] != expected:
                return VerifyResult(False, index, prev, "record hash mismatch (edited?)", index)
            prev = rec["hash"]
        except Exception as exc:  # malformed record
            return VerifyResult(False, index, prev, f"malformed record: {type(exc).__name__}", index)
    return VerifyResult(True, len(records), prev)


def read_records(path: Path) -> List[Dict[str, Any]]:
    records: List[Dict[str, Any]] = []
    with open(path, "r", encoding="utf-8") as handle:
        for line_no, line in enumerate(handle, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise AuditError(f"line {line_no} is not valid JSON") from exc
    return records


def verify_file(path: Path) -> VerifyResult:
    try:
        records = read_records(Path(path))
    except (AuditError, OSError) as exc:
        return VerifyResult(False, 0, GENESIS_HASH, str(exc))
    return verify_records(records)


class AuditLog:
    """Append-only log. Pass ``path=None`` for an in-memory log (tests)."""

    def __init__(self, path: Optional[Path] = None) -> None:
        self._path = Path(path) if path else None
        self._records: List[Dict[str, Any]] = []
        self._lock = threading.Lock()
        if self._path and self._path.exists():
            self._records = read_records(self._path)
            result = verify_records(self._records)
            if not result.ok:
                raise AuditError(f"existing log is corrupt at seq {result.bad_seq}: {result.error}")
        elif self._path:
            self._path.parent.mkdir(parents=True, exist_ok=True)

    @property
    def head_hash(self) -> str:
        return self._records[-1]["hash"] if self._records else GENESIS_HASH

    def __len__(self) -> int:
        return len(self._records)

    @property
    def records(self) -> List[Dict[str, Any]]:
        return [dict(r) for r in self._records]

    def append(self, body: Dict[str, Any]) -> Dict[str, Any]:
        """Append one record. Raises if it cannot be written durably."""
        with self._lock:
            seq = len(self._records)
            prev = self.head_hash
            record = {
                "seq": seq,
                "prev_hash": prev,
                "body": body,
                "hash": _record_hash(prev, seq, body),
            }
            line = json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n"
            if self._path:
                with open(self._path, "a", encoding="utf-8") as handle:
                    handle.write(line)
                    handle.flush()
                    os.fsync(handle.fileno())
            self._records.append(record)
            return record

    def verify(self) -> VerifyResult:
        return verify_records(self._records)
