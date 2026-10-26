"""Simulated ledger and per-agent history.

SIMULATED: a "charge" is an in-memory entry. No payment network is touched.

Reservations matter. A proposal that is waiting for human review has not been
paid, but it *will be* if approved, so its amount counts against the cumulative
cap and the velocity window straight away. Without that, an agent could queue
several reviews that each looked affordable on their own.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from typing import Deque, Dict, List, Optional, Set, Tuple


@dataclass(frozen=True)
class Charge:
    charge_id: str
    mandate_id: str
    agent_id: str
    merchant: str
    category: str
    amount_cents: int
    ts: int
    review_id: Optional[str] = None


@dataclass(frozen=True)
class Reservation:
    review_id: str
    mandate_id: str
    agent_id: str
    merchant: str
    category: str
    amount_cents: int
    ts: int


class Ledger:
    def __init__(self) -> None:
        self._charges: List[Charge] = []
        self._reservations: Dict[str, Reservation] = {}

    # --- reads -----------------------------------------------------------
    @property
    def charges(self) -> Tuple[Charge, ...]:
        return tuple(self._charges)

    def committed_total(self, mandate_id: str) -> int:
        return sum(c.amount_cents for c in self._charges if c.mandate_id == mandate_id)

    def reserved_total(self, mandate_id: str) -> int:
        return sum(
            r.amount_cents for r in self._reservations.values() if r.mandate_id == mandate_id
        )

    def exposure(self, mandate_id: str) -> int:
        """Money committed plus money held for pending reviews."""
        return self.committed_total(mandate_id) + self.reserved_total(mandate_id)

    def in_window_count(self, mandate_id: str, since_ts: int) -> int:
        """Approvals and pending reviews for a mandate strictly after ``since_ts``."""
        done = sum(1 for c in self._charges if c.mandate_id == mandate_id and c.ts > since_ts)
        held = sum(
            1
            for r in self._reservations.values()
            if r.mandate_id == mandate_id and r.ts > since_ts
        )
        return done + held

    # --- writes ----------------------------------------------------------
    def commit(self, charge: Charge) -> None:
        self._charges.append(charge)

    def reserve(self, reservation: Reservation) -> None:
        self._reservations[reservation.review_id] = reservation

    def release(self, review_id: str) -> Optional[Reservation]:
        return self._reservations.pop(review_id, None)

    def reservation(self, review_id: str) -> Optional[Reservation]:
        return self._reservations.get(review_id)


# ---------------------------------------------------------------------------
# Per-agent history used for risk features. The same class feeds the gate at
# serving time and the synthetic generator at training time, so a feature can
# never mean one thing in training and another in production.
# ---------------------------------------------------------------------------

SECS_SINCE_LAST_CAP = 7 * 86400
_MAX_MERCHANTS_REMEMBERED = 1000


@dataclass(frozen=True)
class HistorySnapshot:
    secs_since_last: int
    txns_last_hour: int
    mean_amount: Optional[float]
    new_merchant: bool


class AgentHistory:
    def __init__(self, maxlen: int = 500) -> None:
        self._events: Deque[Tuple[int, int]] = deque(maxlen=maxlen)  # (ts, amount)
        self._merchants: Set[str] = set()
        self._sum = 0
        self._count = 0

    def snapshot(self, now: int, merchant: str) -> HistorySnapshot:
        if self._events:
            last_ts = self._events[-1][0]
            secs = min(max(now - last_ts, 0), SECS_SINCE_LAST_CAP)
        else:
            secs = SECS_SINCE_LAST_CAP
        recent = sum(1 for ts, _ in self._events if ts > now - 3600)
        mean = (self._sum / self._count) if self._count else None
        return HistorySnapshot(secs, recent, mean, merchant not in self._merchants)

    def record(self, ts: int, merchant: str, amount_cents: int) -> None:
        self._events.append((ts, amount_cents))
        self._sum += amount_cents
        self._count += 1
        if len(self._merchants) < _MAX_MERCHANTS_REMEMBERED:
            self._merchants.add(merchant)
