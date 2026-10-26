"""The scorer interface the gate depends on.

The gate never imports a model library. It only needs something with a
``score(features) -> RiskResult`` method, which keeps the deterministic core
free of ML dependencies and easy to test with a stub.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, Sequence, Tuple


@dataclass(frozen=True)
class RiskResult:
    score: float  # 0.0 (benign) to 1.0 (very likely fraud); a ranking score, not a calibrated probability
    reasons: Tuple[str, ...]
    model_version: str


class RiskScorer(Protocol):
    model_version: str

    def score(self, features: Sequence[float]) -> RiskResult: ...


class StubScorer:
    """Fixed-score scorer for tests and rule-only runs."""

    def __init__(self, score: float = 0.0, reasons: Tuple[str, ...] = ("STUB",), version: str = "stub-1"):
        self._score = score
        self._reasons = reasons
        self.model_version = version
        self.calls = 0

    def score(self, features: Sequence[float]) -> RiskResult:
        self.calls += 1
        return RiskResult(self._score, self._reasons, self.model_version)
