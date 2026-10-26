"""Shared fixtures for the gate tests.

``World`` builds a registry, a user, an agent, a signed mandate and a gate on a
simulated clock. ``submit`` evaluates a proposal and, as a side check, asserts
that exactly one audit record was written for it: "every decision is logged"
is verified on every single call, not just in one dedicated test.
"""

from __future__ import annotations

import copy
import unittest
from typing import Any, Dict, Iterable, List, Optional, Tuple

from mandate_gate.audit import AuditLog
from mandate_gate.codes import Code, Outcome
from mandate_gate.envelope import make_envelope
from mandate_gate.gate import Decision, Gate, GateConfig
from mandate_gate.mandate import Mandate, sign_mandate
from mandate_gate.proposal import PROPOSAL_FIELDS
from mandate_gate.registry import KeyRegistry
from mandate_gate.risk.scorer import RiskResult, StubScorer
from mandate_gate.signing import DOMAIN_MANDATE, DOMAIN_PROPOSAL, keypair_from_seed, sign

T0 = 1_790_000_000  # a fixed instant, so every test is deterministic
ALLOWED = ("books", "electronics", "groceries", "home", "software")
PER_TXN = 30_000  # $300.00
CUMULATIVE = 300_000  # $3,000.00


class Clock:
    def __init__(self, t: int = T0) -> None:
        self.t = t

    def __call__(self) -> int:
        return self.t

    def advance(self, seconds: int) -> None:
        self.t += seconds


class World:
    def __init__(
        self,
        scorer: Any = None,
        config: Optional[GateConfig] = None,
        categories: Iterable[str] = ALLOWED,
        per_txn: int = PER_TXN,
        cumulative: int = CUMULATIVE,
        lifetime: int = 86_400,
        mandate_id: str = "mandate-1",
        agent_id: str = "shopper-1",
        user_id: str = "alice",
    ) -> None:
        self.clock = Clock()
        self.user = keypair_from_seed(b"test user")
        self.agent = keypair_from_seed(b"test agent")
        self.attacker = keypair_from_seed(b"test attacker")
        self.registry = KeyRegistry()
        self.registry.register(user_id, self.user.public_b64, "user")
        self.registry.register(agent_id, self.agent.public_b64, "agent")
        self.agent_id, self.user_id, self.mandate_id = agent_id, user_id, mandate_id
        self.mandate = Mandate(
            mandate_id, user_id, agent_id, "USD", per_txn, cumulative, tuple(categories), T0 - 60, T0 + lifetime
        )
        self.mandate_msg = sign_mandate(self.user, self.mandate)
        self.audit = AuditLog()
        self.config = config or GateConfig()
        self.gate = Gate(self.registry, self.audit, self.config, clock=self.clock, scorer=scorer)
        self.decisions: List[Decision] = []
        self._n = 0

    # --- building messages ------------------------------------------------------
    def fields(self, **over: Any) -> Dict[str, Any]:
        """A valid proposal payload with a fresh nonce and idempotency key."""
        self._n += 1
        payload: Dict[str, Any] = {
            "agent_id": self.agent_id,
            "mandate_id": self.mandate_id,
            "merchant": "pagepress.example",
            "category": "books",
            "amount_cents": 2_000,
            "currency": "USD",
            "item": "paperback novel",
            "nonce": f"nonce-{self._n:016d}",
            "idempotency_key": f"idem-{self._n:08d}",
            "timestamp": self.clock.t,
        }
        payload.update(over)
        return payload

    def sign_fields(self, payload: Dict[str, Any], key: Any = None, domain: bytes = DOMAIN_PROPOSAL, signer: Optional[str] = None) -> Dict[str, Any]:
        key = key or self.agent
        who = signer if signer is not None else payload.get("agent_id", self.agent_id)
        return make_envelope(payload, sign(key.private, domain, payload), who)

    def proposal(self, **over: Any) -> Dict[str, Any]:
        return self.sign_fields(self.fields(**over))

    # --- running the gate -------------------------------------------------------
    def submit(self, msg: Any, mandate: Any = "default") -> Decision:
        before = len(self.audit)
        m = self.mandate_msg if mandate == "default" else mandate
        d = self.gate.evaluate(msg, m)
        assert len(self.audit) == before + 1, "every evaluation must append exactly one audit record"
        self.decisions.append(d)
        return d

    def send(self, mandate: Any = "default", **over: Any) -> Decision:
        return self.submit(self.proposal(**over), mandate)

    # --- reading state ----------------------------------------------------------
    @property
    def charges(self):
        return self.gate.ledger.charges

    def total(self) -> int:
        return sum(c.amount_cents for c in self.charges)


def new_mandate_msg(world: World, **changes: Any) -> Dict[str, Any]:
    """A fresh user-signed mandate derived from the world's, with some fields changed."""
    payload = world.mandate.to_payload()
    payload.update(changes)
    return make_envelope(payload, sign(world.user.private, DOMAIN_MANDATE, payload), world.user_id)


def resign_mandate(world: World, payload: Dict[str, Any], key: Any = None, domain: bytes = DOMAIN_MANDATE, signer: Optional[str] = None) -> Dict[str, Any]:
    key = key or world.user
    return make_envelope(payload, sign(key.private, domain, payload), signer or world.user_id)


class Flip(dict):
    """A dict that shows the signature check one thing and the parser another.

    ``items()`` (what canonical JSON, and so the signature check, iterates)
    returns the honest values; ``[]`` (what a parser reads) returns the
    tampered ones. Without a defensive snapshot this is a parser differential.
    """

    def __init__(self, honest: Dict[str, Any], tampered: Dict[str, Any]) -> None:
        super().__init__(honest)
        self._tampered = tampered

    def __getitem__(self, key: str) -> Any:
        return self._tampered.get(key, super().__getitem__(key))

    def get(self, key: str, default: Any = None) -> Any:
        return self[key] if key in self else default


def assert_denied(tc: unittest.TestCase, d: Decision, code: str) -> None:
    tc.assertEqual(d.result, Outcome.DENY, f"expected DENY {code}, got {d.result.value} {d.reason_codes}")
    tc.assertIn(code, d.reason_codes)
    tc.assertNotIn(Code.INTERNAL_ERROR.value, d.reason_codes, "denied for the wrong reason: an internal error")
    tc.assertIsNone(d.charge_id)


def check_no_unauthorized_spend(tc: unittest.TestCase, w: World) -> None:
    """Recompute, from the ledger alone, that nothing exceeded the mandate."""
    m = w.mandate
    charges = [c for c in w.charges if c.mandate_id == m.mandate_id]
    tc.assertLessEqual(sum(c.amount_cents for c in charges), m.cumulative_cap_cents, "cumulative cap exceeded")
    for c in charges:
        tc.assertLessEqual(c.amount_cents, m.per_txn_cap_cents, "per-transaction cap exceeded")
        tc.assertIn(c.category, m.allowed_categories, "charge in a category the mandate does not allow")
        tc.assertEqual(c.agent_id, m.agent_id)
        tc.assertTrue(m.not_before <= c.ts < m.expires_at, "charge made outside the mandate's validity")
    window, limit = w.config.velocity_window_s, w.config.velocity_max_approvals
    for c in charges:
        in_window = [x for x in charges if c.ts - window < x.ts <= c.ts]
        tc.assertLessEqual(len(in_window), limit, "velocity limit exceeded")
    charge_ids = [c.charge_id for c in charges]
    tc.assertEqual(len(charge_ids), len(set(charge_ids)), "a charge id was used twice")
    tc.assertTrue(w.audit.verify().ok, "audit chain broken")


class RaisingScorer:
    model_version = "raising-1"

    def score(self, features):
        raise RuntimeError("model server on fire")


class OddScorer:
    """Returns whatever it is told to, valid or not."""

    model_version = "odd-1"

    def __init__(self, score: Any, reasons: Any = ()) -> None:
        self._score, self._reasons = score, reasons

    def score(self, features):
        return RiskResult(self._score, self._reasons, self.model_version)  # type: ignore[arg-type]


__all__ = [
    "T0", "ALLOWED", "PER_TXN", "CUMULATIVE", "Clock", "World", "Flip", "RaisingScorer", "OddScorer",
    "StubScorer", "GateConfig", "Outcome", "Code", "assert_denied", "check_no_unauthorized_spend",
    "new_mandate_msg", "resign_mandate", "PROPOSAL_FIELDS", "copy",
]
