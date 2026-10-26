"""The deterministic gate.

An agent proposes; this code decides. Checks run in a fixed order and stop at
the first failure. The agent never sees the thresholds and cannot change them.

Invariants (each has tests, and the attack suite tries to break them):

1. Fail closed. Any unexpected exception becomes a DENY, never an approval and
   never an exception to the caller.
2. The risk score can only make a decision stricter. It runs only after every
   rule check passed, and its result is combined with ``stricter``.
3. No audit record, no spend. The record is written *before* any state change
   (charge, reservation, idempotency entry) is applied.
4. A human approval is bound to the exact proposal it was given for
   (``payload_hash``), is single use, and re-checks the mandate when it is used.
5. Every decision, denials included, is appended to the hash-chained log.
"""

from __future__ import annotations

import hmac
import json
import math
import threading
import time
from dataclasses import dataclass, field, replace
from typing import Any, Callable, Dict, List, Optional, Tuple

from .audit import AuditLog
from .canonical import hash_obj, sha256_hex
from .codes import Code, Outcome
from .envelope import parse_envelope
from .ledger import AgentHistory, Charge, Ledger, Reservation
from .mandate import Mandate, MandateError, parse_mandate
from .proposal import Proposal, ProposalError, intent_hash, parse_proposal
from .registry import KeyRegistry
from .risk.features import build_features
from .signing import DOMAIN_MANDATE, DOMAIN_PROPOSAL, verify
from .validation import ID_RE, ValidationError


# ---------------------------------------------------------------------------
# Configuration and result types
# ---------------------------------------------------------------------------


def _micro(x: float) -> int:
    return int(round(x * 1_000_000))


@dataclass(frozen=True)
class GateConfig:
    replay_window_s: int = 120
    velocity_max_approvals: int = 5
    velocity_window_s: int = 3600
    review_ttl_s: int = 3600
    risk_review_threshold: float = 0.30  # at or above: send to a human
    risk_deny_threshold: float = 0.90  # at or above: deny

    def __post_init__(self) -> None:
        for name in ("replay_window_s", "velocity_max_approvals", "velocity_window_s", "review_ttl_s"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ValueError(f"{name} must be a positive integer")
        lo, hi = self.risk_review_threshold, self.risk_deny_threshold
        if not (0.0 < lo < hi <= 1.0):
            raise ValueError("need 0 < risk_review_threshold < risk_deny_threshold <= 1")

    def to_log(self) -> Dict[str, int]:
        """Integer-only view for the audit log (the canonical encoding bans floats)."""
        return {
            "replay_window_s": self.replay_window_s,
            "velocity_max_approvals": self.velocity_max_approvals,
            "velocity_window_s": self.velocity_window_s,
            "review_ttl_s": self.review_ttl_s,
            "risk_review_micro": _micro(self.risk_review_threshold),
            "risk_deny_micro": _micro(self.risk_deny_threshold),
        }


@dataclass(frozen=True)
class CheckResult:
    name: str
    passed: bool
    code: Optional[str] = None
    detail: str = ""


@dataclass(frozen=True)
class RiskInfo:
    score_micro: Optional[int]  # None when the scorer was unavailable
    reasons: Tuple[str, ...]
    model_version: str


@dataclass(frozen=True)
class Decision:
    result: Outcome
    reason_codes: Tuple[str, ...]
    checks: Tuple[CheckResult, ...]
    input_hash: str
    payload_hash: Optional[str] = None
    risk: Optional[RiskInfo] = None
    charge_id: Optional[str] = None
    review_id: Optional[str] = None
    idempotent_replay: bool = False

    @property
    def approved(self) -> bool:
        return self.result is Outcome.APPROVE


@dataclass(frozen=True)
class PendingReviewView:
    """What a human reviewer is shown. The payload_hash is the approval token."""

    review_id: str
    payload_hash: str
    agent_id: str
    mandate_id: str
    merchant: str
    category: str
    amount_cents: int
    item: str
    risk: Optional[RiskInfo]


# ---------------------------------------------------------------------------
# Internal state
# ---------------------------------------------------------------------------


@dataclass
class _Fail:
    code: Code
    detail: str
    outcome: Outcome = Outcome.DENY
    replay_of: Optional["_IdemEntry"] = None


@dataclass
class _IdemEntry:
    intent_hash: str
    decision: Decision


@dataclass
class _Pending:
    review_id: str
    proposal: Proposal
    mandate: Mandate
    payload_hash: str
    created_ts: int
    risk: Optional[RiskInfo]
    entry: _IdemEntry


@dataclass
class _Ctx:
    now: int
    proposal_msg: Any
    mandate_msg: Any
    input_hash: str
    detail: str = ""
    proposal: Optional[Proposal] = None
    proposal_payload: Optional[Dict[str, Any]] = None
    signature: str = ""
    signer: str = ""
    payload_hash: Optional[str] = None
    intent: Optional[str] = None
    mandate: Optional[Mandate] = None
    idem_key: Optional[Tuple[str, str]] = None
    reached_risk: bool = False
    risk: Optional[RiskInfo] = None
    checks: List[CheckResult] = field(default_factory=list)
    effects: List[Callable[[], None]] = field(default_factory=list)


def _safe_hash(obj: Any) -> str:
    """Hash the exact input if it is canonicalisable; otherwise hash its repr."""
    try:
        return hash_obj(obj)
    except Exception:
        return "unhashable:" + sha256_hex(repr(obj)[:4096].encode("utf-8", "replace"))


def _short(text: str, n: int = 120) -> str:
    return text[:n]


def _snapshot(obj: Any) -> Any:
    """Copy untrusted input into plain JSON data exactly once.

    The gate verifies a signature over one object and then reads fields from it.
    If the caller still holds a reference (another thread, or a dict subclass
    that answers differently the second time it is read) the bytes that were
    verified could differ from the bytes that were used. Round-tripping through
    JSON yields plain dict/list/str/int values that nobody else can mutate.
    Raises for anything that is not JSON data.
    """
    return json.loads(json.dumps(obj, allow_nan=False))


# ---------------------------------------------------------------------------
# The gate
# ---------------------------------------------------------------------------


class Gate:
    CHECK_ORDER = (
        "schema",
        "signature",
        "mandate",
        "replay",
        "duplicate",
        "authority",
        "velocity",
        "risk",
    )

    def __init__(
        self,
        registry: KeyRegistry,
        audit: AuditLog,
        config: Optional[GateConfig] = None,
        clock: Callable[[], float] = time.time,
        scorer: Any = None,
        ledger: Optional[Ledger] = None,
    ) -> None:
        self._registry = registry
        self._audit = audit
        self._cfg = config or GateConfig()
        self._clock = clock
        self._scorer = scorer
        self._ledger = ledger or Ledger()
        version = getattr(scorer, "model_version", None)
        self._model_version = _short(str(version), 64) if version is not None else None
        self._nonces: Dict[Tuple[str, str], int] = {}
        self._idem: Dict[Tuple[str, str], _IdemEntry] = {}
        self._pending: Dict[str, _Pending] = {}
        self._histories: Dict[str, AgentHistory] = {}
        self._revoked_mandates: set = set()
        self._seq = 0
        self._lock = threading.RLock()

    # --- public surface ----------------------------------------------------
    @property
    def ledger(self) -> Ledger:
        return self._ledger

    @property
    def audit(self) -> AuditLog:
        return self._audit

    @property
    def config(self) -> GateConfig:
        return self._cfg

    def evaluate(self, proposal_msg: Any, mandate_msg: Any) -> Decision:
        """Decide one proposal. Never raises."""
        with self._lock:
            now = self._now()
            try:
                proposal_msg, mandate_msg = _snapshot(proposal_msg), _snapshot(mandate_msg)
                input_hash = _safe_hash({"proposal": proposal_msg, "mandate": mandate_msg})
            except Exception:
                # Not plain JSON data. Deny it as malformed; hash what we can.
                try:
                    input_hash = _safe_hash(repr((proposal_msg, mandate_msg))[:4096])
                except Exception:
                    input_hash = "unhashable:" + sha256_hex(b"")
                proposal_msg, mandate_msg = None, None
            ctx = _Ctx(
                now=now,
                proposal_msg=proposal_msg,
                mandate_msg=mandate_msg,
                input_hash=input_hash,
            )
            self._prune_nonces(now)
            try:
                decision = self._run(ctx)
            except Exception as exc:  # invariant 1: fail closed
                decision = self._internal_error(ctx, exc)
                ctx.effects = []

            body = self._body("decision", now, decision, self._summary(ctx))
            try:
                self._audit.append(body)  # invariant 3: log first, then act
            except Exception as exc:
                decision = self._internal_error(ctx, exc, audit_failed=True)
                ctx.effects = []
                try:
                    self._audit.append(self._body("decision", now, decision, self._summary(ctx)))
                except Exception:
                    pass  # still denied; nothing was committed
            else:
                for effect in ctx.effects:
                    effect()
            return decision

    def resolve_review(
        self, review_id: str, approve: bool, approver: str, payload_hash: str
    ) -> Decision:
        """Apply a human decision to a pending review. Never raises.

        ``payload_hash`` is the token the reviewer was shown with the proposal.
        It must match the stored proposal exactly, so an approval cannot be
        moved onto a different or altered proposal.
        """
        with self._lock:
            now = self._now()
            input_hash = _safe_hash(
                {
                    "review_id": _short(str(review_id), 80),
                    "approve": bool(approve),
                    "approver": _short(str(approver), 80),
                    "payload_hash": _short(str(payload_hash), 80),
                }
            )
            effects: List[Callable[[], None]] = []
            try:
                decision, effects = self._resolve(
                    now, review_id, approve, approver, payload_hash, input_hash
                )
            except Exception as exc:
                decision = Decision(
                    Outcome.DENY,
                    (Code.INTERNAL_ERROR.value,),
                    (CheckResult("human_review", False, Code.INTERNAL_ERROR.value, type(exc).__name__),),
                    input_hash,
                )
                effects = []
            extra = {
                "review_id": review_id if isinstance(review_id, str) else None,
                "approver": approver if isinstance(approver, str) and ID_RE.fullmatch(approver) else None,
            }
            try:
                self._audit.append(self._body("review_resolution", now, decision, None, extra))
            except Exception as exc:
                decision = Decision(
                    Outcome.DENY,
                    (Code.INTERNAL_ERROR.value,),
                    (CheckResult("audit", False, Code.INTERNAL_ERROR.value, type(exc).__name__),),
                    input_hash,
                )
                effects = []
            for effect in effects:
                effect()
            return decision

    def pending_reviews(self) -> List[PendingReviewView]:
        with self._lock:
            return [
                PendingReviewView(
                    p.review_id,
                    p.payload_hash,
                    p.proposal.agent_id,
                    p.proposal.mandate_id,
                    p.proposal.merchant,
                    p.proposal.category,
                    p.proposal.amount_cents,
                    p.proposal.item,
                    p.risk,
                )
                for p in self._pending.values()
            ]

    def record_rejected_output(self, raw_output: Any, reason: str) -> None:
        """Log agent output that failed the strict schema before it was signed.

        Such output never becomes a proposal, so ``evaluate`` never sees it, but
        a denial that leaves no trace would break "every decision is logged".
        Only a hash of the raw text is stored, not the text itself.
        """
        with self._lock:
            try:
                digest = sha256_hex(str(raw_output).encode("utf-8", "replace")[:4096])
            except Exception:
                digest = sha256_hex(b"")
            self._audit.append(
                {
                    "type": "agent_output_rejected",
                    "ts": self._now(),
                    "result": Outcome.DENY.value,
                    "reason_codes": [Code.MALFORMED.value],
                    "output_sha256": digest,
                    "detail": _short(str(reason), 160),
                }
            )

    def revoke_mandate(self, mandate_id: str) -> None:
        with self._lock:
            self._revoked_mandates.add(mandate_id)
            self._audit.append(
                {
                    "type": "mandate_revocation",
                    "ts": self._now(),
                    "mandate_id": _short(str(mandate_id), 64),
                }
            )

    # --- pipeline ------------------------------------------------------------
    def _run(self, ctx: _Ctx) -> Decision:
        for name in self.CHECK_ORDER:
            fail = getattr(self, f"_check_{name}")(ctx)
            detail, ctx.detail = ctx.detail, ""
            if fail is None:
                ctx.checks.append(CheckResult(name, True, None, detail))
                continue
            if fail.replay_of is not None:
                # A legitimate retry: hand back the original decision.
                ctx.checks.append(CheckResult(name, True, Code.IDEMPOTENT_REPLAY.value, fail.detail))
                # Same outcome, charge_id and review_id as the original (so no
                # second charge), but this attempt's own input hash and checks.
                return replace(
                    fail.replay_of.decision,
                    idempotent_replay=True,
                    input_hash=ctx.input_hash,
                    checks=tuple(ctx.checks),
                )
            ctx.checks.append(CheckResult(name, False, fail.code.value, fail.detail))
            return self._finalize(ctx, fail.outcome, (fail.code,))
        return self._finalize(ctx, Outcome.APPROVE, ())

    # 1 ----------------------------------------------------------------------
    def _check_schema(self, ctx: _Ctx) -> Optional[_Fail]:
        try:
            payload, signature, signer = parse_envelope(ctx.proposal_msg, "proposal message")
            proposal = parse_proposal(payload)
        except ValidationError as exc:
            return _Fail(Code.MALFORMED, _short(str(exc)))
        ctx.proposal_payload = payload
        ctx.signature = signature
        ctx.signer = signer
        ctx.proposal = proposal
        ctx.payload_hash = hash_obj(payload)
        ctx.intent = intent_hash(proposal)
        return None

    # 2 ----------------------------------------------------------------------
    def _check_signature(self, ctx: _Ctx) -> Optional[_Fail]:
        p = ctx.proposal
        assert p is not None
        if ctx.signer != p.agent_id:
            return _Fail(Code.BAD_SIGNATURE, "signer does not match agent_id")
        status, key = self._registry.lookup(p.agent_id, "agent")
        if status in ("unknown", "wrong_kind"):
            return _Fail(Code.UNKNOWN_AGENT, "agent is not a registered agent key")
        if status == "revoked":
            return _Fail(Code.AGENT_REVOKED, "agent key revoked")
        if not verify(key, DOMAIN_PROPOSAL, ctx.proposal_payload, ctx.signature):
            return _Fail(Code.BAD_SIGNATURE, "proposal signature does not verify")
        return None

    # 3 ----------------------------------------------------------------------
    def _check_mandate(self, ctx: _Ctx) -> Optional[_Fail]:
        p = ctx.proposal
        assert p is not None
        if ctx.mandate_msg is None:
            return _Fail(Code.MANDATE_MISSING, "no mandate supplied")
        try:
            payload, signature, signer = parse_envelope(ctx.mandate_msg, "mandate message")
        except ValidationError as exc:
            return _Fail(Code.MANDATE_MALFORMED, _short(str(exc)))
        status, key = self._registry.lookup(signer, "user")
        if status != "ok":
            return _Fail(Code.MANDATE_UNKNOWN_SIGNER, f"mandate signer not usable ({status})")
        # Verify BEFORE interpreting anything inside the payload.
        if not verify(key, DOMAIN_MANDATE, payload, signature):
            return _Fail(Code.MANDATE_BAD_SIGNATURE, "mandate signature does not verify")
        try:
            mandate = parse_mandate(payload)
        except MandateError as exc:
            return _Fail(Code.MANDATE_MALFORMED, _short(str(exc)))
        if mandate.user_id != signer:
            return _Fail(Code.MANDATE_SIGNER_MISMATCH, "mandate user_id differs from signer")
        if mandate.mandate_id != p.mandate_id:
            return _Fail(Code.MANDATE_ID_MISMATCH, "proposal names a different mandate")
        if mandate.agent_id != p.agent_id:
            return _Fail(Code.MANDATE_AGENT_MISMATCH, "mandate does not name this agent")
        if mandate.mandate_id in self._revoked_mandates:
            return _Fail(Code.MANDATE_REVOKED, "mandate revoked")
        if ctx.now < mandate.not_before:
            return _Fail(Code.MANDATE_NOT_YET_VALID, "mandate not yet valid")
        if ctx.now >= mandate.expires_at:
            return _Fail(Code.MANDATE_EXPIRED, "mandate expired")
        ctx.mandate = mandate
        return None

    # 4 ----------------------------------------------------------------------
    def _check_replay(self, ctx: _Ctx) -> Optional[_Fail]:
        p = ctx.proposal
        assert p is not None
        if abs(ctx.now - p.timestamp) > self._cfg.replay_window_s:
            return _Fail(Code.STALE_TIMESTAMP, "timestamp outside the allowed window")
        key = (p.agent_id, p.nonce)
        if key in self._nonces:
            return _Fail(Code.REPLAY, "nonce already used")
        # Consumed immediately, even if a later check denies: each signed
        # message is good for exactly one evaluation.
        self._nonces[key] = ctx.now
        return None

    # 5 ----------------------------------------------------------------------
    def _check_duplicate(self, ctx: _Ctx) -> Optional[_Fail]:
        p = ctx.proposal
        assert p is not None
        key = (p.agent_id, p.idempotency_key)
        entry = self._idem.get(key)
        if entry is not None:
            if entry.intent_hash == ctx.intent:
                return _Fail(Code.IDEMPOTENT_REPLAY, "same intent retried", replay_of=entry)
            return _Fail(Code.IDEMPOTENCY_CONFLICT, "idempotency key reused for a different intent")
        ctx.idem_key = key
        return None

    # 6 ----------------------------------------------------------------------
    def _check_authority(self, ctx: _Ctx) -> Optional[_Fail]:
        p, m = ctx.proposal, ctx.mandate
        assert p is not None and m is not None
        if p.category not in m.allowed_categories:
            return _Fail(Code.CATEGORY_NOT_ALLOWED, "category not on the mandate allowlist")
        if p.currency != m.currency:
            return _Fail(Code.CURRENCY_MISMATCH, "currency differs from the mandate")
        if p.amount_cents > m.per_txn_cap_cents:
            return _Fail(Code.OVER_TXN_CAP, "amount exceeds the per-transaction cap")
        if self._ledger.exposure(m.mandate_id) + p.amount_cents > m.cumulative_cap_cents:
            return _Fail(Code.OVER_CUMULATIVE_CAP, "amount would exceed the cumulative cap")
        return None

    # 7 ----------------------------------------------------------------------
    def _check_velocity(self, ctx: _Ctx) -> Optional[_Fail]:
        m = ctx.mandate
        assert m is not None
        since = ctx.now - self._cfg.velocity_window_s
        if self._ledger.in_window_count(m.mandate_id, since) >= self._cfg.velocity_max_approvals:
            return _Fail(Code.VELOCITY, "too many approvals in the window")
        return None

    # 8 ----------------------------------------------------------------------
    def _check_risk(self, ctx: _Ctx) -> Optional[_Fail]:
        """Advisory score. Only ever moves a decision toward REVIEW or DENY."""
        p, m = ctx.proposal, ctx.mandate
        assert p is not None and m is not None
        ctx.reached_risk = True
        if self._scorer is None:
            ctx.detail = "skipped: no scorer configured"
            return None
        history = self._histories.get(p.agent_id)
        snap = (history or AgentHistory()).snapshot(ctx.now, p.merchant)
        features = build_features(
            amount_cents=p.amount_cents,
            per_txn_cap_cents=m.per_txn_cap_cents,
            remaining_cap_cents=m.cumulative_cap_cents - self._ledger.exposure(m.mandate_id),
            ts=ctx.now,
            category=p.category,
            new_merchant=snap.new_merchant,
            secs_since_last=snap.secs_since_last,
            txns_last_hour=snap.txns_last_hour,
            agent_mean_amount=snap.mean_amount,
        )
        version = _short(str(self._model_version or "unknown"), 64)
        try:
            result = self._scorer.score(features)
            score = result.score
            if (
                isinstance(score, bool)
                or not isinstance(score, (int, float))
                or not math.isfinite(score)
                or not (0.0 <= score <= 1.0)
            ):
                raise ValueError("score outside [0, 1]")
            reasons = tuple(_short(str(r), 80) for r in list(result.reasons)[:3])
            version = _short(str(result.model_version), 64)
        except Exception:
            # An unavailable or misbehaving scorer must tighten, never loosen.
            ctx.risk = RiskInfo(None, (), version)
            return _Fail(Code.RISK_UNAVAILABLE, "scorer failed or returned an invalid score", Outcome.REVIEW)

        ctx.risk = RiskInfo(_micro(score), reasons, version)
        ctx.detail = f"score_micro={ctx.risk.score_micro}"
        if score >= self._cfg.risk_deny_threshold:
            return _Fail(Code.RISK_DENY, f"score_micro={ctx.risk.score_micro} at or above deny threshold")
        if score >= self._cfg.risk_review_threshold:
            return _Fail(Code.RISK_REVIEW, f"score_micro={ctx.risk.score_micro} at or above review threshold", Outcome.REVIEW)
        return None

    # --- decision assembly -------------------------------------------------
    def _finalize(self, ctx: _Ctx, outcome: Outcome, codes: Tuple[Code, ...]) -> Decision:
        charge_id = review_id = None
        if outcome is Outcome.APPROVE:
            charge_id = self._next_id("ch")
        elif outcome is Outcome.REVIEW:
            review_id = self._next_id("rv")
        decision = Decision(
            outcome,
            tuple(c.value for c in codes),
            tuple(ctx.checks),
            ctx.input_hash,
            ctx.payload_hash,
            ctx.risk,
            charge_id,
            review_id,
        )
        p, m = ctx.proposal, ctx.mandate
        entry = None
        if ctx.idem_key is not None and ctx.intent is not None:
            entry = _IdemEntry(ctx.intent, decision)
            key = ctx.idem_key
            ctx.effects.append(lambda: self._idem.__setitem__(key, entry))
        if outcome is Outcome.APPROVE:
            assert p is not None and m is not None and charge_id is not None
            charge = Charge(charge_id, m.mandate_id, p.agent_id, p.merchant, p.category, p.amount_cents, ctx.now)
            ctx.effects.append(lambda: self._ledger.commit(charge))
            # History (merchant familiarity, recent activity) is earned only by
            # purchases that actually settle. A proposal that was denied, or is
            # still waiting for a human, must not make a new merchant look known.
            ctx.effects.append(lambda: self._history(charge.agent_id).record(ctx.now, charge.merchant, charge.amount_cents))
        elif outcome is Outcome.REVIEW:
            assert p is not None and m is not None and review_id is not None and entry is not None
            assert ctx.payload_hash is not None
            reservation = Reservation(review_id, m.mandate_id, p.agent_id, p.merchant, p.category, p.amount_cents, ctx.now)
            pending = _Pending(review_id, p, m, ctx.payload_hash, ctx.now, ctx.risk, entry)

            def hold() -> None:
                self._ledger.reserve(reservation)
                self._pending[pending.review_id] = pending

            ctx.effects.append(hold)
        return decision

    def _internal_error(self, ctx: _Ctx, exc: Exception, audit_failed: bool = False) -> Decision:
        name = "audit" if audit_failed else "internal"
        checks = tuple(ctx.checks) + (CheckResult(name, False, Code.INTERNAL_ERROR.value, type(exc).__name__),)
        return Decision(
            Outcome.DENY,
            (Code.INTERNAL_ERROR.value,),
            checks,
            ctx.input_hash,
            ctx.payload_hash,
            None,
        )

    # --- human review ------------------------------------------------------
    def _binding_ok(self, pending: _Pending, payload_hash: Any) -> bool:
        """The approval must name the exact proposal that is pending."""
        return isinstance(payload_hash, str) and hmac.compare_digest(
            payload_hash.encode("utf-8", "replace"), pending.payload_hash.encode("ascii")
        )

    def _resolve(
        self, now: int, review_id: Any, approve: Any, approver: Any, payload_hash: Any, input_hash: str
    ) -> Tuple[Decision, List[Callable[[], None]]]:
        def deny(code: Code, detail: str, pending: Optional[_Pending] = None) -> Decision:
            return Decision(
                Outcome.DENY,
                (code.value,),
                (CheckResult("human_review", False, code.value, detail),),
                input_hash,
                pending.payload_hash if pending else None,
                pending.risk if pending else None,
                None,
                review_id if isinstance(review_id, str) else None,
            )

        pending = self._pending.get(review_id) if isinstance(review_id, str) else None
        if pending is None:
            return deny(Code.REVIEW_NOT_FOUND, "no such pending review (unknown or already used)"), []
        if not isinstance(approver, str) or not ID_RE.fullmatch(approver):
            return deny(Code.MALFORMED, "approver id invalid", pending), []
        if not self._binding_ok(pending, payload_hash):
            # The review stays pending: a wrong token must not destroy it.
            return deny(Code.REVIEW_BINDING_MISMATCH, "approval does not match this proposal", pending), []

        # From here the review is consumed whatever the outcome (single use).
        p, m = pending.proposal, pending.mandate

        def consume() -> None:
            self._pending.pop(pending.review_id, None)
            self._ledger.release(pending.review_id)

        def settle(decision: Decision) -> None:
            pending.entry.decision = decision

        def finish(decision: Decision) -> Tuple[Decision, List[Callable[[], None]]]:
            return decision, [consume, lambda: settle(decision)]

        if now > pending.created_ts + self._cfg.review_ttl_s:
            return finish(deny(Code.REVIEW_EXPIRED, "review expired", pending))
        if approve is not True:
            return finish(deny(Code.HUMAN_REJECTED, "rejected by reviewer", pending))
        # A human saying yes does not outrank a key that was revoked while the
        # proposal sat in the queue.
        agent_status, _ = self._registry.lookup(p.agent_id, "agent")
        if agent_status != "ok":
            code = Code.AGENT_REVOKED if agent_status == "revoked" else Code.UNKNOWN_AGENT
            return finish(deny(code, "agent key no longer valid while pending", pending))
        user_status, _ = self._registry.lookup(m.user_id, "user")
        if user_status != "ok":
            return finish(deny(Code.MANDATE_UNKNOWN_SIGNER, "mandate signer key no longer valid while pending", pending))
        if m.mandate_id in self._revoked_mandates:
            return finish(deny(Code.MANDATE_REVOKED, "mandate revoked while pending", pending))
        if now >= m.expires_at:
            return finish(deny(Code.MANDATE_EXPIRED, "mandate expired while pending", pending))
        if self._ledger.committed_total(m.mandate_id) + p.amount_cents > m.cumulative_cap_cents:
            return finish(deny(Code.OVER_CUMULATIVE_CAP, "cap exhausted while pending", pending))

        charge_id = self._next_id("ch")
        charge = Charge(charge_id, m.mandate_id, p.agent_id, p.merchant, p.category, p.amount_cents, now, pending.review_id)
        decision = Decision(
            Outcome.APPROVE,
            (Code.HUMAN_APPROVED.value,),
            (CheckResult("human_review", True, Code.HUMAN_APPROVED.value, ""),),
            input_hash,
            pending.payload_hash,
            pending.risk,
            charge_id,
            pending.review_id,
        )
        return decision, [
            consume,
            lambda: self._ledger.commit(charge),
            lambda: self._history(p.agent_id).record(now, p.merchant, p.amount_cents),
            lambda: settle(decision),
        ]

    # --- helpers -----------------------------------------------------------
    def _now(self) -> int:
        return int(self._clock())

    def _next_id(self, prefix: str) -> str:
        self._seq += 1
        return f"{prefix}_{self._seq:06d}"

    def _history(self, agent_id: str) -> AgentHistory:
        history = self._histories.get(agent_id)
        if history is None:
            history = self._histories[agent_id] = AgentHistory()
        return history

    def _prune_nonces(self, now: int) -> None:
        if len(self._nonces) <= 1000:
            return
        # A nonce only needs remembering while its timestamp could still pass.
        cutoff = now - 2 * self._cfg.replay_window_s
        self._nonces = {k: v for k, v in self._nonces.items() if v >= cutoff}

    def _summary(self, ctx: _Ctx) -> Optional[Dict[str, Any]]:
        p = ctx.proposal
        if p is None:
            return None
        return {
            "agent_id": p.agent_id,
            "mandate_id": p.mandate_id,
            "merchant": p.merchant,
            "category": p.category,
            "amount_cents": p.amount_cents,
            "currency": p.currency,
        }

    def _body(
        self,
        kind: str,
        now: int,
        decision: Decision,
        summary: Optional[Dict[str, Any]],
        extra: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        risk = None
        if decision.risk is not None:
            risk = {
                "score_micro": decision.risk.score_micro,
                "reasons": list(decision.risk.reasons),
                "model_version": decision.risk.model_version,
            }
        body: Dict[str, Any] = {
            "type": kind,
            "ts": now,
            "input_hash": decision.input_hash,
            "payload_hash": decision.payload_hash,
            "result": decision.result.value,
            "reason_codes": list(decision.reason_codes),
            "checks": [
                {"name": c.name, "passed": c.passed, "code": c.code, "detail": c.detail}
                for c in decision.checks
            ],
            "risk": risk,
            "model_version": self._model_version,
            "thresholds": self._cfg.to_log(),
            "summary": summary,
            "charge_id": decision.charge_id,
            "review_id": decision.review_id,
            "idempotent_replay": decision.idempotent_replay,
        }
        if extra:
            body.update(extra)
        return body
