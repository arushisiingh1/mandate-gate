"""Day 1, part 1: the deterministic core.

Done when: a signed in-mandate proposal is approved, and a changed amount, a
wrong key or an expired mandate each deny and are logged.
"""

import copy
import unittest

from mandate_gate.audit import GENESIS_HASH
from mandate_gate.gate import Gate

from .helpers import (
    CUMULATIVE,
    PER_TXN,
    T0,
    Code,
    GateConfig,
    Outcome,
    StubScorer,
    World,
    assert_denied,
    check_no_unauthorized_spend,
)


class ApproveHappyPath(unittest.TestCase):
    def test_signed_in_mandate_proposal_is_approved(self):
        w = World()
        d = w.send(amount_cents=2_745)
        self.assertEqual(d.result, Outcome.APPROVE)
        self.assertIsNotNone(d.charge_id)
        self.assertEqual(len(w.charges), 1)
        self.assertEqual(w.charges[0].amount_cents, 2_745)
        check_no_unauthorized_spend(self, w)

    def test_all_checks_run_in_the_documented_order(self):
        w = World(scorer=StubScorer(0.0))
        d = w.send()
        self.assertEqual([c.name for c in d.checks], list(Gate.CHECK_ORDER))
        self.assertTrue(all(c.passed for c in d.checks))

    def test_approval_is_logged_with_everything_the_brief_lists(self):
        w = World(scorer=StubScorer(0.05, version="stub-7"))
        d = w.send()
        body = w.audit.records[-1]["body"]
        self.assertEqual(body["result"], "APPROVE")
        self.assertEqual(body["input_hash"], d.input_hash)
        self.assertEqual([c["name"] for c in body["checks"]], list(Gate.CHECK_ORDER))
        self.assertIn("reason_codes", body)
        self.assertEqual(body["model_version"], "stub-7")
        self.assertIn("risk_review_micro", body["thresholds"])
        self.assertIn("risk_deny_micro", body["thresholds"])
        self.assertEqual(body["risk"]["score_micro"], 50_000)


class ChangedAmountWrongKeyExpiredMandate(unittest.TestCase):
    def test_amount_changed_after_signing_denies_and_is_logged(self):
        w = World()
        msg = w.proposal(amount_cents=2_000)
        msg["payload"]["amount_cents"] = 29_000
        d = w.submit(msg)
        assert_denied(self, d, "BAD_SIGNATURE")
        self.assertEqual(w.audit.records[-1]["body"]["result"], "DENY")
        self.assertEqual(w.charges, ())

    def test_wrong_key_denies_and_is_logged(self):
        w = World()
        d = w.submit(w.sign_fields(w.fields(), key=w.attacker))
        assert_denied(self, d, "BAD_SIGNATURE")
        self.assertIn("BAD_SIGNATURE", w.audit.records[-1]["body"]["reason_codes"])

    def test_expired_mandate_denies_and_is_logged(self):
        w = World(lifetime=600)
        w.clock.advance(601)
        d = w.send()
        assert_denied(self, d, "MANDATE_EXPIRED")
        self.assertEqual(w.audit.records[-1]["body"]["result"], "DENY")

    def test_mandate_expiry_boundary_is_exclusive(self):
        w = World(lifetime=600)
        w.clock.t = T0 + 599
        self.assertEqual(w.send().result, Outcome.APPROVE)
        w.clock.t = T0 + 600  # expires_at itself is already too late
        assert_denied(self, w.send(), "MANDATE_EXPIRED")

    def test_mandate_not_yet_valid(self):
        w = World()
        w.clock.t = T0 - 3600
        assert_denied(self, w.send(), "MANDATE_NOT_YET_VALID")

    def test_missing_mandate(self):
        w = World()
        assert_denied(self, w.send(mandate=None), "MANDATE_MISSING")


class AuthorityBoundaries(unittest.TestCase):
    def test_per_transaction_cap_boundary(self):
        w = World()
        self.assertEqual(w.send(amount_cents=PER_TXN).result, Outcome.APPROVE)
        assert_denied(self, w.send(amount_cents=PER_TXN + 1), "OVER_TXN_CAP")

    def test_cumulative_cap_boundary(self):
        w = World(config=GateConfig(velocity_max_approvals=100))
        for _ in range(CUMULATIVE // PER_TXN):
            self.assertEqual(w.send(amount_cents=PER_TXN).result, Outcome.APPROVE)
        self.assertEqual(w.total(), CUMULATIVE)
        assert_denied(self, w.send(amount_cents=1), "OVER_CUMULATIVE_CAP")
        check_no_unauthorized_spend(self, w)

    def test_denied_proposals_do_not_consume_the_cumulative_cap(self):
        w = World(config=GateConfig(velocity_max_approvals=100))
        for _ in range(5):
            assert_denied(self, w.send(amount_cents=PER_TXN + 1), "OVER_TXN_CAP")
        self.assertEqual(w.total(), 0)
        self.assertEqual(w.send(amount_cents=PER_TXN).result, Outcome.APPROVE)

    def test_category_allowlist(self):
        w = World()
        assert_denied(self, w.send(category="travel"), "CATEGORY_NOT_ALLOWED")
        self.assertEqual(w.send(category="books").result, Outcome.APPROVE)

    def test_currency_must_match_the_mandate(self):
        w = World()
        assert_denied(self, w.send(currency="EUR"), "CURRENCY_MISMATCH")


class FixedOrderStopsAtFirstFailure(unittest.TestCase):
    def test_bad_signature_wins_over_every_later_failure(self):
        w = World()
        # Wrong key AND over the cap AND wrong category AND stale: only the first failure is reported.
        payload = w.fields(amount_cents=PER_TXN * 10, category="travel", timestamp=T0 - 10_000)
        d = w.submit(w.sign_fields(payload, key=w.attacker))
        self.assertEqual(d.reason_codes, ("BAD_SIGNATURE",))
        self.assertEqual([c.name for c in d.checks], ["schema", "signature"])

    def test_checks_after_the_failure_do_not_run(self):
        w = World(scorer=StubScorer(0.0))
        d = w.send(amount_cents=PER_TXN + 1)
        self.assertEqual([c.name for c in d.checks][-1], "authority")
        self.assertNotIn("risk", [c.name for c in d.checks])
        self.assertIsNone(d.risk)

    def test_mandate_is_checked_before_authority(self):
        w = World(lifetime=10)
        w.clock.advance(11)
        d = w.send(amount_cents=PER_TXN * 10)  # would also be over the cap
        self.assertEqual(d.reason_codes, ("MANDATE_EXPIRED",))


class EveryDecisionIsLogged(unittest.TestCase):
    def test_denials_are_logged_too(self):
        w = World()
        w.send()
        w.send(amount_cents=PER_TXN + 1)
        w.send(category="travel")
        w.send(mandate=None)
        self.assertEqual(len(w.audit), 4)  # World.submit also asserts +1 per call
        self.assertEqual([r["body"]["result"] for r in w.audit.records], ["APPROVE", "DENY", "DENY", "DENY"])
        self.assertTrue(w.audit.verify().ok)

    def test_first_record_chains_from_genesis(self):
        w = World()
        w.send()
        self.assertEqual(w.audit.records[0]["prev_hash"], GENESIS_HASH)

    def test_no_audit_record_means_no_spend(self):
        w = World()

        def broken(body):
            raise OSError("disk full")

        w.audit.append = broken  # type: ignore[assignment]
        d = w.gate.evaluate(w.proposal(), w.mandate_msg)
        self.assertEqual(d.result, Outcome.DENY)
        self.assertEqual(d.reason_codes, (Code.INTERNAL_ERROR.value,))
        self.assertEqual(w.charges, ())

    def test_unexpected_exception_fails_closed(self):
        w = World()

        def boom(mandate_id):
            raise RuntimeError("ledger exploded")

        w.gate.ledger.exposure = boom  # type: ignore[assignment]
        d = w.send()
        self.assertEqual(d.result, Outcome.DENY)
        self.assertEqual(d.reason_codes, (Code.INTERNAL_ERROR.value,))
        self.assertEqual(w.audit.records[-1]["body"]["result"], "DENY")


class GateNeverRaises(unittest.TestCase):
    def test_garbage_inputs_are_denied_not_raised(self):
        w = World()
        junk = [None, 42, "text", [], {}, {"payload": 1}, {"payload": {}, "signature": 5, "signer": "x"}, object(), b"bytes", {1, 2}]
        for item in junk:
            with self.subTest(item=repr(item)[:40]):
                before = len(w.audit)
                d = w.gate.evaluate(item, w.mandate_msg)
                self.assertEqual(d.result, Outcome.DENY)
                self.assertEqual(len(w.audit), before + 1)
        self.assertEqual(w.charges, ())


class GateConfigValidation(unittest.TestCase):
    def test_rejects_nonsense(self):
        for kwargs in (
            {"replay_window_s": 0},
            {"velocity_max_approvals": -1},
            {"velocity_window_s": True},
            {"review_ttl_s": 1.5},
            {"risk_review_threshold": 0.9, "risk_deny_threshold": 0.3},
            {"risk_review_threshold": 0.0},
            {"risk_deny_threshold": 1.5},
        ):
            with self.subTest(**kwargs):
                with self.assertRaises(ValueError):
                    GateConfig(**kwargs)

    def test_thresholds_are_logged_as_integers(self):
        cfg = GateConfig(risk_review_threshold=0.25, risk_deny_threshold=0.75)
        self.assertEqual(cfg.to_log()["risk_review_micro"], 250_000)
        self.assertTrue(all(isinstance(v, int) for v in cfg.to_log().values()))


if __name__ == "__main__":
    unittest.main()
