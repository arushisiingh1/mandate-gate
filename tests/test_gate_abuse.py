"""Day 1, part 2: replay, duplicate, velocity and the human-approval queue."""

import unittest

from .helpers import (
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


class Replay(unittest.TestCase):
    def test_exact_resend_is_a_replay(self):
        w = World()
        msg = w.proposal()
        self.assertEqual(w.submit(msg).result, Outcome.APPROVE)
        assert_denied(self, w.submit(msg), "REPLAY")
        self.assertEqual(len(w.charges), 1)

    def test_replay_of_a_denied_message_is_also_a_replay(self):
        w = World()
        msg = w.proposal(amount_cents=PER_TXN + 1)
        assert_denied(self, w.submit(msg), "OVER_TXN_CAP")
        assert_denied(self, w.submit(msg), "REPLAY")  # the nonce was consumed by the first attempt

    def test_timestamp_window(self):
        w = World()
        window = w.config.replay_window_s
        self.assertEqual(w.send(timestamp=T0 - window).result, Outcome.APPROVE)
        assert_denied(self, w.send(timestamp=T0 - window - 1), "STALE_TIMESTAMP")
        assert_denied(self, w.send(timestamp=T0 + window + 1), "STALE_TIMESTAMP")

    def test_nonces_are_per_agent_namespace_and_survive_other_traffic(self):
        w = World(config=GateConfig(velocity_max_approvals=100))
        msg = w.proposal()
        w.submit(msg)
        for _ in range(20):
            w.send()
        assert_denied(self, w.submit(msg), "REPLAY")

    def test_old_nonces_are_pruned_but_cannot_come_back(self):
        w = World(config=GateConfig(velocity_max_approvals=100_000), lifetime=10**7)
        old = w.proposal()
        w.submit(old)
        # Push the nonce table past the pruning size, far later in time.
        w.clock.advance(10 * w.config.replay_window_s)
        for _ in range(1100):
            w.send()
        old_key = (w.agent_id, old["payload"]["nonce"])
        self.assertNotIn(old_key, w.gate._nonces)  # the old nonce was pruned
        assert_denied(self, w.submit(old), "STALE_TIMESTAMP")  # and the old message is still dead


class Duplicate(unittest.TestCase):
    def test_retry_with_fresh_nonce_returns_original_and_charges_once(self):
        w = World()
        first = w.send(idempotency_key="idem-order-0001", amount_cents=2_745)
        retry = w.send(idempotency_key="idem-order-0001", amount_cents=2_745)
        self.assertEqual(first.result, Outcome.APPROVE)
        self.assertEqual(retry.result, Outcome.APPROVE)
        self.assertTrue(retry.idempotent_replay)
        self.assertEqual(retry.charge_id, first.charge_id)
        self.assertEqual(len(w.charges), 1)

    def test_a_retry_of_a_denial_returns_the_denial(self):
        w = World()
        first = w.send(idempotency_key="idem-order-0002", amount_cents=PER_TXN + 1)
        retry = w.send(idempotency_key="idem-order-0002", amount_cents=PER_TXN + 1)
        assert_denied(self, first, "OVER_TXN_CAP")
        self.assertEqual(retry.reason_codes, first.reason_codes)
        self.assertTrue(retry.idempotent_replay)

    def test_same_key_different_intent_is_a_conflict_not_a_retry(self):
        w = World()
        w.send(idempotency_key="idem-order-0003", amount_cents=2_000)
        assert_denied(self, w.send(idempotency_key="idem-order-0003", amount_cents=9_000), "IDEMPOTENCY_CONFLICT")
        assert_denied(self, w.send(idempotency_key="idem-order-0003", amount_cents=2_000, merchant="other.example"), "IDEMPOTENCY_CONFLICT")
        self.assertEqual(len(w.charges), 1)

    def test_replay_is_checked_before_duplicate(self):
        w = World()
        msg = w.proposal(idempotency_key="idem-order-0004")
        w.submit(msg)
        # The identical message again is an attacker's replay, not a retry.
        assert_denied(self, w.submit(msg), "REPLAY")

    def test_unauthenticated_traffic_cannot_squat_an_idempotency_key(self):
        w = World()
        bad = w.sign_fields(w.fields(idempotency_key="idem-order-0005", amount_cents=100), key=w.attacker)
        assert_denied(self, w.submit(bad), "BAD_SIGNATURE")
        good = w.send(idempotency_key="idem-order-0005", amount_cents=2_000)
        self.assertEqual(good.result, Outcome.APPROVE)

    def test_idempotency_keys_are_scoped_to_the_agent(self):
        w = World()
        other = World()
        a = w.send(idempotency_key="idem-shared-key-1")
        b = other.send(idempotency_key="idem-shared-key-1")
        self.assertEqual((a.result, b.result), (Outcome.APPROVE, Outcome.APPROVE))
        self.assertFalse(b.idempotent_replay)


class Velocity(unittest.TestCase):
    def test_split_purchase_is_stopped(self):
        # One $4,000 purchase as twenty $199 purchases.
        w = World(per_txn=20_000, cumulative=400_000)
        results = [w.send(amount_cents=19_900).result for _ in range(20)]
        approved = results.count(Outcome.APPROVE)
        self.assertEqual(approved, w.config.velocity_max_approvals)
        self.assertLess(w.total(), 400_000)
        check_no_unauthorized_spend(self, w)

    def test_velocity_denial_code(self):
        w = World()
        for _ in range(w.config.velocity_max_approvals):
            w.send()
        assert_denied(self, w.send(), "VELOCITY")

    def test_window_slides(self):
        w = World()
        for _ in range(w.config.velocity_max_approvals):
            w.send()
        w.clock.advance(w.config.velocity_window_s + 1)
        self.assertEqual(w.send().result, Outcome.APPROVE)

    def test_splitting_across_idempotency_keys_does_not_help(self):
        w = World()
        outcomes = [w.send(idempotency_key=f"idem-split-{i:04d}", amount_cents=19_900).result for i in range(12)]
        self.assertEqual(outcomes.count(Outcome.APPROVE), w.config.velocity_max_approvals)


class HumanReview(unittest.TestCase):
    def world(self, **kw):
        return World(scorer=StubScorer(0.5, reasons=("TEST_REASON",)), **kw)

    def queue_one(self, w, **over):
        d = w.send(**over)
        self.assertEqual(d.result, Outcome.REVIEW)
        self.assertIsNotNone(d.review_id)
        self.assertEqual(w.charges, ())  # nothing is charged while waiting
        return d, w.gate.pending_reviews()[-1]

    def test_middle_score_goes_to_a_human_and_approval_charges_once(self):
        w = self.world()
        d, view = self.queue_one(w)
        self.assertEqual(view.payload_hash, d.payload_hash)
        r = w.gate.resolve_review(view.review_id, True, "reviewer-1", view.payload_hash)
        self.assertEqual(r.result, Outcome.APPROVE)
        self.assertIn("HUMAN_APPROVED", r.reason_codes)
        self.assertEqual(len(w.charges), 1)
        self.assertEqual(w.gate.pending_reviews(), [])

    def test_approval_is_single_use(self):
        w = self.world()
        _, view = self.queue_one(w)
        w.gate.resolve_review(view.review_id, True, "reviewer-1", view.payload_hash)
        again = w.gate.resolve_review(view.review_id, True, "reviewer-1", view.payload_hash)
        assert_denied(self, again, "REVIEW_NOT_FOUND")
        self.assertEqual(len(w.charges), 1)

    def test_approval_for_one_proposal_cannot_be_used_on_another(self):
        w = self.world()
        _, small = self.queue_one(w, amount_cents=2_000)
        _, large = self.queue_one(w, amount_cents=29_000)
        wrong = w.gate.resolve_review(large.review_id, True, "reviewer-1", small.payload_hash)
        assert_denied(self, wrong, "REVIEW_BINDING_MISMATCH")
        self.assertEqual(w.charges, ())
        # ...and the large review is still pending, not destroyed by the bad token.
        self.assertIn(large.review_id, [v.review_id for v in w.gate.pending_reviews()])

    def test_altered_amount_needs_its_own_review(self):
        w = self.world()
        d, view = self.queue_one(w, idempotency_key="idem-hr-000001", amount_cents=10_000)
        w.gate.resolve_review(view.review_id, True, "reviewer-1", view.payload_hash)
        altered = w.send(idempotency_key="idem-hr-000001", amount_cents=29_000)
        assert_denied(self, altered, "IDEMPOTENCY_CONFLICT")
        fresh = w.send(amount_cents=29_000)
        self.assertEqual(fresh.result, Outcome.REVIEW)  # not inherited from the earlier approval
        self.assertEqual(w.total(), 10_000)

    def test_retry_after_approval_does_not_charge_again(self):
        w = self.world()
        _, view = self.queue_one(w, idempotency_key="idem-hr-000002")
        w.gate.resolve_review(view.review_id, True, "reviewer-1", view.payload_hash)
        retry = w.send(idempotency_key="idem-hr-000002")
        self.assertTrue(retry.idempotent_replay)
        self.assertEqual(retry.result, Outcome.APPROVE)
        self.assertEqual(len(w.charges), 1)

    def test_retry_while_pending_does_not_queue_a_second_review(self):
        w = self.world()
        self.queue_one(w, idempotency_key="idem-hr-000003")
        retry = w.send(idempotency_key="idem-hr-000003")
        self.assertEqual(retry.result, Outcome.REVIEW)
        self.assertTrue(retry.idempotent_replay)
        self.assertEqual(len(w.gate.pending_reviews()), 1)

    def test_rejection_denies_and_releases_the_reservation(self):
        w = self.world()
        _, view = self.queue_one(w, amount_cents=29_000)
        self.assertEqual(w.gate.ledger.reserved_total(w.mandate_id), 29_000)
        r = w.gate.resolve_review(view.review_id, False, "reviewer-1", view.payload_hash)
        assert_denied(self, r, "HUMAN_REJECTED")
        self.assertEqual(w.gate.ledger.reserved_total(w.mandate_id), 0)

    def test_only_a_real_true_approves(self):
        for value in ("yes", 1, "true", None, [True]):
            with self.subTest(value=value):
                w = self.world()
                _, view = self.queue_one(w)
                r = w.gate.resolve_review(view.review_id, value, "reviewer-1", view.payload_hash)  # type: ignore[arg-type]
                self.assertNotEqual(r.result, Outcome.APPROVE)
                self.assertEqual(w.charges, ())

    def test_invalid_approver_id_is_refused(self):
        w = self.world()
        _, view = self.queue_one(w)
        r = w.gate.resolve_review(view.review_id, True, "bad approver\n", view.payload_hash)
        self.assertEqual(r.result, Outcome.DENY)
        self.assertEqual(w.charges, ())

    def test_review_expires(self):
        w = self.world()
        _, view = self.queue_one(w)
        w.clock.advance(w.config.review_ttl_s + 1)
        r = w.gate.resolve_review(view.review_id, True, "reviewer-1", view.payload_hash)
        assert_denied(self, r, "REVIEW_EXPIRED")
        self.assertEqual(w.charges, ())

    def test_mandate_expiring_while_pending_blocks_the_approval(self):
        w = self.world(lifetime=600)
        _, view = self.queue_one(w)
        w.clock.advance(700)
        r = w.gate.resolve_review(view.review_id, True, "reviewer-1", view.payload_hash)
        assert_denied(self, r, "MANDATE_EXPIRED")

    def test_revoked_mandate_while_pending_blocks_the_approval(self):
        w = self.world()
        _, view = self.queue_one(w)
        w.gate.revoke_mandate(w.mandate_id)
        r = w.gate.resolve_review(view.review_id, True, "reviewer-1", view.payload_hash)
        assert_denied(self, r, "MANDATE_REVOKED")

    def test_agent_key_revoked_while_pending_blocks_the_approval(self):
        w = self.world()
        _, view = self.queue_one(w)
        w.registry.revoke(w.agent_id)
        r = w.gate.resolve_review(view.review_id, True, "reviewer-1", view.payload_hash)
        assert_denied(self, r, "AGENT_REVOKED")
        self.assertEqual(w.charges, ())

    def test_user_key_revoked_while_pending_blocks_the_approval(self):
        w = self.world()
        _, view = self.queue_one(w)
        w.registry.revoke(w.user_id)
        r = w.gate.resolve_review(view.review_id, True, "reviewer-1", view.payload_hash)
        assert_denied(self, r, "MANDATE_UNKNOWN_SIGNER")

    def test_pending_reviews_hold_budget_and_count_toward_velocity(self):
        w = self.world(per_txn=100_000, cumulative=250_000)
        self.queue_one(w, amount_cents=100_000)
        self.queue_one(w, amount_cents=100_000)
        # 200k is held; another 100k would pass the per-transaction cap but not the budget.
        assert_denied(self, w.send(amount_cents=100_000), "OVER_CUMULATIVE_CAP")
        w2 = self.world()
        for _ in range(w2.config.velocity_max_approvals):
            self.queue_one(w2, amount_cents=100)
        assert_denied(self, w2.send(amount_cents=100), "VELOCITY")  # queue flooding is bounded

    def test_resolution_is_logged(self):
        w = self.world()
        _, view = self.queue_one(w)
        w.gate.resolve_review(view.review_id, True, "reviewer-1", view.payload_hash)
        last = w.audit.records[-1]["body"]
        self.assertEqual(last["type"], "review_resolution")
        self.assertEqual(last["result"], "APPROVE")
        self.assertEqual(last["approver"], "reviewer-1")
        self.assertTrue(w.audit.verify().ok)


class RiskIsStricterOnly(unittest.TestCase):
    def test_score_bands(self):
        cfg = GateConfig(risk_review_threshold=0.30, risk_deny_threshold=0.90)
        for score, expected in ((0.0, Outcome.APPROVE), (0.2999, Outcome.APPROVE), (0.30, Outcome.REVIEW), (0.8999, Outcome.REVIEW), (0.90, Outcome.DENY), (1.0, Outcome.DENY)):
            with self.subTest(score=score):
                self.assertEqual(World(scorer=StubScorer(score), config=cfg).send().result, expected)

    def test_a_perfect_score_never_overrides_a_failed_check(self):
        w = World(scorer=StubScorer(0.0))
        assert_denied(self, w.send(amount_cents=PER_TXN + 1), "OVER_TXN_CAP")
        assert_denied(self, w.send(category="travel"), "CATEGORY_NOT_ALLOWED")
        bad = w.sign_fields(w.fields(), key=w.attacker)
        assert_denied(self, w.submit(bad), "BAD_SIGNATURE")

    def test_risk_denial_is_recorded_with_score_and_reasons(self):
        w = World(scorer=StubScorer(0.97, reasons=("NEW_MERCHANT(1):+2.00",)))
        d = w.send()
        assert_denied(self, d, "RISK_DENY")
        body = w.audit.records[-1]["body"]
        self.assertEqual(body["risk"]["score_micro"], 970_000)
        self.assertEqual(body["risk"]["reasons"], ["NEW_MERCHANT(1):+2.00"])


if __name__ == "__main__":
    unittest.main()
