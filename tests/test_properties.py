"""Invariant: the risk score can only make a decision stricter.

For hundreds of random proposals (some honest, some tampered, stale, over-cap,
off-category, wrongly signed or missing a mandate) the same input is decided by
two otherwise identical gates: one whose scorer says "0.0, perfectly safe" and
one whose scorer says something arbitrary. For every input:

* whatever the rules deny, both gates deny, with the same reason (a low score
  never rescues a failed check), and
* the second gate is never more lenient than the first (a score never turns a
  denial or a review into an approval).
"""

import random
import unittest

from .helpers import PER_TXN, T0, Outcome, StubScorer, World, new_mandate_msg

RANK = {Outcome.APPROVE: 0, Outcome.REVIEW: 1, Outcome.DENY: 2}


def random_case(rng: random.Random):
    """Return a function (world) -> (proposal msg, mandate arg) for one random case."""
    kind = rng.choice(["ok", "ok", "amount", "category", "currency", "tamper", "stale", "wrongkey", "nomandate", "othermandate", "extra"])
    amount = rng.choice([1, 500, 2_000, 15_000, PER_TXN, PER_TXN + 1, 90_000]) if kind != "ok" else rng.randint(1, PER_TXN)
    category = rng.choice(["books", "home", "gift_cards", "crypto", "travel"]) if kind == "category" else rng.choice(["books", "home", "software"])

    def build(w: World):
        over = {"amount_cents": amount, "category": category}
        if kind == "currency":
            over["currency"] = rng.choice(["EUR", "GBP"])
        if kind == "stale":
            over["timestamp"] = T0 - rng.randint(121, 10**6)
        mandate = "default"
        if kind == "wrongkey":
            return w.sign_fields(w.fields(**over), key=w.attacker), mandate
        if kind == "extra":
            return w.sign_fields({**w.fields(**over), "extra_field": 1}), mandate
        msg = w.proposal(**over)
        if kind == "tamper":
            msg["payload"]["amount_cents"] = msg["payload"]["amount_cents"] + 1
        if kind == "nomandate":
            mandate = None
        if kind == "othermandate":
            mandate = new_mandate_msg(w, agent_id="someone-else")
        return msg, mandate

    return build


class RiskCanOnlyTighten(unittest.TestCase):
    def test_random_proposals(self):
        rng = random.Random(20261020)
        seen = {Outcome.APPROVE: 0, Outcome.REVIEW: 0, Outcome.DENY: 0}
        for trial in range(400):
            case_seed = rng.random()
            score = rng.choice([0.0, 0.05, 0.3, 0.5, 0.89, 0.9, 0.99, 1.0, rng.random()])
            lenient = World(scorer=StubScorer(0.0))
            strict = World(scorer=StubScorer(score))
            a_msg, a_mandate = random_case(random.Random(case_seed))(lenient)
            b_msg, b_mandate = random_case(random.Random(case_seed))(strict)
            a = lenient.submit(a_msg, a_mandate)
            b = strict.submit(b_msg, b_mandate)
            seen[a.result] += 1
            with self.subTest(trial=trial, score=score):
                self.assertGreaterEqual(RANK[b.result], RANK[a.result], "a score loosened a decision")
                if a.result == Outcome.DENY:
                    self.assertEqual(b.result, Outcome.DENY, "a score rescued a proposal the rules denied")
                    self.assertEqual(a.reason_codes, b.reason_codes)
        # The sample must actually exercise approvals and rule denials, or the test proves nothing.
        self.assertGreater(seen[Outcome.APPROVE], 40)
        self.assertGreater(seen[Outcome.DENY], 100)


if __name__ == "__main__":
    unittest.main()
