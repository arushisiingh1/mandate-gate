"""The risk model pipeline: leakage, frozen thresholds, honest metrics, committed artefacts."""

import json
import tempfile
import unittest
from pathlib import Path

try:
    import numpy as np
    import pandas as pd
    import sklearn  # noqa: F401

    HAVE_ML = True
except ImportError:  # pragma: no cover
    HAVE_ML = False

ROOT = Path(__file__).resolve().parents[1]
ARTIFACTS = ROOT / "artifacts" / "risk"

if HAVE_ML:
    from mandate_gate.categories import CATEGORIES
    from mandate_gate.ledger import SECS_SINCE_LAST_CAP
    from mandate_gate.risk import evaluate as ev
    from mandate_gate.risk.features import FEATURE_NAMES, REASON_STEMS, build_features
    from mandate_gate.risk.model import (
        ModelIntegrityError,
        RiskModel,
        THRESHOLDS_FILE,
        load_scorer,
    )
    from mandate_gate.risk.synth import generate
    from mandate_gate.risk.thresholds import choose_thresholds

pytestmark_skip = unittest.skipUnless(HAVE_ML, "needs numpy, pandas and scikit-learn")


@pytestmark_skip
class SyntheticData(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.df = generate(n_agents=80, days=60, seed=11)

    def test_fraud_rate_is_about_one_percent_and_classes_are_not_trivially_separable(self):
        rate = self.df["is_fraud"].mean()
        self.assertTrue(0.005 < rate < 0.03, rate)
        self.assertGreaterEqual(set(self.df["pattern"]) & {"legit", "legit_unusual"}, {"legit", "legit_unusual"})
        self.assertEqual(self.df.loc[self.df["pattern"] == "legit_unusual", "is_fraud"].sum(), 0)  # hard negatives exist

    def test_features_at_time_t_use_only_earlier_events(self):
        """Recompute three history features from the rows themselves and compare."""
        df = self.df
        checked = 0
        for agent, rows in df.groupby("agent_id"):
            rows = rows.sort_values("ts", kind="mergesort")
            seen_merchants, past = set(), []
            for _, r in rows.iterrows():
                last_hour = sum(1 for ts in past if ts > r["ts"] - 3600)
                secs = min(r["ts"] - past[-1], SECS_SINCE_LAST_CAP) if past else SECS_SINCE_LAST_CAP
                self.assertEqual(r["txns_last_hour"], last_hour)
                self.assertEqual(r["secs_since_last"], secs)
                self.assertEqual(r["new_merchant"], 0.0 if r["merchant"] in seen_merchants else 1.0)
                seen_merchants.add(r["merchant"])
                past.append(r["ts"])
                checked += 1
            if checked > 3000:
                break
        self.assertGreater(checked, 1000)

    def test_generator_is_deterministic(self):
        again = generate(n_agents=80, days=60, seed=11)
        pd.testing.assert_frame_equal(self.df, again)

    def test_only_rule_passing_traffic_reaches_the_model(self):
        self.assertTrue((self.df["amt_frac_txn_cap"] <= 1.0 + 1e-9).all())
        self.assertTrue((self.df["amt_frac_remaining"] <= 1.0 + 1e-9).all())
        self.assertTrue((self.df["txns_last_hour"] <= 5).all())

    def test_serving_and_training_build_the_same_features(self):
        row = self.df.iloc[len(self.df) // 2]
        rebuilt = build_features(
            amount_cents=int(row["amount_cents"]),
            per_txn_cap_cents=int(round(row["amount_cents"] / row["amt_frac_txn_cap"])),
            remaining_cap_cents=int(round(row["amount_cents"] / row["amt_frac_remaining"])),
            ts=int(row["ts"]),
            category=CATEGORIES[int(row["category_id"])],
            new_merchant=bool(row["new_merchant"]),
            secs_since_last=int(row["secs_since_last"]),
            txns_last_hour=int(row["txns_last_hour"]),
            agent_mean_amount=(row["amount_cents"] / row["amt_vs_agent_mean"]) if row["amt_vs_agent_mean"] != 1.0 else None,
        )
        for name, got in zip(FEATURE_NAMES, rebuilt):
            self.assertAlmostEqual(got, float(row[name]), places=6, msg=name)


@pytestmark_skip
class SplitsAndThresholds(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.df = generate(n_agents=80, days=60, seed=11)

    def test_split_is_by_time_with_no_overlap_and_nothing_lost(self):
        train, val, test = ev.time_split(self.df)
        self.assertEqual(len(train) + len(val) + len(test), len(self.df))
        self.assertLess(train["ts"].max(), val["ts"].min())
        self.assertLess(val["ts"].max(), test["ts"].min())
        self.assertAlmostEqual(len(train) / len(self.df), 0.60, delta=0.02)

    def test_split_boundaries_never_cut_through_a_timestamp_tie(self):
        df = pd.DataFrame({"ts": [1, 1, 2, 2, 2, 3, 3, 4, 5, 5], "is_fraud": 0})
        for part_a, part_b in zip(ev.time_split(df, 0.3, 0.3), ev.time_split(df, 0.3, 0.3)[1:]):
            self.assertLess(part_a["ts"].max(), part_b["ts"].min())

    def test_thresholds_meet_their_targets_on_the_data_they_were_chosen_on(self):
        rng = np.random.default_rng(0)
        y = (rng.random(20_000) < 0.02).astype(int)
        s = np.clip(rng.normal(0.2 + 0.5 * y, 0.15), 0, 1)
        t = choose_thresholds(y, s, deny_precision=0.9, review_recall=0.9)
        self.assertLess(t["risk_review_threshold"], t["risk_deny_threshold"])
        c_deny = ev.confusion(y.tolist(), s.tolist(), t["risk_deny_threshold"])
        c_review = ev.confusion(y.tolist(), s.tolist(), t["risk_review_threshold"])
        self.assertGreaterEqual(ev.precision_recall(c_deny)[0], 0.9)
        self.assertGreaterEqual(ev.precision_recall(c_review)[1], 0.9)

    def test_thresholds_always_satisfy_the_gates_ordering_even_for_a_perfect_model(self):
        y = np.array([0] * 995 + [1] * 5 + [0] * 100)
        s = np.array([0.0] * 995 + [1.0] * 5 + [0.0] * 100)
        t = choose_thresholds(y, s)
        self.assertTrue(0 < t["risk_review_threshold"] < t["risk_deny_threshold"] <= 1)

    def test_confusion_metrics_can_be_checked_by_hand(self):
        y = [1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0]
        s = [0.9, 0.8, 0.7, 0.2, 0.1, 0.6, 0.3, 0.2, 0.1, 0.1, 0.0, 0.0]
        c = ev.confusion(y, s, 0.5)
        self.assertEqual(c, {"tp": 3, "fp": 1, "fn": 2, "tn": 6})
        precision, recall = ev.precision_recall(c)
        self.assertEqual((precision, recall), (3 / 4, 3 / 5))
        self.assertEqual(ev.precision_recall({"tp": 0, "fp": 0, "fn": 4, "tn": 96}), (None, 0.0))  # nothing flagged: precision undefined


@pytestmark_skip
class FrozenBeforeTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.out = Path(cls.tmp.name)
        cls.calls = []
        original = RiskModel.predict
        out = cls.out

        def spy(self, X):
            cls.calls.append({"rows": len(X), "thresholds_on_disk": (out / THRESHOLDS_FILE).exists()})
            return original(self, X)

        RiskModel.predict = spy
        try:
            cls.metrics = ev.run_evaluation(out, n_agents=70, days=60, seed=5, make_plot=False)
        finally:
            RiskModel.predict = original

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_the_test_split_is_first_scored_after_thresholds_are_on_disk(self):
        self.assertGreaterEqual(len(self.calls), 2)
        validation, test = self.calls[0], self.calls[-1]
        self.assertFalse(validation["thresholds_on_disk"], "validation is scored before thresholds exist")
        self.assertTrue(test["thresholds_on_disk"], "the test split was scored before thresholds were frozen")
        split_rows = [s["rows"] for s in self.metrics["splits"]]
        self.assertEqual((validation["rows"], test["rows"]), (split_rows[1], split_rows[2]))

    def test_recorded_order_of_events(self):
        order = self.metrics["order_of_events"]
        self.assertEqual(order.index("fit_on_train") < order.index("score_validation") < order.index("choose_thresholds_on_validation"), True)
        self.assertLess(order.index("thresholds_frozen_to_disk"), order.index("score_test"))

    def test_frozen_file_matches_what_the_test_metrics_used(self):
        frozen = json.loads((self.out / THRESHOLDS_FILE).read_text())
        self.assertEqual(frozen["chosen_on"], "validation")
        self.assertEqual(self.metrics["thresholds"], {"review": frozen["risk_review_threshold"], "deny": frozen["risk_deny_threshold"]})

    def test_the_never_fraud_baseline_is_reported_honestly(self):
        base = self.metrics["never_fraud_baseline"]
        self.assertEqual(base["recall"], 0.0)
        self.assertIsNone(base["precision"])
        self.assertAlmostEqual(base["accuracy"], 1 - self.metrics["prevalence"], places=3)
        self.assertAlmostEqual(base["pr_auc"], self.metrics["prevalence"], places=3)
        self.assertGreater(base["accuracy"], 0.95)  # high accuracy, zero fraud caught: why accuracy is not the headline

    def test_the_model_beats_the_baseline_on_pr_auc(self):
        self.assertGreater(self.metrics["model"]["pr_auc"], 3 * self.metrics["prevalence"])

    def test_the_saved_model_loads_and_scores_like_the_one_that_was_trained(self):
        scorer, meta = load_scorer(self.out)
        self.assertEqual(meta["model_version"], scorer.model_version)
        self.assertLess(meta["fit_parity_max_abs_diff"], 1e-9)

    def test_a_modified_model_file_is_refused(self):
        tampered = Path(self.tmp.name + "_tampered")
        tampered.mkdir()
        try:
            for f in self.out.iterdir():
                (tampered / f.name).write_bytes(f.read_bytes())
            model_file = tampered / json.loads((tampered / THRESHOLDS_FILE).read_text())["model_file"]
            model_file.write_text(model_file.read_text().replace('"intercept": ', '"intercept": 0.5 + ', 1))  # any edit changes the hash
            with self.assertRaises(ModelIntegrityError):
                load_scorer(tampered)
        finally:
            for f in tampered.iterdir():
                f.unlink()
            tampered.rmdir()


@pytestmark_skip
@unittest.skipUnless((ARTIFACTS / THRESHOLDS_FILE).exists(), "artifacts/risk has not been generated")
class CommittedArtifacts(unittest.TestCase):
    """The model that ships in the repository is the one the demo and README describe."""

    @classmethod
    def setUpClass(cls):
        cls.scorer, cls.meta = load_scorer(ARTIFACTS)
        cls.metrics = json.loads((ARTIFACTS / "metrics.json").read_text())
        cls.df = generate(n_agents=cls.meta["n_agents"], days=cls.meta["days"], seed=cls.meta["seed"])

    def test_thresholds_are_valid_for_the_gate(self):
        self.assertTrue(0 < self.meta["risk_review_threshold"] < self.meta["risk_deny_threshold"] <= 1)

    def test_regenerating_the_data_reproduces_the_recorded_fingerprint(self):
        self.assertEqual(ev._dataset_fingerprint(self.df), self.meta["dataset_sha256"])

    def test_the_recorded_test_metrics_are_reproduced_from_the_shipped_model(self):
        _, _, test = ev.time_split(self.df)
        model = self.scorer._model
        s = model.predict(test[list(FEATURE_NAMES)].to_numpy())
        y = test["is_fraud"].to_numpy()
        c = ev.confusion(y.tolist(), s.tolist(), self.meta["risk_review_threshold"])
        recorded = self.metrics["model"]["at_review_threshold"]
        self.assertEqual({k: recorded[k] for k in ("tp", "fp", "fn", "tn")}, c)
        from sklearn.metrics import average_precision_score

        self.assertAlmostEqual(float(average_precision_score(y, s)), self.metrics["model"]["pr_auc"], places=4)

    def test_every_shipped_score_has_at_most_three_positive_reasons_that_add_up(self):
        _, _, test = ev.time_split(self.df)
        model = self.scorer._model
        sample = test.sample(60, random_state=0)
        for _, row in sample.iterrows():
            x = [float(row[n]) for n in FEATURE_NAMES]
            reasons = model.explain(x)
            self.assertLessEqual(len(reasons), 3)
            contrib = model.contributions(x)  # raises if additivity fails
            self.assertAlmostEqual(float(contrib.sum()) + model.intercept, float(model.logit(np.asarray([x]))[0]), places=9)
            stems = {REASON_STEMS[n] for n in FEATURE_NAMES}
            for r in reasons:
                self.assertIn(r.split("(")[0], stems)
                self.assertTrue(r.rsplit(":", 1)[1].startswith("+"), r)  # only reasons that raised the score

    def test_the_model_ranks_fraud_far_above_chance(self):
        self.assertGreater(self.metrics["model"]["pr_auc"], 10 * self.metrics["prevalence"])

    def test_the_unseen_pattern_is_reported_as_a_weakness_not_hidden(self):
        slow = self.metrics["recall_by_pattern_on_test"]["slow_novel"]
        self.assertLess(slow["recall_at_review"], 0.5)


if __name__ == "__main__":
    unittest.main()
