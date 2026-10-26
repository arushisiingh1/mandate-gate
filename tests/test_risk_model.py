"""The small risk model: explainable by hand, additive, hash-pinned, and unable to loosen a decision."""

import json
import tempfile
import unittest
from pathlib import Path

try:
    import numpy as np

    HAVE_NUMPY = True
except ImportError:  # pragma: no cover
    HAVE_NUMPY = False

if HAVE_NUMPY:
    from mandate_gate.categories import CATEGORIES
    from mandate_gate.risk.features import FEATURE_NAMES
    from mandate_gate.risk.model import (
        COLUMN_SOURCE,
        MODEL_FILE,
        N_COLUMNS,
        ModelIntegrityError,
        RiskModel,
        expand,
    )

needs_numpy = unittest.skipUnless(HAVE_NUMPY, "needs numpy")


def make_model(version="t"):
    rng = np.random.default_rng(0)
    return RiskModel(
        mean=rng.normal(size=N_COLUMNS) * 0.1,
        scale=np.ones(N_COLUMNS) * 1.5,
        coef=rng.normal(size=N_COLUMNS),
        intercept=-3.0,
        version=version,
    )


def sample_row(category="gift_cards"):
    # amount_cents, frac_cap, frac_remaining, hour, secs_since_last, txns_last_hour, new_merchant, category_id, vs_mean
    return [28900.0, 0.96, 0.2, 3.0, 40.0, 2.0, 1.0, float(CATEGORIES.index(category)), 4.0]


@needs_numpy
class ExplainableByHand(unittest.TestCase):
    def test_the_score_is_a_sigmoid_of_a_plain_weighted_sum_you_can_recompute_in_pure_python(self):
        import math

        m = make_model()
        row = sample_row()
        cols = expand(np.asarray([row]))[0]
        logit = m.intercept + sum(w * (c - mu) / sd for w, c, mu, sd in zip(m.coef, cols, m.mean, m.scale))
        by_hand = 1 / (1 + math.exp(-logit))
        self.assertAlmostEqual(m.score_row(row), by_hand, places=12)

    def test_contributions_add_up_to_the_logit_exactly(self):
        m = make_model()
        for category in CATEGORIES:
            row = sample_row(category)
            phi = m.contributions(row)
            self.assertEqual(len(phi), len(FEATURE_NAMES))
            self.assertAlmostEqual(float(phi.sum()) + m.intercept, float(m.logit(np.asarray([row]))[0]), places=12)

    def test_one_hot_category_columns_are_grouped_into_one_reason(self):
        self.assertEqual(COLUMN_SOURCE.count(FEATURE_NAMES.index("category_id")), len(CATEGORIES))

    def test_reasons_are_at_most_three_and_only_positive(self):
        m = make_model()
        reasons = m.explain(sample_row())
        self.assertLessEqual(len(reasons), 3)
        for r in reasons:
            self.assertTrue(r.rsplit(":", 1)[1].startswith("+"), r)

    def test_category_is_shown_by_name_not_by_id(self):
        m = make_model()
        m.coef[:] = 0.0
        m.coef[len(COLUMN_SOURCE) - len(CATEGORIES) + CATEGORIES.index("gift_cards")] = 5.0
        reasons = m.explain(sample_row("gift_cards"))
        self.assertTrue(any(r.startswith("CATEGORY(gift_cards)") for r in reasons), reasons)

    def test_wrong_width_input_is_an_error_not_a_guess(self):
        with self.assertRaises(ValueError):
            make_model().predict(np.zeros((1, 4)))


@needs_numpy
class SavedModel(unittest.TestCase):
    def test_round_trip_scores_identically(self):
        m = make_model()
        with tempfile.TemporaryDirectory() as d:
            name, sha = m.save(Path(d))
            loaded = RiskModel.load(Path(d), name, sha)
            row = sample_row()
            self.assertEqual(m.score_row(row), loaded.score_row(row))
            self.assertEqual(loaded.model_version, f"logit-{sha[:12]}")

    def test_the_file_is_json_data_not_code(self):
        m = make_model()
        with tempfile.TemporaryDirectory() as d:
            name, _ = m.save(Path(d))
            obj = json.loads((Path(d) / name).read_text())
            self.assertEqual(set(obj), {"format", "feature_names", "categories", "intercept", "mean", "scale", "coef"})

    def test_a_modified_file_is_refused_by_hash(self):
        m = make_model()
        with tempfile.TemporaryDirectory() as d:
            name, sha = m.save(Path(d))
            path = Path(d) / name
            path.write_text(path.read_text().replace('"intercept": -3.0', '"intercept": -9.0'))
            with self.assertRaises(ModelIntegrityError):
                RiskModel.load(Path(d), name, sha)

    def test_a_correctly_hashed_but_malformed_file_is_refused(self):
        import hashlib

        with tempfile.TemporaryDirectory() as d:
            for body in ('{"format": "other"}', "not json", '{"format": "mandate-gate-logit-v1"}'):
                (Path(d) / MODEL_FILE).write_text(body)
                sha = hashlib.sha256(body.encode()).hexdigest()
                with self.assertRaises(ModelIntegrityError):
                    RiskModel.load(Path(d), MODEL_FILE, sha)

    def test_non_finite_or_zero_scale_weights_are_refused(self):
        with self.assertRaises(ModelIntegrityError):
            RiskModel(np.zeros(N_COLUMNS), np.zeros(N_COLUMNS), np.zeros(N_COLUMNS), 0.0)
        with self.assertRaises(ModelIntegrityError):
            RiskModel(np.zeros(N_COLUMNS), np.ones(N_COLUMNS), np.full(N_COLUMNS, np.nan), 0.0)

    def test_an_unexpected_file_name_is_refused(self):
        with self.assertRaises(ModelIntegrityError):
            RiskModel.load(Path("."), "risk_model.pkl", "0" * 64)


if __name__ == "__main__":
    unittest.main()
