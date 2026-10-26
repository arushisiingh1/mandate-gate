"""Choose the two routing thresholds on the VALIDATION split only.

* ``deny``   : the lowest score at which precision on validation is still at
               least ``deny_precision``. Auto-deny only when the model is sure.
* ``review`` : the highest score at which recall on validation is still at
               least ``review_recall``. Everything from here up goes to a human.

Below ``review`` the proposal can be approved (if every rule passed).
"""

from __future__ import annotations

from typing import Dict

import numpy as np


def pr_points(y: np.ndarray, s: np.ndarray):
    """Precision and recall for 'predict fraud when score >= t', at each distinct t."""
    y = np.asarray(y, dtype=int)
    s = np.asarray(s, dtype=float)
    order = np.argsort(-s, kind="mergesort")
    s_sorted, y_sorted = s[order], y[order]
    last = np.r_[s_sorted[1:] != s_sorted[:-1], True]
    thr = s_sorted[last]
    tp = np.cumsum(y_sorted)[last]
    n = np.arange(1, len(s_sorted) + 1)[last]
    positives = max(int(y.sum()), 1)
    return thr, tp / n, tp / positives, tp


def choose_thresholds(
    y_val: np.ndarray,
    s_val: np.ndarray,
    deny_precision: float = 0.95,
    review_recall: float = 0.90,
    min_deny_support: int = 5,
) -> Dict[str, float]:
    thr, precision, recall, tp = pr_points(y_val, s_val)

    ok_deny = (precision >= deny_precision) & (tp >= min_deny_support)
    deny = float(thr[ok_deny].min()) if ok_deny.any() else 1.0

    ok_review = recall >= review_recall
    review = float(thr[ok_review].max()) if ok_review.any() else float(thr.min())

    # The gate requires 0 < review < deny <= 1. If the model separates so well
    # that the review band would be empty, keep the ordering strict.
    review = min(review, deny - 1e-6)
    review = max(review, 1e-6)
    # Deliberately NOT rounded. The rule is "flag when score >= threshold", so a
    # threshold rounded up past the score of the boundary example silently drops
    # that example and can miss the recall target the threshold was chosen for.
    # JSON round-trips Python floats exactly, so nothing is lost by keeping them.
    return {
        "risk_review_threshold": review,
        "risk_deny_threshold": deny,
    }
