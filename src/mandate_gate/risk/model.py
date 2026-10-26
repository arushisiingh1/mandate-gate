"""A deliberately small fraud model: logistic regression with exact reason codes.

Why logistic regression, and why this is not the interesting part
------------------------------------------------------------------
The model is advisory. It can only make a decision stricter, and the gate is
safe whether it is good, bad or missing. So it is kept small enough to explain
in one breath:

    logit(fraud) = intercept + sum_j  w_j * (z_j - mean_j) / scale_j

where ``z`` is a handful of simple transforms of the nine raw features (logs
for the heavy-tailed ones, a night-time flag, one-hot category). Every term in
that sum is one feature's push on the score, measured from an average
transaction, and the terms add up to the logit exactly. That sum *is* the
reason code (``AMOUNT_VS_TXN_CAP(0.96):+1.23``): there is no approximation and
nothing to trust.

An earlier version of this repository used gradient boosting with an exact
TreeSHAP written from scratch. On this synthetic data it scored PR-AUC 0.81
against 0.78 for this model. That is the honest reason it was cut: a few
hundred lines more code to defend for a gain the data cannot even measure
(see DECISIONS.md and the README).

The saved model is plain JSON (weights, means and scales), so loading it
cannot execute code, and its SHA-256 is pinned in ``thresholds.json``.

Reason codes are log-odds contributions toward "fraud". Only positive
contributions are listed, at most three.
"""

from __future__ import annotations

import hashlib
import json
import math
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

import numpy as np

from ..categories import CATEGORIES
from .features import FEATURE_NAMES, REASON_STEMS
from .scorer import RiskResult

MODEL_FILE = "risk_model.json"
THRESHOLDS_FILE = "thresholds.json"
FORMAT = "mandate-gate-logit-v1"
MIN_REASON_CONTRIBUTION = 0.05  # log-odds; ignore negligible contributors
ADDITIVITY_TOLERANCE = 1e-9
PARITY_TOLERANCE = 1e-9
NIGHT_BEFORE_HOUR = 6  # hours 00:00-05:59 UTC count as "night"

# Indices into FEATURE_NAMES for the raw columns the transforms read.
_AMOUNT, _FRAC_CAP, _FRAC_REM, _HOUR, _SECS, _RECENT, _NEW_MERCH, _CATEGORY, _VS_MEAN = range(9)
assert FEATURE_NAMES[_CATEGORY] == "category_id" and FEATURE_NAMES[_VS_MEAN] == "amt_vs_agent_mean"

# Which raw feature each expanded column belongs to (for grouping contributions).
_NUMERIC_SOURCES = (_AMOUNT, _FRAC_CAP, _FRAC_REM, _HOUR, _SECS, _RECENT, _NEW_MERCH, _VS_MEAN)
COLUMN_SOURCE: Tuple[int, ...] = _NUMERIC_SOURCES + (_CATEGORY,) * len(CATEGORIES)
N_COLUMNS = len(COLUMN_SOURCE)


class ModelIntegrityError(Exception):
    pass


def expand(X: np.ndarray) -> np.ndarray:
    """Raw feature matrix (n x 9) -> model columns (n x N_COLUMNS). The only place transforms live."""
    X = np.asarray(X, dtype=float)
    if X.ndim != 2 or X.shape[1] != len(FEATURE_NAMES):
        raise ValueError(f"expected {len(FEATURE_NAMES)} features per row")
    numeric = np.column_stack(
        [
            np.log1p(np.maximum(X[:, _AMOUNT], 0.0)),
            X[:, _FRAC_CAP],
            X[:, _FRAC_REM],
            (X[:, _HOUR] < NIGHT_BEFORE_HOUR).astype(float),
            np.log1p(np.maximum(X[:, _SECS], 0.0)),
            X[:, _RECENT],
            X[:, _NEW_MERCH],
            np.log(np.maximum(X[:, _VS_MEAN], 1e-3)),
        ]
    )
    onehot = np.column_stack([(X[:, _CATEGORY] == i).astype(float) for i in range(len(CATEGORIES))])
    return np.hstack([numeric, onehot])


def _sigmoid(z: np.ndarray) -> np.ndarray:
    return 1.0 / (1.0 + np.exp(-np.clip(z, -700.0, 700.0)))


class RiskModel:
    def __init__(
        self,
        mean: Sequence[float],
        scale: Sequence[float],
        coef: Sequence[float],
        intercept: float,
        version: str = "unsaved",
    ) -> None:
        self.mean = np.asarray(mean, dtype=float)
        self.scale = np.asarray(scale, dtype=float)
        self.coef = np.asarray(coef, dtype=float)
        self.intercept = float(intercept)
        self.model_version = version
        self.fit_parity_max_abs_diff: Optional[float] = None
        for arr in (self.mean, self.scale, self.coef):
            if arr.shape != (N_COLUMNS,) or not np.all(np.isfinite(arr)):
                raise ModelIntegrityError("model arrays are the wrong length or not finite")
        if not np.all(self.scale > 0) or not math.isfinite(self.intercept):
            raise ModelIntegrityError("model scales must be positive and the intercept finite")

    # --- scoring -------------------------------------------------------------
    def _terms(self, X: np.ndarray) -> np.ndarray:
        """Each expanded column's push on the logit, measured from the training mean."""
        return self.coef * (expand(X) - self.mean) / self.scale

    def logit(self, X: np.ndarray) -> np.ndarray:
        return self.intercept + self._terms(X).sum(axis=1)

    def predict(self, X: np.ndarray) -> np.ndarray:
        return _sigmoid(self.logit(np.asarray(X, dtype=float)))

    def score_row(self, row: Sequence[float]) -> float:
        return float(self.predict(np.asarray([row], dtype=float))[0])

    # --- reason codes ----------------------------------------------------------
    @property
    def explanation_method(self) -> str:
        return "linear"

    def contributions(self, row: Sequence[float]) -> np.ndarray:
        """Per raw feature log-odds contribution for one row. Raises if it fails the additivity check."""
        x = np.asarray([[float(v) for v in row]], dtype=float)
        terms = self._terms(x)[0]
        phi = np.zeros(len(FEATURE_NAMES))
        for col, source in enumerate(COLUMN_SOURCE):
            phi[source] += terms[col]
        gap = abs(float(phi.sum()) + self.intercept - float(self.logit(x)[0]))
        if not gap <= ADDITIVITY_TOLERANCE:
            raise ModelIntegrityError(f"reason codes do not add up to the score (gap {gap:.3g})")
        return phi

    def explain(self, row: Sequence[float], k: int = 3) -> Tuple[str, ...]:
        x = [float(v) for v in row]
        contrib = self.contributions(x)
        order = np.argsort(-contrib, kind="mergesort")[:k]
        out = []
        for j in order:
            if contrib[j] > MIN_REASON_CONTRIBUTION:
                name = FEATURE_NAMES[j]
                shown = f"{x[j]:.3g}"
                if name == "category_id" and 0 <= int(x[j]) < len(CATEGORIES):
                    shown = CATEGORIES[int(x[j])]  # a name is readable; an id is not
                out.append(f"{REASON_STEMS[name]}({shown}):{contrib[j]:+.2f}")
        return tuple(out)

    # --- persistence -------------------------------------------------------------
    def to_json(self) -> str:
        return json.dumps(
            {
                "format": FORMAT,
                "feature_names": list(FEATURE_NAMES),
                "categories": list(CATEGORIES),
                "intercept": self.intercept,
                "mean": self.mean.tolist(),
                "scale": self.scale.tolist(),
                "coef": self.coef.tolist(),
            },
            sort_keys=True,
            indent=1,
        )

    def save(self, out_dir: Path) -> Tuple[str, str]:
        """Write the model. Returns ``(file name, sha256 of the file)``."""
        blob = (self.to_json() + "\n").encode("utf-8")
        (Path(out_dir) / MODEL_FILE).write_bytes(blob)
        sha = hashlib.sha256(blob).hexdigest()
        self.model_version = f"logit-{sha[:12]}"
        return MODEL_FILE, sha

    @classmethod
    def load(cls, out_dir: Path, file_name: str, expected_sha256: str) -> "RiskModel":
        if file_name != MODEL_FILE:
            raise ModelIntegrityError("unexpected model file name")
        blob = (Path(out_dir) / file_name).read_bytes()
        sha = hashlib.sha256(blob).hexdigest()
        if sha != expected_sha256:
            raise ModelIntegrityError("model file hash does not match thresholds.json; refusing to load")
        try:
            obj = json.loads(blob.decode("utf-8"))
            if obj["format"] != FORMAT:
                raise ModelIntegrityError("unknown model format")
            if tuple(obj["feature_names"]) != tuple(FEATURE_NAMES) or tuple(obj["categories"]) != tuple(CATEGORIES):
                raise ModelIntegrityError("model was trained on a different feature set")
            return cls(obj["mean"], obj["scale"], obj["coef"], obj["intercept"], f"logit-{sha[:12]}")
        except (KeyError, TypeError, ValueError) as exc:
            raise ModelIntegrityError(f"malformed model file: {exc}") from exc


class ModelScorer:
    """Adapts a ``RiskModel`` to the gate's scorer interface."""

    def __init__(self, model: RiskModel) -> None:
        self._model = model
        self.model_version = model.model_version

    def score(self, features: Sequence[float]) -> RiskResult:
        score = self._model.score_row(features)
        return RiskResult(score, self._model.explain(features), self.model_version)


def fit_model(X: np.ndarray, y: np.ndarray, seed: int = 7) -> RiskModel:
    """Standardise the expanded columns and fit an L2 logistic regression."""
    from sklearn.linear_model import LogisticRegression

    E = expand(np.asarray(X, dtype=float))
    y = np.asarray(y, dtype=int)
    mean = E.mean(axis=0)
    scale = E.std(axis=0)
    scale = np.where(scale > 1e-9, scale, 1.0)  # a constant column gets weight ~0, not a divide by zero
    clf = LogisticRegression(C=1.0, max_iter=5000, random_state=seed)
    clf.fit((E - mean) / scale, y)
    model = RiskModel(mean, scale, clf.coef_[0], float(clf.intercept_[0]))
    # The deployed arithmetic must reproduce scikit-learn's own probabilities.
    ref = clf.predict_proba((E - mean) / scale)[:, 1]
    diff = float(np.max(np.abs(_sigmoid(model.logit(np.asarray(X, dtype=float))) - ref)))
    model.fit_parity_max_abs_diff = diff
    if not diff <= PARITY_TOLERANCE:
        raise ModelIntegrityError(f"saved-model arithmetic disagrees with scikit-learn (max |diff| {diff:.3g})")
    return model


def load_scorer(risk_dir: Path) -> Tuple[ModelScorer, Dict[str, Any]]:
    """Load the model and frozen thresholds written by ``run_evaluation``."""
    risk_dir = Path(risk_dir)
    meta = json.loads((risk_dir / THRESHOLDS_FILE).read_text())
    model = RiskModel.load(risk_dir, meta.get("model_file", MODEL_FILE), meta["model_sha256"])
    return ModelScorer(model), meta
