"""Train, choose thresholds on validation, freeze them, then evaluate on test.

Order of operations (recorded in ``metrics.json`` under ``order_of_events``):

    generate -> time split -> fit on TRAIN -> score VAL -> choose thresholds
    -> write thresholds.json (frozen) -> score TEST -> metrics

The test split is not scored until after the thresholds file is on disk. That
ordering is enforced by the structure of this function, and a test asserts it.

Everything here runs on SYNTHETIC data. See ``synth.py`` and the README.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
import pandas as pd
from sklearn.metrics import average_precision_score, precision_recall_curve

from .features import FEATURE_NAMES
from .model import MODEL_FILE, THRESHOLDS_FILE, ModelScorer, fit_model, load_scorer
from .synth import PATTERNS, generate
from .thresholds import choose_thresholds

TRAIN_FRAC = 0.60
VAL_FRAC = 0.20


# ---------------------------------------------------------------------------
# Splitting
# ---------------------------------------------------------------------------


def time_split(df: pd.DataFrame, train_frac: float = TRAIN_FRAC, val_frac: float = VAL_FRAC):
    """Split by time, never by random shuffle. Boundaries never fall inside a tie."""
    ts = df["ts"].to_numpy()
    n = len(df)

    def boundary(frac: float, start: int) -> int:
        i = max(int(n * frac), start + 1)
        while i < n and ts[i] == ts[i - 1]:
            i += 1
        return i

    i1 = boundary(train_frac, 0)
    i2 = boundary(train_frac + val_frac, i1)
    return df.iloc[:i1].copy(), df.iloc[i1:i2].copy(), df.iloc[i2:].copy()


# ---------------------------------------------------------------------------
# Metrics: a plain-Python confusion matrix so results can be checked by hand
# ---------------------------------------------------------------------------


def confusion(y: List[int], s: List[float], threshold: float) -> Dict[str, int]:
    tp = fp = fn = tn = 0
    for label, score in zip(y, s):
        flagged = score >= threshold
        if flagged and label == 1:
            tp += 1
        elif flagged:
            fp += 1
        elif label == 1:
            fn += 1
        else:
            tn += 1
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn}


def precision_recall(c: Dict[str, int]) -> Tuple[Optional[float], Optional[float]]:
    flagged = c["tp"] + c["fp"]
    positives = c["tp"] + c["fn"]
    precision = c["tp"] / flagged if flagged else None
    recall = c["tp"] / positives if positives else None
    return precision, recall


def _r(x: Optional[float], nd: int = 4) -> Optional[float]:
    return None if x is None else round(float(x), nd)


def _split_summary(name: str, part: pd.DataFrame) -> Dict[str, Any]:
    return {
        "split": name,
        "rows": int(len(part)),
        "fraud": int(part["is_fraud"].sum()),
        "fraud_rate": _r(part["is_fraud"].mean(), 5),
        "ts_min": int(part["ts"].min()),
        "ts_max": int(part["ts"].max()),
    }


def _dataset_fingerprint(df: pd.DataFrame) -> str:
    cols = list(FEATURE_NAMES) + ["ts", "agent_id", "is_fraud"]
    return hashlib.sha256(df[cols].round(6).to_csv(index=False).encode()).hexdigest()


# ---------------------------------------------------------------------------
# The pipeline
# ---------------------------------------------------------------------------


def run_evaluation(
    out_dir: Path,
    *,
    seed: int = 7,
    n_agents: int = 300,
    days: int = 90,
    make_plot: bool = True,
    deny_precision: float = 0.95,
    review_recall: float = 0.90,
) -> Dict[str, Any]:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    events: List[str] = []

    df = generate(n_agents=n_agents, days=days, seed=seed)
    events.append("generate")
    train, val, test = time_split(df)
    events.append("time_split")
    assert train["ts"].max() < val["ts"].min() and val["ts"].max() < test["ts"].min(), "split leaks across time"

    X_cols = list(FEATURE_NAMES)
    model = fit_model(train[X_cols].to_numpy(), train["is_fraud"].to_numpy(), seed=seed)
    events.append("fit_on_train")

    s_val = model.predict(val[X_cols].to_numpy())
    events.append("score_validation")
    y_val = val["is_fraud"].to_numpy()
    thresholds = choose_thresholds(y_val, s_val, deny_precision, review_recall)
    events.append("choose_thresholds_on_validation")

    # ---- FREEZE: nothing below this line may influence thresholds or model ----
    model_file, model_sha = model.save(out_dir)
    val_conf_review = confusion(y_val.tolist(), s_val.tolist(), thresholds["risk_review_threshold"])
    frozen = {
        **thresholds,
        "model_file": model_file,
        "model_sha256": model_sha,
        "model_version": model.model_version,
        "fit_parity_max_abs_diff": model.fit_parity_max_abs_diff,
        "model_kind": "logistic_regression",
        "explanation_method": model.explanation_method,
        "chosen_on": "validation",
        "targets": {"deny_precision": deny_precision, "review_recall": review_recall},
        "seed": seed,
        "n_agents": n_agents,
        "days": days,
        "dataset_sha256": _dataset_fingerprint(df),
        "train_end_ts": int(train["ts"].max()),
        "val_end_ts": int(val["ts"].max()),
        "validation_confusion_at_review": val_conf_review,
    }
    (out_dir / THRESHOLDS_FILE).write_text(json.dumps(frozen, indent=2, sort_keys=True) + "\n")
    events.append("thresholds_frozen_to_disk")

    # The test split is touched for the first time here, using the frozen file.
    frozen_on_disk = json.loads((out_dir / THRESHOLDS_FILE).read_text())
    t_review = frozen_on_disk["risk_review_threshold"]
    t_deny = frozen_on_disk["risk_deny_threshold"]
    y_test = test["is_fraud"].to_numpy()
    s_test = model.predict(test[X_cols].to_numpy())
    events.append("score_test")

    metrics = _test_metrics(y_test, s_test, test, t_review, t_deny)
    metrics.update(
        {
            "order_of_events": events,
            "splits": [_split_summary("train", train), _split_summary("validation", val), _split_summary("test", test)],
            "thresholds": {"review": t_review, "deny": t_deny},
            "model_kind": "logistic_regression",
            "explanation_method": model.explanation_method,
            "model_version": model.model_version,
            "validation_pr_auc": _r(average_precision_score(y_val, s_val)),
        }
    )
    (out_dir / "metrics.json").write_text(json.dumps(metrics, indent=2, sort_keys=True) + "\n")
    if make_plot:
        _plot(out_dir / "pr_curve.png", y_val, s_val, y_test, s_test, t_review, t_deny, metrics)
    (out_dir / "report.md").write_text(_report(metrics, frozen))
    return metrics


def _test_metrics(y: np.ndarray, s: np.ndarray, test: pd.DataFrame, t_review: float, t_deny: float) -> Dict[str, Any]:
    prevalence = float(y.mean())
    ap = float(average_precision_score(y, s))
    yl, sl = y.tolist(), s.tolist()
    conf_review = confusion(yl, sl, t_review)
    conf_deny = confusion(yl, sl, t_deny)
    p_r, r_r = precision_recall(conf_review)
    p_d, r_d = precision_recall(conf_deny)

    approve = s < t_review
    review = (s >= t_review) & (s < t_deny)
    deny = s >= t_deny
    routing = {
        name: {"legit": int(((y == 0) & mask).sum()), "fraud": int(((y == 1) & mask).sum())}
        for name, mask in (("approve", approve), ("review", review), ("deny", deny))
    }

    by_pattern = {}
    fraud_rows = test[test["is_fraud"] == 1]
    for pattern in PATTERNS:
        sub = fraud_rows[fraud_rows["pattern"] == pattern]
        if len(sub):
            sub_scores = s[sub.index.map(lambda i: test.index.get_loc(i))]
            by_pattern[pattern] = {
                "n": int(len(sub)),
                "caught_at_review_or_above": int((sub_scores >= t_review).sum()),
                "recall_at_review": _r((sub_scores >= t_review).mean()),
            }

    return {
        "prevalence": _r(prevalence, 5),
        "model": {
            "pr_auc": _r(ap),
            "at_review_threshold": {**conf_review, "precision": _r(p_r), "recall": _r(r_r)},
            "at_deny_threshold": {**conf_deny, "precision": _r(p_d), "recall": _r(r_d)},
        },
        "never_fraud_baseline": {
            "accuracy": _r(1 - prevalence),
            "precision": None,
            "recall": 0.0,
            "pr_auc": _r(prevalence),
            "note": "Always predicting 'legitimate' is right about 99% of the time and catches nothing. A constant score has PR-AUC equal to the fraud rate.",
        },
        "model_accuracy_at_review": _r((conf_review["tp"] + conf_review["tn"]) / len(y)),
        "routing_on_test": routing,
        "recall_by_pattern_on_test": by_pattern,
    }


def _plot(path: Path, y_val, s_val, y_test, s_test, t_review, t_deny, metrics) -> None:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    fig, ax = plt.subplots(figsize=(6.4, 4.4), dpi=150)
    pv, rv, _ = precision_recall_curve(y_val, s_val)
    pt, rt, _ = precision_recall_curve(y_test, s_test)
    ax.plot(rv, pv, color="#0072B2", lw=1.8, ls="--", label="validation (thresholds chosen here)")
    ax.plot(rt, pt, color="#D55E00", lw=2.0, label=f"test (PR-AUC {metrics['model']['pr_auc']:.2f})")
    ax.axhline(metrics["prevalence"], color="#555555", lw=1.2, ls=":", label=f"never-fraud / constant baseline ({metrics['prevalence']:.3f})")
    for name, t, marker in (("review", t_review, "o"), ("deny", t_deny, "s")):
        c = confusion(y_test.tolist(), s_test.tolist(), t)
        prec, rec = precision_recall(c)
        if prec is not None and rec is not None:
            ax.plot([rec], [prec], marker, color="#D55E00", ms=7, mfc="white", mew=1.8)
            ax.annotate(f"{name} threshold", (rec, prec), textcoords="offset points", xytext=(6, 6), fontsize=8)
    ax.set_xlabel("Recall")
    ax.set_ylabel("Precision")
    ax.set_xlim(0, 1.0)
    ax.set_ylim(0, 1.02)
    ax.set_title("Precision-recall (SYNTHETIC data, time-ordered split)", fontsize=10)
    ax.grid(alpha=0.25)
    ax.legend(fontsize=8, loc="lower left")
    fig.tight_layout()
    fig.savefig(path)
    plt.close(fig)


def _fmt(x: Optional[float]) -> str:
    return "n/a" if x is None else f"{x:.3f}"


def _report(m: Dict[str, Any], frozen: Dict[str, Any]) -> str:
    r, d = m["model"]["at_review_threshold"], m["model"]["at_deny_threshold"]
    base = m["never_fraud_baseline"]
    lines = [
        "# Risk model evaluation",
        "",
        "> **Synthetic data.** The fraud patterns were written by the project author. These numbers show the",
        "> evaluation method works; they say nothing about performance on real fraud.",
        "",
        f"Model: logistic regression  |  reason codes: `{m['explanation_method']}`  |  model: `{m['model_version']}`",
        "",
        "## Splits (time-ordered, no shuffling)",
        "",
        "| split | rows | fraud | fraud rate |",
        "|---|---:|---:|---:|",
    ]
    for s in m["splits"]:
        lines.append(f"| {s['split']} | {s['rows']:,} | {s['fraud']} | {s['fraud_rate']:.3%} |")
    lines += [
        "",
        "## Thresholds (chosen on validation, frozen before the test split was scored)",
        "",
        f"- review (send to a human) at score >= **{m['thresholds']['review']}**  (target: recall >= {frozen['targets']['review_recall']} on validation)",
        f"- deny at score >= **{m['thresholds']['deny']}**  (target: precision >= {frozen['targets']['deny_precision']} on validation)",
        "",
        "Order of events: " + " -> ".join(m["order_of_events"]),
        "",
        "## Test results",
        "",
        "| | PR-AUC | precision | recall | accuracy |",
        "|---|---:|---:|---:|---:|",
        f"| Model, flag at review threshold | {m['model']['pr_auc']:.3f} | {_fmt(r['precision'])} | {_fmt(r['recall'])} | {m['model_accuracy_at_review']:.3f} |",
        f"| Model, flag at deny threshold | {m['model']['pr_auc']:.3f} | {_fmt(d['precision'])} | {_fmt(d['recall'])} | |",
        f"| Never-fraud baseline | {base['pr_auc']:.3f} | n/a | 0.000 | {base['accuracy']:.3f} |",
        "",
        f"Confusion matrix at the review threshold: TP {r['tp']}, FP {r['fp']}, FN {r['fn']}, TN {r['tn']}.",
        f"Confusion matrix at the deny threshold: TP {d['tp']}, FP {d['fp']}, FN {d['fn']}, TN {d['tn']}.",
        "",
        "The never-fraud baseline looks excellent on accuracy and catches nothing, which is why accuracy is not reported as a headline.",
        "",
        "## Where proposals land on the test split",
        "",
        "| route | legitimate | fraud |",
        "|---|---:|---:|",
    ]
    for route, c in m["routing_on_test"].items():
        lines.append(f"| {route} | {c['legit']:,} | {c['fraud']} |")
    lines += ["", "## Recall by fraud pattern (test, at the review threshold)", "", "| pattern | n | caught | recall |", "|---|---:|---:|---:|"]
    for pattern, c in m["recall_by_pattern_on_test"].items():
        note = "  (never seen in training)" if pattern == "slow_novel" else ""
        lines.append(f"| {pattern}{note} | {c['n']} | {c['caught_at_review_or_above']} | {_fmt(c['recall_at_review'])} |")
    lines += ["", "![precision-recall curve](pr_curve.png)", ""]
    return "\n".join(lines)


def ensure_model(risk_dir: Path, **kwargs: Any) -> Tuple[ModelScorer, Dict[str, Any]]:
    """Load the trained model, training it first if it does not exist yet."""
    risk_dir = Path(risk_dir)
    if not (risk_dir / THRESHOLDS_FILE).exists() or not (risk_dir / MODEL_FILE).exists():
        run_evaluation(risk_dir, make_plot=False, **kwargs)
    return load_scorer(risk_dir)
