"""Command-line entry point: ``mandate-gate`` or ``python -m mandate_gate``."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import List, Optional

from .audit import verify_file

# The trained model that ships with the repository. ``demo`` and
# ``evaluate-risk`` both default to it; ``evaluate-risk`` regenerates it.
DEFAULT_RISK_DIR = "artifacts/risk"


def _cmd_demo(args: argparse.Namespace) -> int:
    from .demo import run_demo

    risk_dir = None if args.no_model else Path(args.risk_dir)
    if risk_dir is not None:
        try:
            import sklearn  # noqa: F401
        except ImportError:
            print("The risk model needs the ML extras: pip install 'mandate-gate[ml]'")
            print("(or run with --no-model to see the rule-only gate)")
            return 2
    return run_demo(Path(args.out), risk_dir, interactive=args.interactive)


def _cmd_verify_log(args: argparse.Namespace) -> int:
    result = verify_file(Path(args.path))
    if result.ok:
        print(f"OK: {result.records} records, head hash {result.head_hash}")
        return 0
    print(f"FAILED at record {result.bad_seq}: {result.error}")
    return 1


def _cmd_evaluate_risk(args: argparse.Namespace) -> int:
    from .risk.evaluate import run_evaluation

    metrics = run_evaluation(Path(args.out), seed=args.seed)
    print(json.dumps({k: metrics[k] for k in ("model_kind", "explanation_method", "thresholds", "prevalence", "model", "never_fraud_baseline")}, indent=2))
    print(f"\nWrote model, frozen thresholds, metrics.json, report.md and pr_curve.png to {args.out}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="mandate-gate", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    demo = sub.add_parser("demo", help="run the offline end-to-end demo (exits 1 if any scenario deviates)")
    demo.add_argument("--out", default="demo_out", help="where to write audit.jsonl and transcript.txt")
    demo.add_argument(
        "--risk-dir",
        default=DEFAULT_RISK_DIR,
        help="directory with the trained model and frozen thresholds (trained on first use if absent)",
    )
    demo.add_argument("--no-model", action="store_true", help="rules only, no risk model")
    demo.add_argument("--interactive", action="store_true", help="act as the human reviewer at the prompt")
    demo.set_defaults(func=_cmd_demo)

    verify = sub.add_parser("verify-log", help="verify an audit log's hash chain")
    verify.add_argument("path")
    verify.set_defaults(func=_cmd_verify_log)

    ev = sub.add_parser("evaluate-risk", help="train and evaluate the risk model on synthetic data")
    ev.add_argument("--out", default=DEFAULT_RISK_DIR, help="where to write the model, thresholds and report")
    ev.add_argument("--seed", type=int, default=7)
    ev.set_defaults(func=_cmd_evaluate_risk)
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    sys.exit(main())
