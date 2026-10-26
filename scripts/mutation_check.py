#!/usr/bin/env python3
"""Prove that every gate check is load-bearing.

For each gate check (and a few other safety-critical pieces) this script breaks
it on purpose, runs the fast tests, and requires at least one to fail. A test
suite that still passes with a check removed was never testing that check.

How a "mutant" is made: the check still runs (so its side effects and the data
it prepares for later checks still happen) but its verdict is ignored. The
patch is applied in this process only, by monkeypatching. The production code
contains no switch, flag or environment variable that can turn a check off.

Usage:
    python scripts/mutation_check.py                      # exit 1 if any mutant survives
    python scripts/mutation_check.py --report docs/MUTATION_REPORT.md
"""

from __future__ import annotations

import argparse
import io
import sys
import unittest
from contextlib import ExitStack
from pathlib import Path
from typing import Callable, Dict, List, Tuple
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT))

from mandate_gate import audit as audit_mod  # noqa: E402
from mandate_gate import gate as gate_mod  # noqa: E402
from mandate_gate import ledger as ledger_mod  # noqa: E402
from mandate_gate import proposal as proposal_mod  # noqa: E402
from mandate_gate import registry as registry_mod  # noqa: E402
from mandate_gate.signing import DOMAIN_MANDATE, DOMAIN_PROPOSAL  # noqa: E402

# Fast tests only: the model-training, notebook and demo tests do not exercise gate checks.
SKIP_MODULE_PARTS = ("risk_pipeline", "demo", "cli", "examples", "mutation")


def ignore_verdict(original: Callable) -> Callable:
    def wrapper(self, ctx):
        original(self, ctx)  # side effects and ctx preparation still happen
        return None  # ...but the check can never fail

    return wrapper


def _lenient_keys(obj, expected, what):
    """Like require_exact_keys, but silently accepts unexpected extra fields."""
    if not isinstance(obj, dict) or not set(expected) <= set(obj):
        raise proposal_mod.ValidationError(f"{what}: missing fields")
    return obj


def _lookup_ignoring_kind(self, principal_id, kind):
    entry = self._entries.get(principal_id)
    if entry is None:
        return "unknown", None
    if entry.revoked:
        return "revoked", None
    return "ok", entry.public_b64


_real_verify = gate_mod.verify


def _verify_any_domain(public_b64, domain, payload, signature_b64):
    """Accept a signature made under either domain tag (no domain separation)."""
    return _real_verify(public_b64, DOMAIN_MANDATE, payload, signature_b64) or _real_verify(
        public_b64, DOMAIN_PROPOSAL, payload, signature_b64
    )


def _fake_append(self, body):
    return {"seq": -1, "prev_hash": "", "body": body, "hash": ""}  # "logs" nothing


Mutant = Tuple[str, str, Callable[[ExitStack], None]]


def _mutants() -> List[Mutant]:
    out: List[Mutant] = []

    def check(name: str) -> Mutant:
        attr = f"_check_{name}"

        def apply(stack: ExitStack) -> None:
            stack.enter_context(mock.patch.object(gate_mod.Gate, attr, ignore_verdict(getattr(gate_mod.Gate, attr))))

        return (f"check: {name}", f"the {name} check can no longer deny anything", apply)

    for name in gate_mod.Gate.CHECK_ORDER:
        out.append(check(name))

    def patch(target, attr, value):
        return lambda stack: stack.enter_context(mock.patch.object(target, attr, value))

    out += [
        ("approval binding", "a human approval is accepted for any proposal", patch(gate_mod.Gate, "_binding_ok", lambda self, p, h: True)),
        ("input snapshot", "the gate reads the caller's live object instead of a copy", patch(gate_mod, "_snapshot", lambda obj: obj)),
        ("audit log", "decisions are no longer written to the audit log", patch(audit_mod.AuditLog, "append", _fake_append)),
        ("review reservation", "a pending review no longer holds budget", patch(ledger_mod.Ledger, "reserve", lambda self, r: None)),
        ("key kind (agent vs user)", "a user key is accepted as an agent key and vice versa", patch(registry_mod.KeyRegistry, "lookup", _lookup_ignoring_kind)),
        ("domain separation", "a signature made for one message type verifies as the other", patch(gate_mod, "verify", _verify_any_domain)),
        ("strict proposal keys", "proposals may carry unexpected extra fields", patch(proposal_mod, "require_exact_keys", _lenient_keys)),
    ]
    return out


def _load_tests() -> unittest.TestSuite:
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    for path in sorted((ROOT / "tests").glob("test_*.py")):
        if any(part in path.stem for part in SKIP_MODULE_PARTS):
            continue
        suite.addTests(loader.loadTestsFromName(f"tests.{path.stem}"))
    return suite


def _run() -> Tuple[int, List[str]]:
    result = unittest.TextTestRunner(stream=io.StringIO(), verbosity=0).run(_load_tests())
    failed = [t.id().replace("tests.", "") for t, _ in result.failures + result.errors]
    return result.testsRun, failed


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--report", help="write a markdown report to this path")
    args = parser.parse_args()

    ran, failed = _run()
    if failed:
        print(f"Baseline is not green ({len(failed)} failing). Fix the tests first.")
        for name in failed[:10]:
            print("  ", name)
        return 2
    print(f"baseline: {ran} tests pass\n")

    rows: List[Dict] = []
    survivors = []
    for label, meaning, apply in _mutants():
        with ExitStack() as stack:
            apply(stack)
            _, killed_by = _run()
        rows.append({"label": label, "meaning": meaning, "killed_by": killed_by})
        status = f"killed by {len(killed_by):>3} tests" if killed_by else "SURVIVED"
        print(f"{label:<28} {status}")
        if not killed_by:
            survivors.append(label)

    if args.report:
        Path(args.report).write_text(_report(ran, rows))
        print(f"\nwrote {args.report}")

    if survivors:
        print(f"\n{len(survivors)} mutant(s) survived: {', '.join(survivors)}")
        return 1
    print(f"\nall {len(rows)} mutants killed")
    return 0


def _report(ran: int, rows: List[Dict]) -> str:
    lines = [
        "# Mutation check",
        "",
        "Each row disables one safety-critical piece of the gate (see `scripts/mutation_check.py`) and re-runs the",
        f"fast test suite ({ran} tests). A row with no killing test would mean the piece is not actually tested.",
        "Regenerate with `python scripts/mutation_check.py --report docs/MUTATION_REPORT.md`.",
        "",
        "| Disabled | Effect | Tests that fail | Example |",
        "|---|---|---:|---|",
    ]
    for r in rows:
        example = r["killed_by"][0] if r["killed_by"] else "**none: SURVIVED**"
        lines.append(f"| {r['label']} | {r['meaning']} | {len(r['killed_by'])} | `{example}` |")
    lines.append("")
    return "\n".join(lines)


if __name__ == "__main__":
    sys.exit(main())
