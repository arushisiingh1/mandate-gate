"""The demo, the CLI and the quickstart example run end to end, offline."""

import contextlib
import io
import runpy
import tempfile
import unittest
from pathlib import Path

from mandate_gate.audit import verify_file
from mandate_gate.cli import main

ROOT = Path(__file__).resolve().parents[1]
ARTIFACTS = ROOT / "artifacts" / "risk"

try:
    import sklearn  # noqa: F401

    HAVE_ML = True
except ImportError:  # pragma: no cover
    HAVE_ML = False


def run_cli(*argv):
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        code = main(list(argv))
    return code, out.getvalue()


class Demo(unittest.TestCase):
    def test_rules_only_demo_meets_every_expectation(self):
        with tempfile.TemporaryDirectory() as d:
            code, text = run_cli("demo", "--no-model", "--out", d)
            self.assertEqual(code, 0, text[-800:])
            self.assertIn("expectations met", text)
            self.assertNotIn("!! ", text)
            self.assertTrue(verify_file(Path(d) / "audit.jsonl").ok)
            self.assertTrue((Path(d) / "transcript.txt").exists())

    @unittest.skipUnless(HAVE_ML and (ARTIFACTS / "thresholds.json").exists(), "needs the ml extra and artifacts/risk")
    def test_demo_with_the_shipped_model_routes_risky_purchases_to_a_human(self):
        with tempfile.TemporaryDirectory() as d:
            code, text = run_cli("demo", "--risk-dir", str(ARTIFACTS), "--out", d)
            self.assertEqual(code, 0, text[-1200:])
            self.assertIn("linear reasons", text)
            self.assertIn("REVIEW", text)
            self.assertIn("HUMAN_APPROVED", text)
            self.assertIn("approval cannot be reused", text)
            self.assertIn("editing one record in a copy of the log is detected", text)
            self.assertNotIn("!! ", text)

    def test_demo_is_deterministic(self):
        with tempfile.TemporaryDirectory() as a, tempfile.TemporaryDirectory() as b:
            run_cli("demo", "--no-model", "--out", a)
            run_cli("demo", "--no-model", "--out", b)
            self.assertEqual((Path(a) / "audit.jsonl").read_text(), (Path(b) / "audit.jsonl").read_text())


class Cli(unittest.TestCase):
    def test_verify_log_ok_and_failed(self):
        with tempfile.TemporaryDirectory() as d:
            run_cli("demo", "--no-model", "--out", d)
            log = Path(d) / "audit.jsonl"
            code, text = run_cli("verify-log", str(log))
            self.assertEqual(code, 0)
            self.assertIn("OK", text)
            lines = log.read_text().splitlines()
            lines[3] = lines[3].replace('"result":"APPROVE"', '"result":"DENY"', 1)
            log.write_text("\n".join(lines) + "\n")
            code, text = run_cli("verify-log", str(log))
            self.assertEqual(code, 1)
            self.assertIn("FAILED at record 3", text)

    def test_missing_log_fails(self):
        code, _ = run_cli("verify-log", "/nonexistent/audit.jsonl")
        self.assertEqual(code, 1)


class Quickstart(unittest.TestCase):
    def test_example_runs_and_behaves(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            outcomes = runpy.run_path(str(ROOT / "examples" / "quickstart.py"), run_name="not_main")["main"]()
        got = {label: result for label, result, _ in outcomes}
        self.assertEqual(got["in-mandate book"], "APPROVE")
        self.assertEqual(got["over the per-transaction cap"], "DENY")
        self.assertEqual(got["category not allowed"], "DENY")
        self.assertEqual(got["model output that breaks the schema"], "REJECTED")
        self.assertIn("1 charge(s)", out.getvalue())
        self.assertIn("chain valid: True", out.getvalue())


if __name__ == "__main__":
    unittest.main()
