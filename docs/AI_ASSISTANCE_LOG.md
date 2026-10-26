# AI-assistance log

The brief's rule: keep a running log of what I/Claude scaffolded, what the I wrote, what was edited, and what was found wrong in Claude's output. This is that log for the build that produced this repository. 

## Who did what

| Work | Who | Notes |
|---|---|---|
| Gate check order, thresholds, invariants, mandate format | **Mine** | Written in full following the brief. Hardened by Claude (below). |
| Key handling, canonical JSON, signing, registry, envelope, validation | Mine | Reviewed by Claude; no defects found. |
| Audit log, ledger, agent (mock, gullible, Claude-backed), CLI, demo, synthetic data, evaluation, CI | Mine | Reviewed by Claude; defects found and fixed (below). |
| Risk model: logistic regression with exact reason codes, JSON file pinned by hash | Mine | Round 2. Replaced a gradient-boosting + hand-written TreeSHAP version (round 1) after feedback; the replacement was measured first (PR-AUC 0.777 vs 0.807). |
| Gate hardening: input snapshot, key-revocation re-check on approval, logging of rejected agent output | **Claude** | Each has a test and (where it applies) a mutation check. |
| All 189 tests, including the 40 attack scenarios | **Claude** | Outlined by me, written by Claude, and reviewed. |
| `scripts/mutation_check.py` and `docs/MUTATION_REPORT.md` | **Claude** | Implements the brief's "disable each check, confirm a test fails". |
| Risk notebook (`scripts/build_notebook.py`) | **Claude** | Split, metrics and thresholds follow the pre-existing evaluation code, not a human's choices. |
| `README.md`, `THREAT_MODEL.md`, `DECISIONS.md`, `docs/STUDY_GUIDE.md`, `docs/GATE_WALKTHROUGH.md`, `docs/INTERVIEW_PREP.md`, this file, `examples/quickstart.py` | Mine | Drafts. The web research behind the Web Bot Auth notes was done once, on 2026-10-23, from the cited pages. |

## What I found wrong (in my raw code, and in Claude's work)

In my code:

1. **Reason codes were not SHAP** when XGBoost was missing (occlusion, which ignores interactions) while I had initially planned for SHAP.
   First replaced with an exact TreeSHAP tested against brute force; then, after feedback that the model should be tiny, replaced again by a logistic regression whose reason codes are exact by construction (so the hand-written TreeSHAP, XGBoost backend and their tests were deleted).
2. **Model stored as a pickle** (loading executes code, in a security project). Change to plain JSON, pinned by SHA-256; there is no pickle left.
3. **A human approval was not re-checked against key revocation.** If an agent's key was revoked while its proposal waited in the
   queue, a human "yes" would still charge. Fixed; tested for agent and user keys.
4. **Time-of-check/time-of-use on the input.** The gate verified the signature on the caller's object and then parsed the same live
   object; a dict that answers differently when read twice produced a charge for an unsigned amount. Fixed by copying input once to
   plain JSON; `A37` reproduces it and the mutation check proves the test depends on the fix.
5. **Thresholds were rounded to 6 decimals**, which could push one above the boundary example and miss the validation recall target
   (0.8995 against 0.90). Caught by a test written to check the target; now stored exactly.
6. **Rejected agent output left no audit record**, against "every decision is logged". Now logged (hash only, never the text).
7. **`demo --no-model` exited non-zero** because two scenarios assumed the model. Expectations are now mode-aware.
8. Smaller: unused `shap` dependency; the CI file and demo referenced `scripts/mutation_check.py` and `tests/test_attacks.py`, which
   did not exist; the model directory defaulted to an untracked `var/` path.

In Claude's work (pointed out to Claude for self-correction, solutions reviewed):

- A pruning test asserted the wrong thing (the code was right); corrected.
- The first "domain separation" mutant broke all mandate verification and so "killed" 90 tests for the wrong reason; replaced with a mutant that
  accepts either domain, which only the two cross-domain scenarios catch.
- A notebook cell contained `assert … or True`, which can never fail; removed.
- Reading the reason codes exposed that the model leans on category (first `gift_cards`, +11 log-odds, with the boosted model; with the
  logistic model `electronics` carries about +5), because those categories are rare in the generator's legitimate traffic. That is a
  shortcut in the *synthetic data*; it is disclosed in the notebook, README and threat model rather than tuned away.


## Review comments and what was done

The feedback after reading the brief, and how each point was handled.

| Comment | Decision | What changed |
|---|---|---|
| The gate design is strong; know it fully and be able to defend all of it | Accepted | Added `docs/GATE_WALKTHROUGH.md` (gate.py read top to bottom with the reasoning) and `docs/INTERVIEW_PREP.md`; extended the study guide (these are private files, not included in the repo but available upon request)|
| The fraud model is the least important part; keep it tiny, put the effort into the gate and the writing | Accepted, after measuring | Logistic regression measured at PR-AUC 0.777 against 0.807 for the boosted model; swapped; TreeSHAP, XGBoost backend and pickle deleted (about 300 fewer lines in `risk/`; 13 TreeSHAP tests replaced by 12 simpler model tests); README and DECISIONS now lead with the gate |
| Stay in Python | Accepted | No change |
| RFC 9421 / Web Bot Auth: keep as "what I'd do next", but know and name it | Accepted | README "What I would do next"; researched the mapping (INTERVIEW_PREP section 6) |
| Be upfront about overlap with the team's existing gate | Accepted, with a caution | README "Relationship to existing work" and INTERVIEW_PREP section 3. I have not seen that gate, so the doc talked about what my work adds, not what the other lacks |
| Smaller build, same write-up | Accepted for the model; no other code was removed | The attack suite, mutation check and gate are unchanged; no new features were built |
| Put the saved hours into making the gate bulletproof | Partly | Re-read the gate end to end; found no new defect, but made one claim precise (nonce before audit). It is not proof there are none |

## How the work was checked

| My check | What was done here | Still have to check |
|---|---|---|
| Disable each gate check and confirm a test fails | Done by script, 15 mutants, all killed (`docs/MUTATION_REPORT.md`) | Try a handmade mutant of my own |
| Recompute precision and recall by hand from the confusion matrix | A test and a notebook cell do it from the confusion counts | Do it once with pencil on the printed matrix |
| Check the split for leakage | Time-ordered; tests recompute history features from earlier rows only; thresholds-on-disk-before-test is asserted with a spy | Read `synth.py` for leakage *by construction*, which tests cannot see (DONE) |
| Read every diff before committing | I did do this! | None |
| Explain each module aloud, then be quizzed | Not done | `docs/STUDY_GUIDE.md` (private file)|

## Limits of this build

- **Not run:** the Claude-backed agent against the real API (a fake client is tested); `pip install .` (the sandbox's
  setuptools fails on even a trivial package, so only the metadata, package discovery and entry point were checked); pytest (the tests
  are `unittest` classes, run with `python -m unittest`, and are written to be collected by pytest unchanged); the GitHub Actions workflow.
- **The notebook's outputs were produced by `scripts/build_notebook.py`,** a small executor, because Jupyter could not be installed.
  Open it in Jupyter and run all to refresh it.
- Everything about fraud performance is on synthetic data.
