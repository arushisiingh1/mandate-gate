# Decisions

For each module: what it does, one alternative that was rejected, and one way it can fail.

> **Status: draft for the author to own.** The project brief says these notes are written by the human before each
> module, as a check that they can defend the design. In this build they were drafted by Claude from the code as it
> stands, so they are a starting point to read, argue with and rewrite, not evidence that anyone has yet explained
> these modules out loud. Where a decision changed during review, the entry says so.

## canonical.py: one byte encoding for signing and hashing
Sorted keys, no whitespace, ASCII escapes, and **no floats anywhere**; money is integer cents. *Rejected:* RFC 8785 (JCS),
which supports floats but needs a number-formatting algorithm that is easy to get subtly wrong and not needed here.
*Fails if:* two parties canonicalise differently. Everything here is one codebase, so that cannot happen today, but it
is the first thing that breaks when another implementation (for example a TypeScript Worker) has to verify these signatures.

## signing.py: Ed25519 with a domain tag
Every signature covers `DOMAIN || canonical_json`, so a mandate signature can never verify as a proposal signature.
*Rejected:* a single signing context, simpler but one confused-deputy bug away from a user's signature authorising an agent's
message. *Fails if:* a private key leaks; there is no rotation or revocation beyond marking a registry entry revoked.
`keypair_from_seed` exists for demos and tests only and is labelled as such.

## registry.py: who a key belongs to
A local JSON file mapping an id to a public key and a **kind** (`agent` or `user`). A key is looked up *for a role*, so an
agent key cannot sign a mandate and a user key cannot propose a purchase. *Rejected:* one flat namespace of keys.
*Fails if:* whoever can edit the file can add themselves; this is simulated identity with no proofing.

## mandate.py: consent and delegated authority
The user signs per-transaction cap, cumulative cap, allowed categories, a currency, a validity window and the agent it
is for. The gate verifies the signature **before** it interprets any field. *Rejected:* a mandate the gate looks up by
id from its own store, which would make the gate the author of consent; carrying the signed mandate with each
proposal keeps the user as the author. *Fails if:* a user signs something too generous; the gate enforces the mandate, it
does not judge it.

## proposal.py / validation.py / agent.py (schema): hostile input, exact shapes
Exact keys, exact types (a `bool` is not an integer), bounded lengths, anchored regexes (`fullmatch`, so a trailing
newline cannot slip past `$`), and a closed set of categories. The model's output controls only five fields; identity,
mandate id, idempotency key and timestamp come from the runtime that holds the key. *Rejected:* "be liberal in what you
accept" coercion (`"100"` to `100`), which is how look-alike and type-confusion bugs arrive. *Fails if:* a legitimate
merchant name contains a character the pattern excludes, which is a false denial, the safe direction.
**Note:** `item` is free text, so injection phrases pass the schema as data. That is intended; nothing ever interprets it.

## gate.py: fixed order, first failure stops
`schema, signature, mandate, replay, duplicate, authority, velocity, risk`. Cheap, authenticated and
state-free checks come first, so an unauthenticated sender cannot consume nonces, squat idempotency keys or reach the
model. Order is a security property, not a style choice: see `docs/STUDY_GUIDE.md` for what breaks when each check
is removed, with the mutation report as evidence. *Rejected:* running every check and reporting all failures; it leaks
the thresholds to the agent (which the brief says must not happen) and runs state-changing checks for senders who
failed authentication. *Fails if:* a new check is added in the wrong place.
**Changed in review:** input is now copied once into plain JSON data before verification (a dict that answers
differently the second time it is read could otherwise make the signature check and the parser see different amounts).

## gate.py: replay versus duplicate
A **replay** is an attacker resending a valid signed message: stopped by a one-time nonce and a timestamp window.
A **duplicate** is a legitimate retry of one intent: it carries a fresh nonce but the same idempotency key, and gets the
original decision back with no second charge. Reusing a key for a *different* intent is a conflict and is denied.
The nonce is consumed even when a later check denies the proposal. *Rejected:* treating the idempotency key as the replay
guard, which lets an attacker replay a message by sending it as a "retry". *Fails if:* the process restarts: state is in
memory, so one still-fresh message could be replayed once (see the threat model).

## gate.py: velocity and reservations
At most N approvals per window **per mandate**, and a proposal waiting for a human *reserves* its amount and counts toward
the window straight away. That stops a $4,000 purchase being split into twenty $199 ones, and stops an agent queueing many
reviews that each looked affordable alone. *Rejected:* counting only settled charges, which leaves the queue as a loophole.
*Fails if:* an agent holds several mandates (each gets its own velocity budget).

## gate.py: human approval
An approval carries the **payload hash** of the exact proposal it was shown, is single use, expires, and re-checks the agent
key, the user key and the mandate when it is used. A wrong token does not destroy the pending review. *Rejected:* a bare
`approve(review_id)`, which would let an approval for a $20 purchase be applied to a $290 one under the same id.
*Fails if:* the approver is impersonated; the CLI prompt does not authenticate a person.
**Changed in review:** the re-check of agent and user key revocation was missing and was added.

## gate.py: audit before action, fail closed
The audit record is written before the charge, the idempotency entry or the reservation is applied, and any exception becomes
a denial. No record means no spend. *Rejected:* charge first, log after, which can leave spend that no log explains.
*Fails if:* the log is writable but the disk is full: the gate then denies everything, which is the safe failure.

## audit.py: hash chain
Each record commits to the previous record's hash; verification reports the first bad record. *Rejected:* a signed
log (needs another key to protect) and an external ledger (out of scope). *Fails if:* an attacker can rewrite the whole
file and recompute every hash, or truncate the tail; there is no external anchor (a test documents this limit).

## risk/features.py and ledger.AgentHistory: one feature path
The same `build_features` and `AgentHistory` serve training and the gate, so a feature cannot mean one thing in training and
another in production. *Rejected:* a separate feature pipeline in the notebook (classic train/serve skew).
*Fails if:* a feature is added to one path and not the other; a test rebuilds features from the generated rows to catch it.

## risk/synth.py: synthetic fraud
About 1% fraud from four patterns the author wrote, with overlapping legitimate behaviour, one pattern that exists only in the
last 20% of time, and only rule-passing traffic (what the model would see in production). *Rejected:* a public dataset
(licensing, and it would hide how much the result depends on how the data was made). *Fails if:* read as evidence of real
performance. It is not, and it contains a shortcut (some categories are rare for legitimate agents).

## risk/model.py: a deliberately small model
**Changed twice; the final choice is the smallest one.** The brief asks for XGBoost or LightGBM with SHAP reasons. Neither could be
installed where this was built, so the first draft used scikit-learn gradient boosting with an exact TreeSHAP written from scratch
(tested against brute-force Shapley values). That worked, but it was several hundred lines of subtle code to defend for a model that is
only advisory. Replacing it with a plain **logistic regression** scored PR-AUC 0.777 against 0.807 on the synthetic test split, a gap
the data is too simple to make meaningful, and the reason codes became trivially exact: each feature's term is
`weight x (value - mean) / scale`, and the terms plus the intercept equal the log-odds. The saved model is JSON (weights, means, scales)
pinned by SHA-256, so loading cannot execute code. *Rejected:* gradient boosting plus TreeSHAP (more code to defend than the component
deserves), a pickle (loading executes code), and writing "SHAP" on an approximation. *Fails if:* the real signal is an interaction a
linear model cannot represent (for example "large AND new merchant AND night"), which is the cost of the choice; the notebook says so.
It also leans on a shortcut in the synthetic data: electronics and gift cards are rare in legitimate traffic, so a purchase in those categories carries a large term (about +5 log-odds for electronics) whatever else is true. The lesson recorded here: the model is the part
of this project that matters least to its safety, so it got the least code.

## risk/thresholds.py and evaluate.py: thresholds on validation only
Review threshold: highest score keeping validation recall at 90%. Deny threshold: lowest score keeping validation precision at
95%. Written to disk, then the test split is scored for the first time. *Rejected:* tuning on test, or a random split.
*Fails if:* the validation window is unrepresentative, which the test results show: recall at the review threshold falls from
0.90 on validation to 0.75 on test, mostly because of the unseen pattern.
**Changed in review:** thresholds were rounded to 6 decimals, which could push one above the boundary example and miss the
recall target (a test caught it). They are now stored exactly.

## agent.py: mock first, Claude optional
A scripted agent for offline demos, a deliberately gullible one that obeys injected page text, and an optional Claude-backed
one whose prompt marks page text as untrusted. Whatever any of them says goes through the same strict schema and gate.
*Rejected:* depending on the model's good behaviour for safety. *Fails if:* read as proof about LLM robustness: the Claude
agent is **untested against the real API** and untuned.
