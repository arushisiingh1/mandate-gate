# Gate walkthrough: read the code with the *why*

For when you have to defend this code out loud. It follows `src/mandate_gate/gate.py` top to bottom, then the small
modules it leans on. Each part says what the code does, **why it is that way**, and the question a reader is likely to ask.
Open the file next to this. If you cannot say a section in your own words, that section is not yours yet.

Names in `code font` are functions or classes you can search for.

---

## 0. The one-paragraph version

An agent hands the gate two signed messages: a **proposal** (what it wants to buy) and a **mandate** (what the user said it may
spend). `Gate.evaluate` runs eight checks in a fixed order and stops at the first failure. Rules run first. A risk score runs
last and can only move the answer toward *review* or *deny*. The result is written to a hash-chained log **before** anything
that moves money or budget is applied. A human approval is tied to the exact proposal it was shown. Any unexpected error is a
denial.

## 1. The five invariants (docstring at the top of `gate.py`)

| # | Invariant | Why it is stated as an invariant |
|---|---|---|
| 1 | Fail closed: any exception becomes a DENY | A crash that approves is the worst bug a gate can have |
| 2 | Risk can only tighten | The model is the least trustworthy component, so it gets the least power |
| 3 | No audit record, no spend | A purchase with no explanation is an accountability failure |
| 4 | An approval is bound to one exact proposal, single use, re-checked | Otherwise "approve $20" becomes "approve $290" |
| 5 | Every decision, denials included, is logged | Denials are the evidence an attack was tried |

Each is tested by name; `docs/MUTATION_REPORT.md` shows what happens when the code behind it is removed.

**Precision on invariant 3 (be ready to say this unprompted).** There is exactly one state change made *before* the log write:
`_check_replay` marks the nonce as used while the checks are still running. Everything that moves money or budget (the charge, the
reservation, the idempotency entry, the agent's history) is collected as `ctx.effects` and applied only *after* `self._audit.append`
succeeds. The nonce is the exception on purpose: if the log write then fails, the nonce stays burned, which is the safe direction
(a legitimate message must be re-signed; no money moved). The doc comment says "log first, then act", and this is the one honest
asterisk on it.

## 2. `Gate.evaluate` (the entry point)

1. **Take the lock.** One `RLock` around decide-and-commit, so two racing requests cannot both spend the last of the budget.
   *Why not finer-grained?* Correctness first; a single process is a stated limit.
2. **`_snapshot` both inputs.** `json.loads(json.dumps(x))` turns whatever the caller passed into plain data that nobody else holds a
   reference to. *Why:* the gate verifies a signature over one object and then reads fields from it. If that object could answer
   differently the second time (a dict subclass, or another thread), the bytes that were *verified* could differ from the bytes that
   were *used*. That is a time-of-check/time-of-use bug. Attack `A37` reproduces it and the mutation check proves the test depends
   on the fix. This was found in review, not designed in.
3. **Hash the input** (`input_hash`) for the log. If it is not hashable, hash its `repr` so even garbage leaves a trace.
4. **Run the checks** in `_run`. If anything raises, `_internal_error` returns a DENY (invariant 1).
5. **Build the log body and append it.** If the append fails, the decision is replaced by a DENY and the pending effects are
   thrown away.
6. **Only now apply the effects.** (Invariant 3.)

*Likely question:* "What if the process dies between the log write and the effects?" The log then says APPROVE with no charge
in memory. Nothing was spent, and the state is in memory anyway; a durable store with an atomic decide-and-commit is the real fix
and is listed under "not built".

## 3. The pipeline `_run` and why the order is what it is

`CHECK_ORDER = schema, signature, mandate, replay, duplicate, authority, velocity, risk`. Each `_check_*` returns `None` (passed)
or a `_Fail`. The first failure stops everything. The agent only ever sees the reason code, never the thresholds.

The principle: **cheap, stateless and authenticated checks first; anything that changes state or costs a model call last.**

### 1. `_check_schema`
Strict parse of the envelope and the proposal: exact key set, exact types (`bool` is not an integer), bounded lengths, `fullmatch`
regexes (so a trailing newline cannot slip past `$`), a closed category set, integer cents. *Why first:* nothing else can safely read
a field until the input has an exact shape, and we need `agent_id` to know which key to verify against. *Why strict, not
"liberal in what you accept":* coercing `"100"` to `100` is how look-alike and type-confusion bugs arrive. *Note:* `item` is free
text, so an injection phrase passes the schema *as data*. Nothing ever interprets it.

### 2. `_check_signature`
The signer must equal the `agent_id` in the payload; the registry is asked for that id **as an agent key**; revoked or unknown keys
fail with their own codes; then Ed25519 verification over `DOMAIN_PROPOSAL + canonical JSON`. *Why before replay:* an
unauthenticated sender must not be able to consume nonces or squat idempotency keys. Swap the order and anyone could burn a real
agent's nonces by guessing them.

### 3. `_check_mandate`
The mandate envelope is parsed, the signer looked up **as a user key**, the signature verified **before any field inside the
payload is interpreted**, and only then `parse_mandate`. Then the cross-checks: signer is the mandate's `user_id`, the mandate id and
agent id match the proposal, not revoked, inside `[not_before, expires_at)`. *Why verify before parsing:* parsing is interpretation.
You never interpret what you have not authenticated. *Why the proposal carries the mandate:* the user stays the author of consent;
the gate never looks a mandate up in its own store, which would make the gate the author.

### 4. `_check_replay`
Timestamp within ±120 s of the gate's clock, and the `(agent_id, nonce)` pair unseen; then the nonce is stored immediately, *even if
a later check denies*. *Why consume on deny:* each signed message is good for exactly one evaluation, so a denied message cannot be
fixed up and resent. *Why a window at all:* so the nonce table can be pruned (`_prune_nonces` keeps a nonce only while its timestamp
could still pass).

### 5. `_check_duplicate`
Looks up `(agent_id, idempotency_key)`. Same key and same **intent hash** returns the *original decision* (no second charge). Same key
and a *different* intent is `IDEMPOTENCY_CONFLICT`. *Why intent hash:* it covers everything except the per-attempt fields (nonce,
timestamp), so "a retry" means the same purchase, not just the same key. *Why replay before duplicate:* an exact resend must be a
denied **replay**. If duplicate ran first, an attacker could replay a captured message by presenting it as a retry and get a cached
approval. *Why duplicate before authority:* a retry should get the original answer even if the budget has moved since; re-evaluating
could double-charge or flip the answer. If the original was a REVIEW and the human later approved, `settle()` updates the stored
decision, so a retry returns the approval with the *same* charge id.

### 6. `_check_authority`
Category on the allowlist, currency equal, amount ≤ per-transaction cap, and `ledger.exposure + amount ≤ cumulative cap`. *Why
exposure, not spend:* `exposure` is committed charges **plus reservations for pending reviews**. A proposal waiting for a human has
not been paid, but it will be if approved, so it already counts. Without that, an agent could queue many reviews that each looked
affordable on their own.

### 7. `_check_velocity`
At most `velocity_max_approvals` (5) approvals **and pending reviews** per `velocity_window_s` (3600) per mandate. *Why:* the caps
alone do not stop one $4,000 purchase being split into twenty $199 ones if each is under the per-transaction cap and the total
is still within budget; velocity is the rate limit on the agent's behaviour. *Limit:* it is per mandate, so one agent holding two
mandates gets two budgets of velocity.

### 8. `_check_risk`
Only reached if every rule passed (`ctx.reached_risk`). No scorer configured: skip (rules-only). Otherwise build features, call the
scorer, and validate what comes back: a real number in [0, 1], not a bool, finite. **Any exception or invalid score becomes
`RISK_UNAVAILABLE`, outcome REVIEW**: a broken model sends the case to a human; it never approves and never silently denies.
Score at or above deny → DENY, at or above review → REVIEW, else pass. *Why "only tighten" is true by construction:* the function can
only return a `_Fail` (REVIEW or DENY) or `None` (no objection). There is no code path where it turns a failure into a pass, and a
failure earlier in the loop returns before this function is called. `tests/test_properties.py` checks that on 400 random cases and
`A39` checks that a perfect score cannot launder a bad proposal.

## 4. `_finalize` (turning a result into effects)

Builds the `Decision`, allocates a `charge_id` (approve) or `review_id` (review), and **queues effects instead of applying them**:
the idempotency entry, the ledger commit and the agent's history (approve), or the reservation and pending entry (review). Note the
comment on history: merchant familiarity is earned only by purchases that actually settle, so a denied or still-pending proposal
cannot make a new merchant look "known" to the model.

## 5. Human review: `resolve_review` and `_resolve`

A reviewer sees a `PendingReviewView` whose `payload_hash` is the approval token. `_resolve` checks, in order:

1. The review exists (unknown or already used → `REVIEW_NOT_FOUND`).
2. The approver id is a valid id.
3. **The token matches** (`hmac.compare_digest`, so a wrong token gives `REVIEW_BINDING_MISMATCH` and does *not* destroy the pending
   review; a typo should not cost the user the proposal).
4. From here the review is **consumed whatever the outcome** (single use).
5. Not expired (`review_ttl_s`), and the reviewer said yes.
6. **Re-check everything that could have changed while it sat in the queue:** agent key still valid, user key still valid, mandate not
   revoked, not expired, cumulative cap still has room.

*Why step 6:* a human "yes" does not outrank a key revoked after the proposal was queued. This check was **missing** in the first
version and was added in review; tests cover agent and user key revocation. *Why bind to `payload_hash`:* so the approval is for
this exact message, not for "the review with this id". *Honest limit:* the *approver* is a CLI prompt and is not authenticated;
the binding is to a proposal, not to a person.

## 6. The small modules

| Module | What to say |
|---|---|
| `canonical.py` | One byte encoding for signing and hashing: sorted keys, no whitespace, ASCII, **no floats** (money is integer cents), depth-limited. Floats are banned because two parties can print the same number differently. Not RFC 8785 and not RFC 9421; see "what I'd do next" in the README. |
| `signing.py` | Ed25519 over `DOMAIN || canonical_json`. Domain tags (`mandate-gate/v1/proposal\n`, `.../mandate\n`) mean a signature for one message type can never verify as another. `verify` never raises; any failure is `False`. `keypair_from_seed` is for demos and tests only. |
| `registry.py` | id → public key + **kind** (`agent` or `user`). Lookup is *for a role*: an agent key cannot sign a mandate, a user key cannot propose. Simulated identity: a local file, no proofing. |
| `envelope.py` | Wire shape `{payload, signature, signer}`; validates shape only. Content is parsed after verification. |
| `proposal.py` / `mandate.py` | Frozen dataclasses with strict `parse_*`. `intent_hash` defines "same purchase". The mandate rejects `per_txn > cumulative` and `expires_at <= not_before`. |
| `ledger.py` | Simulated charges plus **reservations**. `exposure` = committed + reserved. `in_window_count` counts both. `AgentHistory` feeds both the gate and the data generator so a feature cannot mean two things (train/serve skew). |
| `audit.py` | Each record hashes `prev_hash + canonical({seq, body})`; `verify` reports the first bad record. The file append is `flush` + `fsync`. Limits: no external anchor, so rewriting the whole file or truncating the tail is not detectable (a test documents it). |
| `agent.py` | The LLM's output is parsed against a strict schema (exact keys, bounded, duplicate keys and floats rejected) before it is signed; only five fields are the model's to control. Rejected output is logged by hash via `record_rejected_output`. |

## 7. Questions to practise with the code open

1. Point to the exact line where "the risk score can only tighten" becomes true. (`_check_risk` returns only `_Fail` or `None`, and
   `_run` returns on the first failure.)
2. Point to where the audit record is written and which effects come after. (`evaluate`, `ctx.effects`.)
3. What would the *first* state change be if the audit log were unwritable? (The nonce.) Is that safe? (Yes; say why.)
4. Walk one retry of an approved purchase through the checks. (New nonce passes replay; duplicate returns the original; nothing is charged.)
5. Walk the same message sent twice. (Second send fails `REPLAY` before duplicate is reached.)
6. Why does `_check_authority` use `exposure`, and where is the reservation created? (`_finalize` → `hold`.)
7. What happens if the scorer returns `float("nan")`? (`RISK_UNAVAILABLE`, REVIEW.)
8. What happens if `evaluate` is given a dict subclass that lies? (`_snapshot` copies it to plain JSON first; `A37`.)
9. What does `resolve_review` do with a *correct* token for a mandate revoked while pending? (Denies `MANDATE_REVOKED`, consumes the review.)
10. Which check would you delete if you were told the gate was too slow, and why would you refuse? (None; the model is the only
    expensive one, and it is already last and optional.)
