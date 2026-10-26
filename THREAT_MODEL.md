# Threat model

One page, written before the gate was built and updated when the review found gaps. Every row names the control
that stops the threat and the test that proves it, so the claims can be checked rather than believed.

## What is being protected

**Money that moves without the user's authority.** The asset is the user's budget. The user's consent is a signed
mandate; everything else is an attempt to spend beyond it, in someone else's name, more than once, or by talking the
agent into it.

## Who is trusted, and who is not

| Party | Trust | Why |
|---|---|---|
| The deterministic gate | **Trusted** | Plain code in a fixed order. It is the only thing that approves a purchase. |
| The user's signing key | Trusted (assumed) | A mandate is only as good as the key. Identity proofing is **not built**. |
| The agent runtime (holds the agent key) | Semi-trusted | It signs, but it can only sign what passed the strict output schema. |
| **The LLM** | **Untrusted** | It can be prompt-injected, jailbroken or wrong. It *proposes*; it decides nothing. |
| Merchant page text | **Untrusted data** | Never instructions. The gate never reads free text; the Claude agent's prompt marks it as data. |
| The risk model | Advisory | It can only make a decision stricter. A broken model fails to a human, not to an approval. |
| The human reviewer | Trusted but **not authenticated** | A CLI prompt. Their approval is bound to one exact proposal. |

Trust boundary: everything that crosses into the gate (`evaluate(proposal, mandate)`) is treated as hostile input.

## Threats, controls, evidence

| # | Threat | Control | Test |
|---|---|---|---|
| T1 | Forge, edit or re-target a proposal | Ed25519 signature over canonical JSON, checked against the registered key of the *named* agent; domain-separated | `A01`-`A08` |
| T2 | Use one key for another role (user key as agent key, agent signs a "mandate") | Registry stores a `kind` per key; mandates verify only against `user` keys | `A06`, `A09`, `A10`, `mutation: key kind` |
| T3 | Sign for the wrong message type (proposal signature as mandate signature) | Domain tag in every signature | `A07`, `A14`, `mutation: domain separation` |
| T4 | Spend with no, expired, altered, foreign or revoked consent | Mandate must verify against the user's key, name this agent, be inside its validity window and not be revoked | `A09`-`A19` |
| T5 | Resend a valid signed message | Nonce consumed on first sight (even if denied) + timestamp window | `A20`-`A22` |
| T6 | Double-charge on a legitimate retry | Idempotency key returns the original decision; same key with a different intent is a conflict, not a retry | `A23`, `A24` |
| T7 | Exceed per-transaction / cumulative caps, or use a disallowed category or currency | Authority check against the signed mandate; pending reviews *reserve* budget | `A25`-`A28` |
| T8 | Split one big purchase into many small ones | Velocity limit: at most N approvals (and pending reviews) per window | `A29` |
| T9 | Race many requests at the last of the budget | One lock around decide-and-commit | `A30` |
| T10 | Smuggle behaviour through malformed or look-alike input (extra fields, floats, bools, Cyrillic letters, control characters, oversized strings) | Exact-key, exact-type, bounded schemas; floats banned from signed data; closed category set | `A31`-`A34` |
| T11 | Prompt injection: scraped page text steers the agent | The gate never interprets text. Injected text can change only the five schema fields, and the rules judge those. Extra fields are rejected before signing. | `A35`, demo `S7a`-`S7c` |
| T12 | Make the signature check and the parser see different data (parser differential, time-of-check/time-of-use) | Input is copied once into plain JSON data before it is verified or parsed | `A37`, `mutation: input snapshot` (found in review; see AI log) |
| T13 | Reuse a human approval for another proposal, twice, or after things changed | Approval carries the exact payload hash; single use; expires; mandate, agent key and user key are re-checked when it is used | `A38`, `HumanReview.*` |
| T14 | Launder a bad proposal through a good fraud score | Risk runs last and can only tighten; failed checks never reach it | `A39`, `test_properties` (400 random cases), `mutation: check risk` |
| T15 | The model or its explanations break | Score outside [0,1], an exception, or reason codes that fail the additivity check route to a human, never to approval | `A40`, `test_risk_model` |
| T16 | Spend with no record | The audit record is written *before* any state change that moves money or budget (charge, reservation, idempotency entry); an audit failure denies. The one earlier state change is consuming the nonce, which fails safe. Every decision, denials included, is logged | `EveryDecisionIsLogged`, `mutation: audit log` |
| T17 | Rewrite history | Hash chain: editing, deleting, reordering or inserting a record breaks verification at that record | `AuditChain.*` |
| T18 | Poisoned or swapped model file | Model is JSON (loading cannot execute code); its SHA-256 must match the frozen `thresholds.json` | `test_a_modified_model_file_is_refused` |

## Known gaps (not defended, on purpose or by scope)

- **In-mandate abuse.** A hijacked agent can spend *inside* the mandate. Caps bound the damage; only the advisory
  score (and a human) can notice the intent. The demo shows exactly this case (`S7c`).
- **State is in memory.** Nonces, idempotency keys, the ledger and pending reviews are lost on restart: after a restart
  a still-fresh message could be replayed once, and cumulative spend starts again from zero. A real deployment needs a
  durable store with the same atomic decide-and-commit.
- **Single process, one lock.** No multi-process or multi-region story.
- **Audit log has no external anchor.** Someone who can rewrite the whole file can recompute the whole chain, and
  truncating the tail is undetectable unless the head hash is published elsewhere (there is a test that documents this).
- **Identity is simulated.** The registry is a local file. There is no proofing and no human-to-agent binding.
- **The human approver is not authenticated.** The approval is bound to a proposal, not to a person.
- **Velocity is per mandate.** An agent holding two active mandates from the same user gets two budgets of velocity.
- **Clock.** The gate trusts its own clock; replay protection assumes it does not run backwards.
- **Denial of service.** Nothing rate-limits the gate itself (pending reviews are bounded by the velocity limit, nothing else is).
- **Signing format.** Canonical JSON, not an RFC 9421 HTTP message signature (the brief's stretch goal, not built).
- **Fraud model.** Trained and evaluated on synthetic data, and it partly learns a shortcut of the simulator
  (rare categories such as electronics and gift cards carry a large term). It is a plain linear model, so it cannot represent interactions. It has never seen real fraud and does not handle label delay or drift.
