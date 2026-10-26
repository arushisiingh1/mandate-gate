# Interview prep: owning Mandate Gate

This is for the person who will present the project. It is not part of the product. Delete it before publishing if you prefer;
nothing else links to it except the README's document table.

The goal is not to sound polished. It is for someone who reads the code and keeps asking *why* to find that you have an answer, or
that you say "I don't know, here is how I'd find out", which is also a good answer.

## 1. Be straight about how this was built (do this first)

The brief says "I am writing the project myself and using Claude Code the way I would on a team." **This repository was not built
that way.** Claude played developer and assistant, and started from a pre-existing implementation of unknown authorship
([AI_ASSISTANCE_LOG.md](../AI_ASSISTANCE_LOG.md) has the full account). That is fine to publish, and the log already says so, but it
changes what you can truthfully say:

- Do **not** say "I wrote the gate." Say what is true after you have done the work: "I scoped it, I reviewed and rewrote X, I broke
  it with Y, Claude drafted the rest."
- Before you publish, **edit the log to describe what you actually did** (the diffs you read, the modules you rewrote, the things you
  changed your mind on). It currently records that no human review happened, because none had.
- The cheap way to make it yours is to do the things the log lists as still open: rewrite `DECISIONS.md` in your words, do the
  explain-aloud, recompute one confusion matrix by hand, and try to break the gate with an attack of your own (add `A41`).

If an interviewer asks "what did the AI write?", the strong answer is specific: "The first draft of the tests and the model code.
I found these five bugs in review, here is the one I'm proudest of (the check-then-use bug in `evaluate`), and here is a test I wrote
that it had missed."

## 2. The 60-second pitch

> Agents can already shop; accountability is the hard part. I built a small system where an LLM agent *proposes* purchases and plain
> deterministic code *decides* them. The user signs a mandate with caps, categories and an expiry. The gate runs eight checks in a
> fixed order: schema, signature, mandate, replay, duplicate, authority, velocity, and last an advisory risk score that can only make
> the answer stricter. Every decision, denials included, goes into a hash-chained log before any money moves. I wrote 40 attack
> scenarios that try to push unauthorised spend through, and a script that disables each check in turn to prove a test fails. The
> fraud model is deliberately small and on synthetic data, and the README has a table that says exactly what is real and what is
> simulated.

## 3. Say the overlap out loud before anyone asks

The brief says the core pattern overlaps with the trust gate Adam built, on purpose, because it is the pattern the team works with.
So say that first, in your own words:

> "I know this follows the pattern the Agent Trust team already uses: signed identity, deterministic checks, risk as advisory. I
> built on that on purpose rather than inventing a different design. What I added is: a risk score that can only tighten a decision
> and explains itself with reason codes; idempotency keys on top of nonces, so replay and legitimate retry are different cases;
> cumulative caps and a velocity limit, with pending reviews counting against both; a hash-chained log; and an attack suite with a
> mutation check."

**One caution:** you have not (as far as this repo knows) read Adam's code. Say "I added", never "his doesn't have". If you can read
his gate before the interview, do, and edit the list above to what is actually different.

## 4. Resume and GitHub bullets (edit to what you can defend)

Pick two or three. Every number below is reproducible from the repo.

- Built **Mandate Gate**, a deterministic authorization layer for AI shopping agents: Ed25519-signed user mandates and agent
  proposals, an eight-check fail-closed gate (signature, mandate, replay, idempotency, caps, velocity, advisory risk), human review
  bound to the exact proposal, and a hash-chained audit log. Python, 189 tests.
- Wrote a **40-scenario attack suite** and a **mutation check** (15 mutants, all killed) that disable each gate check in turn and
  confirm a test fails; found and fixed a time-of-check/time-of-use bug where the signature check and the parser could see different
  data.
- Added an advisory fraud score (logistic regression, exact reason codes) evaluated with fraud-appropriate metrics (PR-AUC against a
  never-fraud baseline, time-ordered split, thresholds frozen before the test set), and documented what is real and what is
  simulated.

Avoid on a resume: "production", "secure", "prevents fraud". Say "prototype" and "synthetic".

## 5. Questions to expect, with honest answers

Short answers you can expand. Where the answer is "this is a limit", say it with confidence; limits you named yourself are a
strength.

### Design

| Question | Answer |
|---|---|
| Why does code own the decision? | A model can be talked into things (prompt injection). A rule can be tested, explained and inspected. The model proposes; it does not decide. |
| Why this check order? | Cheap, stateless, authenticated checks first; state-changing or expensive checks last. Concretely: signature before replay so strangers cannot burn nonces; replay before duplicate so a resend cannot pass as a "retry"; duplicate before authority so a retry gets the original answer; risk last because it is advisory and costs a model call. See [STUDY_GUIDE](STUDY_GUIDE.md). |
| Replay vs duplicate? | Replay: an attacker resending a valid signed message, stopped by the nonce and a time window. Duplicate: a legitimate retry of one intent, which carries a fresh nonce and the same idempotency key and gets the first result back. Same key with a different intent is a conflict, not a retry. |
| Why is the nonce consumed even on a denial? | One signed message is good for exactly one evaluation. Otherwise a denied message could be adjusted around and resent. |
| What does "risk can only tighten" mean in code? | `_check_risk` can only return REVIEW or DENY or "no objection", and it is only reached if every rule passed. There is no path that turns a failure into a pass. Checked by a 400-case randomised test and `A39`. |
| Why write the audit record before the charge? | "No record, no spend." If the log write fails the decision becomes a DENY. One honest asterisk: the nonce is burned before the log write, in the safe direction. |
| What is the human approval bound to? | The payload hash of the exact proposal shown, single use, expiring, and the keys and mandate are re-checked when it is used (a revoked key outranks a human yes). The approver is not authenticated. |
| What was the check-then-use bug? | The gate verified a signature over the caller's object and then read fields from the same live object. A dict that answers differently the second time yields a charge for an unsigned amount. Fix: copy input to plain JSON once. Test `A37`; the mutation check shows the test fails without the fix. |
| Why ban floats? | Two parties can print the same number differently, which breaks signatures. Money is integer cents. |
| Why domain-separated signatures? | So a signature for a mandate cannot verify as a signature for a proposal. |
| What happens on restart? | State is in memory: a still-fresh message could be replayed once and spend restarts from zero. A real system needs a durable store with atomic decide-and-commit. |
| How would it scale? | It would not as written: one process, one lock. The shape that scales is the same checks over a transactional store keyed by mandate. Say so. |

### Model and evaluation

| Question | Answer |
|---|---|
| Why is the model so small? | It is advisory and the gate is safe whether it is good, bad or missing. Effort belongs in the part that has to be right. It is a logistic regression whose reason codes are exact: each term is `weight × (value − mean)/scale`, and they add up to the score. |
| Why use a model at all if rules decide? | Rules catch known violations one at a time. A linear score adds up several individually acceptable signals (large, late at night, new merchant, rapid) that no single rule objects to, and says why. It does not model interactions; say that. It can only tighten. |
| Did you try something bigger? | Yes: gradient boosting with a from-scratch TreeSHAP. On this synthetic data it scored PR-AUC 0.81 against 0.78, a difference the data cannot even distinguish, for several hundred more lines to defend. I cut it. (The earlier version is described in `DECISIONS.md`.) |
| Why is 99% accuracy meaningless? | At 1% fraud, "always legitimate" scores 99% and catches nothing. Look at precision, recall and PR-AUC. Here the baseline's PR-AUC equals the fraud rate, 0.014; the model's is 0.777. |
| Your recall dropped from 0.90 to 0.75. | Yes, and the reason is known: one pattern appears only late in the timeline and was never in training (recall 0.04 on it). Reporting it rather than tuning it away is the point of a time-ordered split. |
| What does "thresholds frozen before test" protect against? | Choosing thresholds by peeking at the test set, which inflates the numbers. A test asserts the thresholds file exists before the test split is first scored. |
| What does the model actually learn? | Partly a shortcut in my simulator: legitimate agents rarely buy certain categories, so category carries a large term. The reason codes exposed it, which is part of why they are logged. Scores mean nothing outside the simulator. |
| Why not real data? | Public fraud sets are not about agent shopping, and a synthetic set makes the dependence on how it was generated visible. |

### Process and judgement

| Question | Answer |
|---|---|
| Why Python, not TypeScript on Workers? | Python is where I can reason fastest, and the point is the gate logic and the thinking about trust, not a deployment target. Porting is mostly plumbing. If it matters, the check logic is small enough to port. |
| Why not RFC 9421 from day one? | See section 6. Canonical-JSON Ed25519 is a fair prototype of the same idea; building HTTP message signatures from scratch is plumbing that would have cost hours without teaching anything about the gate. It is the first "what next". |
| What would you build next? | (1) Web Bot Auth / RFC 9421 signing on the envelope; (2) durable state and an external anchor for the audit head; (3) real identity binding and an authenticated approver; (4) late labels and drift monitoring for the model; (5) velocity across mandates. |
| What is the weakest part? | In-mandate abuse: a hijacked agent can spend *inside* the mandate, and only caps, the advisory score and a human can notice. Say it before they do. |
| How did you check it works? | Attack suite, 15 mutants (each check disabled in turn must fail a test), a 400-case property test, and a demo that exits non-zero on any deviation. |
| What did you get wrong? | Pick two from the log: the TOCTOU bug; the missing revocation re-check on human approval; thresholds rounded so they missed their own recall target (a test caught it). |

## 6. Web Bot Auth and RFC 9421: know it, name it, do not build it

Researched on 2026-10-23 from the sources below. This area is moving; treat details as "as of that date" and re-check before you
quote one.

**What it is.** RFC 9421 defines HTTP Message Signatures: a client signs selected parts of an HTTP request and sends the result in
the `Signature-Input` and `Signature` headers. **Web Bot Auth** is a proposal to use that so automated agents can identify
themselves to websites cryptographically, instead of by spoofable User-Agent strings or hard-to-attribute IP lists. It is an
individual IETF Internet-Draft (draft-meunier-web-bot-auth-architecture; later material has moved to related drafts), not a standard.
A recommended `Signature-Agent` header says where the agent's public key can be found; the key id is a JWK SHA-256 thumbprint; a
key directory is how the verifier finds the key. Test vectors use Ed25519 and RSASSA-PSS.

**Where it shows up in the market.** Cloudflare's October 2025 post on agentic commerce describes agents signing requests with
Ed25519, with `Signature-Input` parameters (`keyid`, `alg`, `nonce`, `created`, `expires`, `tag`), keys fetched from a well-known
directory, and a check that the nonce was not recently used. It says Visa's Trusted Agent Protocol and Mastercard's Agent Pay build
on Web Bot Auth by adding a tag that says whether the agent is browsing or paying.

**How it relates to this project (say this).** Web Bot Auth answers "which agent is this request from?" for the *merchant or
origin*. Mandate Gate answers a different question on the *spending* side: "had the user authorised this agent to spend this much
here?" They compose. The pieces map closely:

| Mandate Gate today | Web Bot Auth equivalent |
|---|---|
| Ed25519 over canonical JSON, with a domain tag | Ed25519 over an RFC 9421 *signature base* built from the request |
| `nonce` + `timestamp` window (replay check) | `nonce`, `created`, `expires` parameters |
| Registry lookup by agent id | `keyid` (JWK thumbprint) resolved through a key directory named by `Signature-Agent` |
| Message type separated by a domain tag | The `tag` parameter |
| Mandate (user-signed consent) | **No equivalent.** Web Bot Auth authenticates the agent; it carries no user spending authority |

What would change in the code: the envelope and `signing.py` (build and verify a signature base from headers), and the registry
(resolve keys by thumbprint from a directory). What would not: the mandate, the check order, the ledger, the log, the attack suite.
That separation is the argument for having kept the gate's logic independent of the wire format.

**Sources (read the first two):**
[Cloudflare: Securing agentic commerce](https://blog.cloudflare.com/secure-agentic-commerce/) ·
[IETF draft: Web Bot Auth architecture](https://datatracker.ietf.org/doc/html/draft-meunier-web-bot-auth-architecture) ·
[IETF draft: HTTP Message Signatures for Bots (June 2026)](https://www.ietf.org/archive/id/draft-meunier-webbotauth-httpsig-protocol-00.html)

## 7. How to drill (the part that matters)

1. **Say, do not read.** Pick a module, close the code, explain it aloud in under a minute. Record yourself once; it is
   uncomfortable and works.
2. **Work through [GATE_WALKTHROUGH.md](GATE_WALKTHROUGH.md)** with the code open, then the ten questions at its end with it
   closed.
3. **Ask Claude to quiz you one question at a time and not to reveal the answer until you have given yours.** Good prompts: "Quiz me
   on why the checks run in this order." "Pretend you are a sceptical reviewer who has just read `gate.py`; ask follow-ups until I
   get stuck." "Remove a check and ask me what breaks."
4. **Break it yourself.** Write one attack (`A41`) that you think might get through. If it does, you found a bug; if not, you now
   know why. Either is a story.
5. **Run the mutation check and read one row.** Pick a check, disable it by hand, watch which test fails.
6. **Know the limits cold** ([THREAT_MODEL.md](../THREAT_MODEL.md), "Known gaps"). The ones you name first cannot be used against you.
7. **Know the numbers**, but do not lead with them: 189 tests, 40 attacks, 15 mutants, PR-AUC 0.777 against 0.014.
