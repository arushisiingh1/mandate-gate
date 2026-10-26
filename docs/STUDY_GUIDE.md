# Study guide: explain it without the code, then be quizzed

The brief's end-of-day routine: explain every module out loud without looking at the code, then ask for a quiz on **why the
checks run in this order** and **what breaks if one is removed**. This file is the answer key for the second half and a
checklist for the first. Nothing here replaces actually doing it: a document cannot tell you whether you can explain the gate.

## Explain-aloud checklist

Say each in under a minute, with the code closed. If you cannot, that module is not yet yours.

- [ ] Why does code own the decision and the model only propose?
- [ ] What is in a mandate, who signs it, and why is it verified *before* any field in it is read?
- [ ] What does domain separation prevent, and how?
- [ ] Replay versus duplicate: what stops each, and why does a retry need a fresh nonce but the same idempotency key?
- [ ] Why is the nonce consumed even when the proposal is denied?
- [ ] How does the velocity limit stop a split purchase, and why do pending reviews count toward it?
- [ ] What exactly is a human approval bound to, and what is re-checked when it is used?
- [ ] Why is the audit record written *before* the charge?
- [ ] Why does the risk score run last, and what does "can only tighten" mean in code?
- [ ] Why is 99% accuracy meaningless at 1% fraud, and what are PR-AUC, precision and recall here?
- [ ] Why a time-ordered split, and what does "thresholds frozen before the test set" protect against?
- [ ] What is a reason code for a logistic regression, and why do the terms add up to the score exactly?
- [ ] What is *not* built (see README), and what would you build next?

## Quiz 1: why this order?

`schema, signature, mandate, replay, duplicate, authority, velocity, risk`

| Question | Answer |
|---|---|
| Why is the schema check first? | Nothing else can read a field safely until the input has an exact shape. Also needed to learn which agent to verify against. |
| Why signature before replay? | An unauthenticated sender must not be able to consume nonces. Reversed, anyone could burn a real agent's nonces by guessing them, and legitimate messages would then look like replays. |
| Why mandate before replay? | A message with no valid consent should leave no trace in replay state either. |
| Why replay before duplicate? | An exact resend must be a *denied replay*, not a "retry" that returns a cached approval. Reversed, an attacker replays a message by presenting it as a retry. |
| Why duplicate before authority? | A legitimate retry should return the original answer even if the budget has since moved; re-evaluating it could charge twice or flip the answer. |
| Why authority before velocity? | Both are rules, but caps are cheap, deterministic facts about one proposal; velocity depends on history. Either order is safe; this one reports the clearer reason. |
| Why risk last? | It is the only check that is not a hard rule and the only one that costs a model call. It can only tighten, and it must never see a proposal the rules already denied. |
| Why audit last, but *before* the charge? | The record describes the final decision, and no spend may exist without one. |

## Quiz 2: what breaks if one is removed?

Each answer below is measured, not asserted: `scripts/mutation_check.py` disables the piece and re-runs the fast tests
(results in [`MUTATION_REPORT.md`](MUTATION_REPORT.md)). Pick any row and find the named test.

| Remove… | What an attacker gets | Test that fails (example) |
|---|---|---|
| schema | Extra fields, floats, look-alike strings reach the logic; the gate crashes closed instead of denying cleanly | `A08`, `A31`-`A34` |
| signature | Anyone can spend as any agent; edit amounts after signing | `A01`-`A03`, `A39` |
| mandate | The agent writes its own spending limits | `A09`, `A11`, `A19` |
| replay | Any captured message can be resent forever | `A20`-`A22` |
| duplicate | A retry charges twice; a reused key can swap in a larger purchase | `A23`, `A24` |
| authority | Caps, categories and currency are decoration | `A25`-`A28` |
| velocity | One large purchase split into many small ones | `A29` |
| risk | Nothing notices in-mandate spend that "looks wrong"; broken-scorer cases are no longer routed to a human | `A40` |
| approval binding | An approval for $20 applies to $290 | `A38` |
| input snapshot | A crafted object makes the signature check and the parser see different amounts | `A37` |
| audit log | Spend with no record | every test (the harness asserts one record per decision) |
| review reservation | Many pending reviews, each affordable alone, together exceed the budget | `exposure` / reservation tests |
| key kind | A user key accepted as an agent key and the reverse | `A10` |
| domain separation | A signature made for one message type is accepted as the other | `A07`, `A14` |
| strict proposal keys | Unknown fields ride along unreviewed | `A31` |

## Quiz 3: questions to expect, with the short honest answer

- **Why does code own the decision?** A model can be talked into things; a hard rule can be tested, explained and inspected.
- **Why use a model at all if rules decide?** Rules catch known violations. The model adds up several individually acceptable signals (large, late at night,
  new merchant, rapid) that no single rule objects to; it is linear, so it adds signals and does not model interactions. It can only tighten a decision, and explains itself with reason codes.
- **How do you prove a human authorised this purchase?** A signed mandate and, in the gray zone, an approval bound to the exact
  proposal. Real identity and device binding is the part that is *not* built.
- **Your fraud metrics?** Synthetic data, so they validate the method and not the world. At the review threshold recall fell
  from 0.90 (validation) to 0.75 (test) because of a pattern the model had never seen: report that, do not hide it.
- **What did Claude write and what did you?** Answer from [`AI_ASSISTANCE_LOG.md`](../AI_ASSISTANCE_LOG.md), and be ready to say what
  you checked and what you found wrong.
