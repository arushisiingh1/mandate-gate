"""The smallest useful use of Mandate Gate as a library.

One user, one agent, one signed mandate, four proposals. Run it with:

    python examples/quickstart.py

To add the advisory risk model, build the gate like this instead (needs the
``ml`` extra, and uses the model that ships in ``artifacts/risk``):

    from mandate_gate.risk.model import load_scorer
    scorer, meta = load_scorer("artifacts/risk")
    gate = Gate(registry, AuditLog("audit.jsonl"),
                GateConfig(risk_review_threshold=meta["risk_review_threshold"],
                           risk_deny_threshold=meta["risk_deny_threshold"]),
                scorer=scorer)
"""

import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from mandate_gate.agent import AgentRuntime, SchemaError  # noqa: E402
from mandate_gate.audit import AuditLog  # noqa: E402
from mandate_gate.gate import Gate, GateConfig  # noqa: E402
from mandate_gate.mandate import Mandate, sign_mandate  # noqa: E402
from mandate_gate.registry import KeyRegistry  # noqa: E402
from mandate_gate.signing import generate_keypair  # noqa: E402


def main():
    now = int(time.time())

    # 1. Identity: each principal holds an Ed25519 key; the registry maps ids to public keys.
    user_keys, agent_keys = generate_keypair(), generate_keypair()
    registry = KeyRegistry()
    registry.register("alice", user_keys.public_b64, "user")
    registry.register("shopper-1", agent_keys.public_b64, "agent")

    # 2. Consent: the user signs what this agent may spend.
    mandate = sign_mandate(
        user_keys,
        Mandate("mandate-1", "alice", "shopper-1", "USD", 5_000, 20_000, ("books", "groceries"), now - 60, now + 3600),
    )

    # 3. The gate decides. The agent only proposes.
    audit = AuditLog()  # pass a path to persist: AuditLog("audit.jsonl")
    gate = Gate(registry, audit, GateConfig())  # no scorer: rules only
    agent = AgentRuntime("shopper-1", agent_keys, "mandate-1", on_reject=gate.record_rejected_output)

    def purchase(merchant, category, cents, item, nonce):
        return json.dumps({"merchant": merchant, "category": category, "amount_cents": cents, "item": item, "nonce": nonce})

    outcomes = []
    for label, raw in [
        ("in-mandate book", purchase("pagepress.example", "books", 1_999, "paperback", "nonce-aaaaaaaaaaaaaaaa")),
        ("over the per-transaction cap", purchase("bigbox.example", "books", 9_999, "boxed set", "nonce-bbbbbbbbbbbbbbbb")),
        ("category not allowed", purchase("cardshop.example", "gift_cards", 2_000, "gift card", "nonce-cccccccccccccccc")),
        ("model output that breaks the schema", "Sure! I bought you a nice book."),
    ]:
        try:
            decision = gate.evaluate(agent.propose(raw), mandate)
            outcomes.append((label, decision.result.value, decision.reason_codes))
        except SchemaError:
            outcomes.append((label, "REJECTED", ("SCHEMA",)))

    for label, result, codes in outcomes:
        print(f"{result:<9} {label:<38} {','.join(codes) or '-'}")
    print(f"\n{len(gate.ledger.charges)} charge(s), ${sum(c.amount_cents for c in gate.ledger.charges) / 100:.2f} spent")
    print(f"audit log: {len(audit)} records, chain valid: {audit.verify().ok}")
    return outcomes


if __name__ == "__main__":
    main()
