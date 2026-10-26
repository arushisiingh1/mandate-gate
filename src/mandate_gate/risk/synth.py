"""Synthetic transaction generator (about 1% fraud).

SYNTHETIC: I wrote the fraud patterns below myself. Metrics computed on this
data show that the *evaluation method* works (time-ordered split, thresholds
frozen on validation, honest baselines). They say nothing about real-world
fraud performance, and scores mean nothing outside this simulator.

Design choices that matter for honesty:

* Only transactions that would pass the gate's rules reach the model in
  production, so the generator drops events that would have hit the per-
  transaction cap, the cumulative cap or the velocity limit. The model is
  trained on the distribution it will actually be asked to score.
* Features are built with the same ``build_features`` and ``AgentHistory`` the
  gate uses, in one forward pass per agent. A feature at time *t* only sees
  events before *t*, so no future information leaks into training.
* Classes overlap on purpose: some legitimate purchases look like fraud
  (large, late-night, new merchant) and some fraud looks routine.
* One fraud pattern (``slow_novel``) only appears in the final 20% of the
  timeline, so the test split contains a pattern the model never saw.
"""

from __future__ import annotations

from typing import Dict, List

import numpy as np
import pandas as pd

from ..categories import CATEGORIES
from ..ledger import AgentHistory
from .features import FEATURE_NAMES, build_features

START_TS = 1_760_000_000 - (1_760_000_000 % 86400)  # a UTC midnight in Oct 2025
VELOCITY_MAX = 5  # mirrors GateConfig.velocity_max_approvals
CYCLE_DAYS = 30  # mandate budget resets every 30 days
PATTERNS = ("legit", "legit_unusual", "card_testing", "cap_hugging", "drain", "slow_novel")

_SAFE_CATEGORIES = [c for c in CATEGORIES if c != "crypto"]
_NORMAL_CATEGORIES = ["groceries", "books", "home", "clothing", "software", "travel"]


def _pick(rng: np.random.Generator, allowed: List[str], preferred: List[str]) -> str:
    pool = [c for c in preferred if c in allowed] or allowed
    return str(rng.choice(pool))


def generate(
    n_agents: int = 300,
    days: int = 90,
    seed: int = 7,
    target_fraud_rate: float = 0.01,
) -> pd.DataFrame:
    rng = np.random.default_rng(seed)

    profiles: List[Dict] = []
    for a in range(n_agents):
        per_txn = int(rng.choice([15000, 25000, 40000, 60000]))
        n_allowed = int(rng.integers(4, 8))
        allowed = list(rng.choice(_SAFE_CATEGORIES, size=n_allowed, replace=False))
        # A minority of agents are allowed risky categories or crypto.
        if rng.random() < 0.10 and "crypto" not in allowed:
            allowed.append("crypto")
        if rng.random() < 0.25 and "gift_cards" not in allowed:
            allowed.append("gift_cards")
        normal = [c for c in allowed if c in _NORMAL_CATEGORIES] or allowed
        profiles.append(
            {
                "agent": a,
                "tz": int(rng.integers(-8, 10)),
                "per_txn": per_txn,
                "cum_cap": per_txn * 12,
                "allowed": allowed,
                "normal": normal,
                "mu": float(np.log(4000) + rng.normal(0, 0.5)),
                "rate": float(rng.uniform(1.0, 3.4)),
                "merchants": [f"a{a}-m{j}" for j in range(10)],
            }
        )

    events: Dict[int, List[dict]] = {a: [] for a in range(n_agents)}
    new_merchant_counter = 0

    def new_merchant() -> str:
        nonlocal new_merchant_counter
        new_merchant_counter += 1
        return f"new-{new_merchant_counter}"

    def local_to_utc_hour(local_hour: float, tz: int) -> float:
        return (local_hour - tz) % 24

    def stamp(day: int, hour_utc: float) -> int:
        return START_TS + day * 86400 + int(hour_utc * 3600) + int(rng.integers(0, 60))

    # ---- legitimate traffic --------------------------------------------------
    n_legit = 0
    for prof in profiles:
        a = prof["agent"]
        n = int(rng.poisson(prof["rate"] * days))
        for _ in range(n):
            day = int(rng.integers(0, days))
            if rng.random() < 0.006:  # legitimate but unusual: late-night, big, new
                hour = local_to_utc_hour(float(rng.uniform(0, 5.99)), prof["tz"])
                amount = int(rng.uniform(0.8, 0.97) * prof["per_txn"])
                events[a].append(
                    dict(ts=stamp(day, hour), merchant=new_merchant(), category=_pick(rng, prof["allowed"], ["electronics", "travel", "home"]), amount=amount, fraud=0, pattern="legit_unusual")
                )
            else:
                local = float(np.clip(rng.normal(14, 4), 0, 23.99))
                hour = local_to_utc_hour(local, prof["tz"])
                if rng.random() < 0.03:
                    amount = int(rng.uniform(0.5, 0.95) * prof["per_txn"])
                else:
                    amount = int(np.exp(rng.normal(prof["mu"], 0.55)))
                amount = int(np.clip(amount, 200, prof["per_txn"]))
                merchant = new_merchant() if rng.random() < 0.15 else str(rng.choice(prof["merchants"]))
                category = str(rng.choice(prof["normal"]))
                events[a].append(dict(ts=stamp(day, hour), merchant=merchant, category=category, amount=amount, fraud=0, pattern="legit"))
            n_legit += 1

    # ---- fraud: an attacker steering a compromised agent -------------------
    total_fraud = max(1, round(target_fraud_rate * n_legit / (1 - target_fraud_rate)))
    n_ct = max(1, round(0.30 * total_fraud / 4.6))  # card-testing bursts
    n_cap = max(1, round(0.30 * total_fraud))  # cap-hugging singles
    n_drain = max(1, round(0.35 * total_fraud / 3.0))  # drain sequences
    n_slow = max(1, round(0.05 * total_fraud))  # novel pattern, final 20% only
    late_start = int(days * 0.8)

    def pick_agent():
        return profiles[int(rng.integers(0, n_agents))]

    for _ in range(n_ct):
        prof = pick_agent()
        day = int(rng.integers(0, days))
        hour = float(rng.uniform(0, 24))
        ts = stamp(day, hour)
        for _k in range(int(rng.integers(4, 8))):
            events[prof["agent"]].append(
                dict(ts=ts, merchant=new_merchant(), category=_pick(rng, prof["allowed"], ["software", "gift_cards"]), amount=int(rng.integers(100, 1000)), fraud=1, pattern="card_testing")
            )
            ts += int(rng.integers(10, 40))

    for _ in range(n_cap):
        prof = pick_agent()
        day = int(rng.integers(0, days))
        if rng.random() < 0.9:  # night, local time
            hour = local_to_utc_hour(float(rng.uniform(0, 5.99)), prof["tz"])
        else:  # a daytime variant: overlaps with legitimate behaviour
            hour = local_to_utc_hour(float(rng.uniform(9, 20)), prof["tz"])
        events[prof["agent"]].append(
            dict(ts=stamp(day, hour), merchant=new_merchant(), category=_pick(rng, prof["allowed"], ["electronics", "gift_cards", "travel"]), amount=int(rng.uniform(0.85, 0.99) * prof["per_txn"]), fraud=1, pattern="cap_hugging")
        )

    for _ in range(n_drain):
        prof = pick_agent()
        day = int(rng.integers(0, days))
        ts = stamp(day, float(rng.uniform(0, 24)))
        for _k in range(int(rng.integers(2, 5))):
            events[prof["agent"]].append(
                dict(ts=ts, merchant=new_merchant(), category=_pick(rng, prof["allowed"], ["gift_cards", "electronics"]), amount=int(rng.uniform(0.4, 0.7) * prof["per_txn"]), fraud=1, pattern="drain")
            )
            ts += int(rng.integers(180, 600))

    for _ in range(n_slow):
        prof = pick_agent()
        day = int(rng.integers(late_start, days))
        hour = local_to_utc_hour(float(np.clip(rng.normal(14, 3), 8, 21)), prof["tz"])
        events[prof["agent"]].append(
            dict(ts=stamp(day, hour), merchant=new_merchant(), category=_pick(rng, prof["allowed"], ["software"]), amount=int(rng.integers(6000, 12000)), fraud=1, pattern="slow_novel")
        )

    # ---- replay each agent's timeline through the gate's own rules ----------
    rows = []
    for prof in profiles:
        a = prof["agent"]
        history = AgentHistory()
        spent: Dict[int, int] = {}
        for ev in sorted(events[a], key=lambda e: e["ts"]):
            amount = min(ev["amount"], prof["per_txn"])
            cycle = (ev["ts"] - START_TS) // (CYCLE_DAYS * 86400)
            remaining = prof["cum_cap"] - spent.get(cycle, 0)
            snap = history.snapshot(ev["ts"], ev["merchant"])
            if amount > remaining or snap.txns_last_hour >= VELOCITY_MAX:
                continue  # the rules would have denied this before the model saw it
            feats = build_features(
                amount_cents=amount,
                per_txn_cap_cents=prof["per_txn"],
                remaining_cap_cents=remaining,
                ts=ev["ts"],
                category=ev["category"],
                new_merchant=snap.new_merchant,
                secs_since_last=snap.secs_since_last,
                txns_last_hour=snap.txns_last_hour,
                agent_mean_amount=snap.mean_amount,
            )
            history.record(ev["ts"], ev["merchant"], amount)
            spent[cycle] = spent.get(cycle, 0) + amount
            row = dict(zip(FEATURE_NAMES, feats))
            row.update(ts=ev["ts"], agent_id=a, merchant=ev["merchant"], amount_raw=amount, is_fraud=ev["fraud"], pattern=ev["pattern"])
            rows.append(row)

    df = pd.DataFrame(rows).sort_values(["ts", "agent_id"], kind="mergesort").reset_index(drop=True)
    return df
