"""Feature construction shared by the gate (serving) and the generator (training).

One function builds the feature vector for both, so a feature cannot drift
between how the model was trained and how it is scored.
"""

from __future__ import annotations

from typing import List

from ..categories import CATEGORY_IDS
from ..ledger import SECS_SINCE_LAST_CAP

FEATURE_NAMES = (
    "amount_cents",
    "amt_frac_txn_cap",
    "amt_frac_remaining",
    "hour_utc",
    "secs_since_last",
    "txns_last_hour",
    "new_merchant",
    "category_id",
    "amt_vs_agent_mean",
)

# Reason-code stems, one per feature. They are deliberately direction-neutral:
# a reason says "this feature, at this value, pushed the score up", not that
# the value is "large" or "rapid". A tiny amount (card testing) and a huge one
# can both raise the score.
REASON_STEMS = {
    "amount_cents": "AMOUNT",
    "amt_frac_txn_cap": "AMOUNT_VS_TXN_CAP",
    "amt_frac_remaining": "AMOUNT_VS_REMAINING_BUDGET",
    "hour_utc": "HOUR_OF_DAY_UTC",
    "secs_since_last": "TIME_SINCE_LAST_TXN",
    "txns_last_hour": "RECENT_ACTIVITY",
    "new_merchant": "NEW_MERCHANT",
    "category_id": "CATEGORY",
    "amt_vs_agent_mean": "AMOUNT_VS_AGENT_NORMAL",
}


def build_features(
    *,
    amount_cents: int,
    per_txn_cap_cents: int,
    remaining_cap_cents: int,
    ts: int,
    category: str,
    new_merchant: bool,
    secs_since_last: int,
    txns_last_hour: int,
    agent_mean_amount: "float | None",
) -> List[float]:
    remaining = max(remaining_cap_cents, 1)
    mean = agent_mean_amount if agent_mean_amount and agent_mean_amount > 0 else None
    return [
        float(amount_cents),
        amount_cents / max(per_txn_cap_cents, 1),
        amount_cents / remaining,
        float((ts // 3600) % 24),
        float(min(max(secs_since_last, 0), SECS_SINCE_LAST_CAP)),
        float(txns_last_hour),
        1.0 if new_merchant else 0.0,
        float(CATEGORY_IDS[category]),
        (amount_cents / mean) if mean else 1.0,
    ]
