"""Mandate Gate: a deterministic authorization layer for AI shopping agents.

An LLM agent *proposes* purchases. Plain, deterministic code *decides* them.
A gradient-boosted fraud score is advisory input that can only make a decision
stricter, and every decision (denials included) lands in a hash-chained log.
"""

__version__ = "0.1.0"
