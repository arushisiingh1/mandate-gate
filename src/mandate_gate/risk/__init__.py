"""Advisory fraud scoring.

Deliberately empty: importing ``mandate_gate.risk.features`` (used by the gate)
must not pull in numpy or scikit-learn. The heavy modules (``synth``,
``model``, ``evaluate``) are imported only by code that needs them.
"""
