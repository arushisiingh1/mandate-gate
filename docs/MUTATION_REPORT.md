# Mutation check

Each row disables one safety-critical piece of the gate (see `scripts/mutation_check.py`) and re-runs the
fast test suite (160 tests). A row with no killing test would mean the piece is not actually tested.
Regenerate with `python scripts/mutation_check.py --report docs/MUTATION_REPORT.md`.

| Disabled | Effect | Tests that fail | Example |
|---|---|---:|---|
| check: schema | the schema check can no longer deny anything | 48 | `test_attacks.Identity.test_a08_malformed_signatures (sig='AAAAAAAAAAAAAAAAAAAA')` |
| check: signature | the signature check can no longer deny anything | 26 | `test_attacks.HumanAndModel.test_a39_a_perfect_risk_score_cannot_launder_a_bad_proposal` |
| check: mandate | the mandate check can no longer deny anything | 18 | `test_attacks.Consent.test_a09_agent_forges_a_mandate_in_the_users_name` |
| check: replay | the replay check can no longer deny anything | 10 | `test_attacks.HumanAndModel.test_a39_a_perfect_risk_score_cannot_launder_a_bad_proposal` |
| check: duplicate | the duplicate check can no longer deny anything | 8 | `test_attacks.Replay.test_a23_reuse_an_idempotency_key_for_a_bigger_purchase` |
| check: authority | the authority check can no longer deny anything | 29 | `test_agent_audit_ledger.LedgerAndHistory.test_denied_and_pending_proposals_do_not_make_a_merchant_familiar` |
| check: velocity | the velocity check can no longer deny anything | 6 | `test_attacks.Authority.test_a29_split_one_large_purchase_into_many_small_ones` |
| check: risk | the risk check can no longer deny anything | 35 | `test_attacks.HumanAndModel.test_a40_a_broken_scorer_fails_safe_never_open (scorer='RaisingScorer', score=None)` |
| approval binding | a human approval is accepted for any proposal | 2 | `test_attacks.HumanAndModel.test_a38_an_approval_for_one_proposal_replayed_onto_another` |
| input snapshot | the gate reads the caller's live object instead of a copy | 1 | `test_attacks.Input.test_a37_a_dict_that_shows_the_signature_check_one_thing_and_the_parser_another` |
| audit log | decisions are no longer written to the audit log | 196 | `test_agent_audit_ledger.AuditChain.test_bodies_with_floats_are_refused_so_a_float_can_never_hide_in_the_log` |
| review reservation | a pending review no longer holds budget | 4 | `test_agent_audit_ledger.LedgerAndHistory.test_exposure_is_committed_plus_reserved` |
| key kind (agent vs user) | a user key is accepted as an agent key and vice versa | 4 | `test_attacks.Consent.test_a10_agent_signs_its_own_mandate_as_itself` |
| domain separation | a signature made for one message type verifies as the other | 2 | `test_attacks.Consent.test_a14_mandate_signed_under_the_proposal_domain` |
| strict proposal keys | proposals may carry unexpected extra fields | 6 | `test_attacks.HumanAndModel.test_a39_a_perfect_risk_score_cannot_launder_a_bad_proposal` |
