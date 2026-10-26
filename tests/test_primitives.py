"""Canonical JSON, signing, registry, mandate, proposal."""

import base64
import tempfile
import unittest
from pathlib import Path

from mandate_gate.canonical import CanonicalError, canonical_bytes, hash_obj
from mandate_gate.mandate import Mandate, MandateError, parse_mandate, sign_mandate
from mandate_gate.proposal import Proposal, ProposalError, intent_hash, parse_proposal, sign_proposal
from mandate_gate.registry import KeyRegistry, RegistryError
from mandate_gate.signing import (
    DOMAIN_MANDATE,
    DOMAIN_PROPOSAL,
    generate_keypair,
    is_valid_public_key,
    keypair_from_seed,
    sign,
    verify,
)

from .helpers import ALLOWED, T0

GOOD_PROPOSAL = {
    "agent_id": "shopper-1",
    "mandate_id": "m-1",
    "merchant": "pagepress.example",
    "category": "books",
    "amount_cents": 2745,
    "currency": "USD",
    "item": "paperback novel",
    "nonce": "nonce-0000000000000001",
    "idempotency_key": "idem-00000001",
    "timestamp": T0,
}


class Canonical(unittest.TestCase):
    def test_key_order_and_whitespace_do_not_matter(self):
        self.assertEqual(canonical_bytes({"b": 1, "a": [1, 2]}), canonical_bytes({"a": [1, 2], "b": 1}))
        self.assertEqual(canonical_bytes({"a": 1}), b'{"a":1}')

    def test_floats_are_refused_everywhere(self):
        for bad in (1.5, {"a": 1.0}, [0.1], float("nan"), float("inf")):
            with self.subTest(bad=bad):
                with self.assertRaises(CanonicalError):
                    canonical_bytes(bad)

    def test_unsupported_types_and_keys_are_refused(self):
        for bad in (object(), {1: "x"}, {"a": {1, 2}}, b"bytes"):
            with self.assertRaises(CanonicalError):
                canonical_bytes(bad)

    def test_nesting_is_bounded(self):
        deep = x = []
        for _ in range(20):
            x.append([])
            x = x[0]
        with self.assertRaises(CanonicalError):
            canonical_bytes(deep)

    def test_output_is_pure_ascii_so_unicode_has_one_encoding(self):
        out = canonical_bytes({"k": "café ‮"})
        out.decode("ascii")
        self.assertIn(b"\\u00e9", out)

    def test_hash_is_stable(self):
        self.assertEqual(hash_obj({"a": 1}), hash_obj({"a": 1}))
        self.assertNotEqual(hash_obj({"a": 1}), hash_obj({"a": 2}))


class Signing(unittest.TestCase):
    def setUp(self):
        self.k = keypair_from_seed(b"k1")
        self.payload = {"amount_cents": 100, "merchant": "x"}

    def test_round_trip(self):
        sig = sign(self.k.private, DOMAIN_PROPOSAL, self.payload)
        self.assertTrue(verify(self.k.public_b64, DOMAIN_PROPOSAL, self.payload, sig))

    def test_any_change_breaks_it(self):
        sig = sign(self.k.private, DOMAIN_PROPOSAL, self.payload)
        self.assertFalse(verify(self.k.public_b64, DOMAIN_PROPOSAL, {**self.payload, "amount_cents": 101}, sig))
        self.assertFalse(verify(self.k.public_b64, DOMAIN_PROPOSAL, {**self.payload, "extra": 1}, sig))
        self.assertFalse(verify(keypair_from_seed(b"k2").public_b64, DOMAIN_PROPOSAL, self.payload, sig))

    def test_domains_do_not_cross(self):
        sig = sign(self.k.private, DOMAIN_MANDATE, self.payload)
        self.assertFalse(verify(self.k.public_b64, DOMAIN_PROPOSAL, self.payload, sig))
        self.assertTrue(verify(self.k.public_b64, DOMAIN_MANDATE, self.payload, sig))

    def test_verify_never_raises_on_garbage(self):
        sig = sign(self.k.private, DOMAIN_PROPOSAL, self.payload)
        for pub in (None, 5, "", "not base64!", base64.b64encode(b"short").decode()):
            self.assertFalse(verify(pub, DOMAIN_PROPOSAL, self.payload, sig))
        for bad in (None, 5, "", "####", base64.b64encode(b"x" * 63).decode(), base64.b64encode(b"x" * 65).decode()):
            self.assertFalse(verify(self.k.public_b64, DOMAIN_PROPOSAL, self.payload, bad))
        self.assertFalse(verify(self.k.public_b64, DOMAIN_PROPOSAL, {"f": 1.5}, sig))  # un-canonicalisable payload

    def test_seeded_keys_are_deterministic_and_random_keys_are_not(self):
        self.assertEqual(keypair_from_seed(b"s").public_b64, keypair_from_seed(b"s").public_b64)
        self.assertNotEqual(generate_keypair().public_b64, generate_keypair().public_b64)

    def test_public_key_validation(self):
        self.assertTrue(is_valid_public_key(self.k.public_b64))
        for bad in (None, "", "AAAA", 5, base64.b64encode(b"x" * 33).decode()):
            self.assertFalse(is_valid_public_key(bad))


class Registry(unittest.TestCase):
    def setUp(self):
        self.k = keypair_from_seed(b"r")

    def test_lookup_statuses(self):
        r = KeyRegistry()
        r.register("a1", self.k.public_b64, "agent")
        self.assertEqual(r.lookup("a1", "agent"), ("ok", self.k.public_b64))
        self.assertEqual(r.lookup("a1", "user"), ("wrong_kind", None))
        self.assertEqual(r.lookup("nobody", "agent"), ("unknown", None))
        r.revoke("a1")
        self.assertEqual(r.lookup("a1", "agent"), ("revoked", None))

    def test_no_silent_key_replacement(self):
        r = KeyRegistry()
        r.register("a1", self.k.public_b64, "agent")
        with self.assertRaises(RegistryError):
            r.register("a1", keypair_from_seed(b"other").public_b64, "agent")

    def test_rejects_bad_registrations(self):
        r = KeyRegistry()
        for args in (("bad id", self.k.public_b64, "agent"), ("a1", "nonsense", "agent"), ("a1", self.k.public_b64, "admin"), ("", self.k.public_b64, "agent")):
            with self.assertRaises(RegistryError):
                r.register(*args)
        with self.assertRaises(RegistryError):
            r.revoke("ghost")

    def test_save_and_load_keeps_revocations(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "registry.json"
            r = KeyRegistry(path)
            r.register("a1", self.k.public_b64, "agent")
            r.register("u1", keypair_from_seed(b"u").public_b64, "user")
            r.revoke("a1")
            r.save()
            again = KeyRegistry(path)
            self.assertEqual(again.lookup("a1", "agent")[0], "revoked")
            self.assertEqual(again.lookup("u1", "user")[0], "ok")


class MandateParsing(unittest.TestCase):
    def payload(self, **over):
        p = Mandate("m-1", "alice", "shopper-1", "USD", 30_000, 300_000, ALLOWED, T0, T0 + 3600).to_payload()
        p.update(over)
        return p

    def test_valid_mandate_parses_and_sorts_categories(self):
        m = parse_mandate(self.payload(allowed_categories=["home", "books"]))
        self.assertEqual(m.allowed_categories, ("books", "home"))

    def test_rejects_every_malformation(self):
        cases = {
            "extra field": self.payload(admin=True),
            "negative cap": self.payload(per_txn_cap_cents=-1),
            "zero cap": self.payload(per_txn_cap_cents=0),
            "bool cap": self.payload(per_txn_cap_cents=True),
            "float cap": self.payload(per_txn_cap_cents=1.5),
            "per-txn above cumulative": self.payload(per_txn_cap_cents=400_000),
            "expires before start": self.payload(expires_at=T0 - 1),
            "unknown category": self.payload(allowed_categories=["books", "weapons"]),
            "duplicate categories": self.payload(allowed_categories=["books", "books"]),
            "no categories": self.payload(allowed_categories=[]),
            "categories not a list": self.payload(allowed_categories="books"),
            "bad currency": self.payload(currency="usd"),
            "bad id": self.payload(mandate_id="has space"),
        }
        for name, bad in cases.items():
            with self.subTest(name):
                with self.assertRaises(MandateError):
                    parse_mandate(bad)
        missing = self.payload()
        del missing["expires_at"]
        with self.assertRaises(MandateError):
            parse_mandate(missing)

    def test_signed_envelope_verifies_and_carries_the_signer(self):
        keys = keypair_from_seed(b"alice")
        msg = sign_mandate(keys, Mandate("m-1", "alice", "shopper-1", "USD", 100, 1000, ("books",), T0, T0 + 10))
        self.assertEqual(msg["signer"], "alice")
        self.assertTrue(verify(keys.public_b64, DOMAIN_MANDATE, msg["payload"], msg["signature"]))


class ProposalParsing(unittest.TestCase):
    def test_valid_proposal(self):
        p = parse_proposal(dict(GOOD_PROPOSAL))
        self.assertEqual(p.amount_cents, 2745)
        self.assertEqual(p.to_payload(), GOOD_PROPOSAL)

    def test_rejects_wrong_shapes(self):
        for name, bad in {
            "extra": {**GOOD_PROPOSAL, "x": 1},
            "str amount": {**GOOD_PROPOSAL, "amount_cents": "2745"},
            "bool amount": {**GOOD_PROPOSAL, "amount_cents": True},
            "unknown category": {**GOOD_PROPOSAL, "category": "weapons"},
            "timestamp float": {**GOOD_PROPOSAL, "timestamp": 1.0},
            "not an object": [GOOD_PROPOSAL],
        }.items():
            with self.subTest(name):
                with self.assertRaises(ProposalError):
                    parse_proposal(bad)

    def test_intent_hash_ignores_per_attempt_fields_only(self):
        a = parse_proposal(dict(GOOD_PROPOSAL))
        retry = parse_proposal({**GOOD_PROPOSAL, "nonce": "nonce-0000000000000002", "timestamp": T0 + 9})
        self.assertEqual(intent_hash(a), intent_hash(retry))
        for field, value in (("amount_cents", 2746), ("merchant", "other.example"), ("item", "other"), ("category", "home"), ("idempotency_key", "idem-00000002")):
            changed = parse_proposal({**GOOD_PROPOSAL, field: value})
            self.assertNotEqual(intent_hash(a), intent_hash(changed), field)

    def test_signed_proposal_verifies(self):
        keys = keypair_from_seed(b"agent")
        msg = sign_proposal(keys, Proposal(**GOOD_PROPOSAL))
        self.assertEqual(msg["signer"], "shopper-1")
        self.assertTrue(verify(keys.public_b64, DOMAIN_PROPOSAL, msg["payload"], msg["signature"]))


if __name__ == "__main__":
    unittest.main()
