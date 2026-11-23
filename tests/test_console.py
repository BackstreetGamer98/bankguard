"""Tests for the console's logic (no browser needed). Run:  python3 -m unittest discover -s tests -v"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from console import Session, clean_args  # noqa: E402


class ConsoleFlow(unittest.TestCase):
    def setUp(self):
        self.s = Session()

    def test_small_payment_runs_and_is_logged(self):
        r = self.s.propose("create_payment", {"amount": 5000, "payee": "Acme"}, "user")
        self.assertEqual((r["decision"], r["outcome"]), ("allow", "executed"))
        self.assertEqual(len(self.s.audit()["entries"]), 1)

    def test_large_payment_is_blocked(self):
        r = self.s.propose("create_payment", {"amount": 250000, "payee": "Acme"}, "user")
        self.assertEqual((r["decision"], r["outcome"]), ("deny", "blocked"))

    def test_approval_flow_records_the_human_decision(self):
        r = self.s.propose("close_account", {"customer_id": "C1001"}, "user")
        self.assertEqual(r["outcome"], "pending")
        done = self.s.decide(r["pending_id"], True)
        self.assertEqual(done["outcome"], "executed")
        entries = self.s.audit()["entries"]
        self.assertEqual([e["rule"] for e in entries], ["approval_tools", "human_approval"])
        self.assertIsNone(self.s.audit()["broken_at"])

    def test_rejection_does_not_run_the_tool(self):
        r = self.s.propose("export_data", {"customer_id": "C1001"}, "user")
        done = self.s.decide(r["pending_id"], False)
        self.assertEqual(done["outcome"], "rejected")
        self.assertEqual(self.s.audit()["entries"][-1]["decision"], "deny")

    def test_cannot_decide_twice(self):
        r = self.s.propose("close_account", {"customer_id": "C1"}, "user")
        self.s.decide(r["pending_id"], True)
        with self.assertRaises(KeyError):
            self.s.decide(r["pending_id"], True)

    def test_on_screen_arguments_are_masked(self):
        r = self.s.propose("send_email", {"recipient": "ops@examplebank.com", "body": "PAN ABCDE1234F"}, "user")
        self.assertEqual(r["decision"], "deny")
        self.assertNotIn("ABCDE1234F", str(r["args"]))
        self.assertNotIn("ABCDE1234F", str(self.s.audit()))

    def test_all_objecting_rules_are_reported(self):
        r = self.s.propose("send_email", {"recipient": "x@gmail.com", "body": "ABCDE1234F"}, "user")
        rules = {o["rule"] for o in r["objections"]}
        self.assertEqual(rules, {"pii_outbound", "recipient"})
        self.assertEqual(r["rule"], "pii_outbound")  # most restrictive wins

    def test_untrusted_source_is_denied(self):
        r = self.s.propose("create_payment", {"amount": 900, "payee": "X"}, "untrusted")
        self.assertEqual(r["rule"], "prompt_injection")

    def test_tampering_is_located(self):
        for amount in (100, 200, 300):
            self.s.propose("create_payment", {"amount": amount, "payee": "A"}, "user")
        self.assertIsNone(self.s.audit()["broken_at"])
        self.s.tamper(1)
        self.assertEqual(self.s.audit()["broken_at"], 1)

    def test_reset_clears_everything(self):
        self.s.propose("create_payment", {"amount": 100, "payee": "A"}, "user")
        self.s.reset()
        self.assertEqual(self.s.audit()["entries"], [])


class Validation(unittest.TestCase):
    def test_rejects_odd_argument_types(self):
        for bad in ({"a": [1]}, {"a": {"b": 1}}, {"a": True}, "text", {"x" * 41: 1}, {"a": "y" * 501}):
            with self.assertRaises(ValueError):
                clean_args(bad)

    def test_accepts_text_and_numbers(self):
        self.assertEqual(clean_args({"amount": 5, "payee": "A"}), {"amount": 5, "payee": "A"})


class ConsoleStats(unittest.TestCase):
    def test_stats_and_export(self):
        s = Session()
        s.propose("create_payment", {"amount": 5000}, "user")
        s.propose("delete_database", {"name": "x"}, "user")
        stats = s.stats()
        self.assertEqual(stats["decisions"], {"allow": 1, "require_approval": 0, "deny": 1})
        lines = s.export().strip().split("\n")
        self.assertEqual(len(lines), 2)
        import json
        self.assertEqual(json.loads(lines[1])["rule"], "tool_allowlist")

    def test_burst_of_small_payments_is_stopped_by_the_daily_limit(self):
        s = Session()
        outcomes = [s.propose("create_payment", {"amount": 9500, "payee": "A"}, "user")["decision"] for _ in range(23)]
        self.assertEqual(outcomes.count("allow"), 21)
        self.assertEqual(outcomes[21], "deny")


if __name__ == "__main__":
    unittest.main()
