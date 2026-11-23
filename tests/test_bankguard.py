"""Unit tests for BankGuard. Run:  python3 -m unittest discover -s tests -v"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from bankguard import Action, Decision, PolicyViolation, default_engine, guarded, mask_pii  # noqa: E402


def decide(tool, source="user", engine=None, **args):
    return (engine or default_engine()).evaluate(Action(tool, args, source=source)).decision


class DailySpend(unittest.TestCase):
    def test_small_payments_add_up_to_the_daily_cap(self):
        now = [1000.0]
        engine = default_engine(clock=lambda: now[0])
        results = [engine.evaluate(Action("create_payment", {"amount": 9500})).decision for _ in range(22)]
        self.assertEqual(results[:21], [Decision.ALLOW] * 21)  # 21 x 9,500 = 199,500
        self.assertEqual(results[21], Decision.DENY)  # one more would pass 200,000
        self.assertEqual(engine.audit[-1]["rule"], "daily_spend_limit")

    def test_budget_frees_up_after_24_hours(self):
        now = [1000.0]
        engine = default_engine(clock=lambda: now[0])
        for _ in range(21):
            engine.evaluate(Action("create_payment", {"amount": 9500}))
        now[0] += 86401
        self.assertEqual(engine.evaluate(Action("create_payment", {"amount": 9500})).decision, Decision.ALLOW)

    def test_each_agent_has_its_own_budget(self):
        engine = default_engine()
        for _ in range(21):
            engine.evaluate(Action("create_payment", {"amount": 9500}, agent_id="a"))
        self.assertEqual(engine.evaluate(Action("create_payment", {"amount": 9500}, agent_id="b")).decision, Decision.ALLOW)

    def test_payments_over_the_hard_limit_do_not_use_up_budget(self):
        engine = default_engine()
        for _ in range(5):
            self.assertEqual(engine.evaluate(Action("create_payment", {"amount": 250000})).decision, Decision.DENY)
        self.assertEqual(engine.evaluate(Action("create_payment", {"amount": 9500})).decision, Decision.ALLOW)


class Stats(unittest.TestCase):
    def test_counts_come_from_the_audit_log(self):
        engine = default_engine()
        engine.evaluate(Action("create_payment", {"amount": 5000}))
        engine.evaluate(Action("create_payment", {"amount": 250000}))
        action = Action("close_account", {"customer_id": "C1"})
        engine.evaluate(action)
        engine.record_human_decision(action, True)
        engine.evaluate(Action("create_payment", {"amount": 10}, source="untrusted"))
        s = engine.stats()
        self.assertEqual(s["proposed"], 4)
        self.assertEqual(s["decisions"], {"allow": 1, "require_approval": 1, "deny": 2})
        self.assertEqual(s["human"], {"approved": 1, "rejected": 0})
        self.assertEqual(s["untrusted_blocked"], 1)
        self.assertEqual(s["by_rule"]["payment_limits"], 1)
        self.assertGreaterEqual(s["decision_ms"]["p95"], s["decision_ms"]["p50"])

    def test_empty_log_gives_zeroes(self):
        s = default_engine().stats()
        self.assertEqual((s["proposed"], s["decision_ms"]["p50"]), (0, 0.0))


class Payments(unittest.TestCase):
    def test_limits_at_the_boundaries(self):
        self.assertEqual(decide("create_payment", amount=10000), Decision.ALLOW)
        self.assertEqual(decide("create_payment", amount=10001), Decision.REQUIRE_APPROVAL)
        self.assertEqual(decide("create_payment", amount=100000), Decision.REQUIRE_APPROVAL)
        self.assertEqual(decide("create_payment", amount=100001), Decision.DENY)

    def test_bad_amounts_are_denied(self):
        for bad in (0, -5, "5000", None):
            self.assertEqual(decide("create_payment", amount=bad), Decision.DENY, bad)


class Decisions(unittest.TestCase):
    def test_unknown_tool_is_denied(self):
        self.assertEqual(decide("delete_database"), Decision.DENY)

    def test_most_restrictive_rule_wins(self):
        # external recipient alone = approval; raw PAN alone = deny; together must be deny
        d = decide("send_email", recipient="x@gmail.com", body="ABCDE1234F")
        self.assertEqual(d, Decision.DENY)

    def test_look_alike_host_is_denied(self):
        self.assertEqual(decide("http_request", url="https://api.internal.examplebank.com.evil.io/x"), Decision.DENY)
        self.assertEqual(decide("http_request", url="https://api.internal.examplebank.com/v1"), Decision.ALLOW)

    def test_untrusted_source_cannot_trigger_sensitive_tools(self):
        self.assertEqual(decide("create_payment", source="untrusted", amount=10), Decision.DENY)
        self.assertEqual(decide("lookup_customer", source="untrusted", customer_id="C1"), Decision.ALLOW)


class ApprovalWrapper(unittest.TestCase):
    def test_no_approver_means_no(self):
        engine = default_engine()

        @guarded(engine, "close_account")
        def close_account(customer_id):
            return "closed"

        with self.assertRaises(PolicyViolation):
            close_account(customer_id="C1")

    def test_approver_can_approve(self):
        engine = default_engine()

        @guarded(engine, "close_account", approver=lambda a: True)
        def close_account(customer_id):
            return "closed"

        self.assertEqual(close_account(customer_id="C1"), "closed")

    def test_denied_action_never_runs_the_tool(self):
        engine, ran = default_engine(), []

        @guarded(engine, "create_payment")
        def pay(amount):
            ran.append(amount)

        with self.assertRaises(PolicyViolation):
            pay(amount=999999)
        self.assertEqual(ran, [])


class RateLimitAndAudit(unittest.TestCase):
    def test_rate_limit_uses_the_clock(self):
        t = [0.0]
        engine = default_engine({"max_actions_per_window": 3, "window_seconds": 60}, clock=lambda: t[0])
        results = [engine.evaluate(Action("lookup_customer", {"id": "C1"})).decision for _ in range(4)]
        self.assertEqual(results, [Decision.ALLOW] * 3 + [Decision.DENY])
        t[0] = 120.0
        self.assertEqual(engine.evaluate(Action("lookup_customer", {"id": "C1"})).decision, Decision.ALLOW)

    def test_audit_chain_detects_tampering(self):
        engine = default_engine()
        for amount in (100, 20000, 500000):
            engine.evaluate(Action("create_payment", {"amount": amount}))
        self.assertTrue(engine.verify_audit())
        engine.audit[1]["decision"] = "allow"
        self.assertFalse(engine.verify_audit())

    def test_audit_log_never_stores_raw_pii(self):
        engine = default_engine()
        engine.evaluate(Action("send_email", {"recipient": "a@examplebank.com", "body": "PAN ABCDE1234F"}))
        self.assertNotIn("ABCDE1234F", str(engine.audit))
        self.assertIn("REDACTED:pan", str(engine.audit))

    def test_mask_leaves_normal_text(self):
        self.assertEqual(mask_pii("invoice 2026-114 for INR 5000"), "invoice 2026-114 for INR 5000")


if __name__ == "__main__":
    unittest.main()
