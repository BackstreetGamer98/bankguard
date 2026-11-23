"""BankGuard: deterministic guardrails that sit between an AI agent and its tools.

The LLM proposes an action; this layer decides ALLOW / REQUIRE_APPROVAL / DENY
using plain code, so safety does not depend on the model behaving.
All names, domains and limits are fictional.
"""
from __future__ import annotations

import functools
import hashlib
import json
import re
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional


class Decision(str, Enum):
    ALLOW = "allow"
    REQUIRE_APPROVAL = "require_approval"
    DENY = "deny"


SEVERITY = {Decision.ALLOW: 0, Decision.REQUIRE_APPROVAL: 1, Decision.DENY: 2}


@dataclass
class Action:
    tool: str
    args: Dict[str, Any] = field(default_factory=dict)
    agent_id: str = "agent-001"
    source: str = "user"  # "user" or "untrusted" (email, PDF, web page content)


@dataclass
class Result:
    decision: Decision
    reason: str
    rule: str


# ---------------------------------------------------------------- PII helpers
PII_PATTERNS = {
    "card": re.compile(r"\b(?:\d{4}[ -]?){3}\d{4}\b"),
    "aadhaar": re.compile(r"\b\d{4}\s?\d{4}\s?\d{4}\b"),
    "pan": re.compile(r"\b[A-Z]{5}\d{4}[A-Z]\b"),
    "long_number": re.compile(r"\b\d{9,18}\b"),
}


def detect_pii(text: str) -> List[str]:
    return [name for name, rx in PII_PATTERNS.items() if rx.search(text)]


def mask_pii(text: str) -> str:
    for name, rx in PII_PATTERNS.items():
        text = rx.sub(f"[REDACTED:{name}]", text)
    return text


INJECTION_PATTERNS = [
    re.compile(r"ignore (all |any )?(the )?(previous|prior|above) (instructions|rules)", re.I),
    re.compile(r"disregard (the |all |any )?(policy|policies|instructions|rules)", re.I),
    re.compile(r"reveal (your )?system prompt", re.I),
]

# ------------------------------------------------------------------ config
DEFAULT_CONFIG: Dict[str, Any] = {
    "allowed_tools": {
        "lookup_customer", "read_policy", "draft_email", "send_email",
        "post_message", "create_payment", "close_account", "export_data",
        "http_request",
    },
    "approval_tools": {"close_account", "export_data"},
    "outbound_tools": {"send_email", "post_message", "export_data"},
    "sensitive_tools": {
        "create_payment", "close_account", "export_data",
        "send_email", "post_message", "http_request",
    },
    "internal_email_domains": {"examplebank.com"},
    "allowed_url_hosts": {"api.internal.examplebank.com", "intranet.examplebank.com"},
    "daily_spend_limit": 200_000,
    "payment_auto_limit": 10_000,
    "payment_approval_limit": 100_000,
    "max_actions_per_window": 30,
    "window_seconds": 60,
}


def _strings(action: Action) -> List[str]:
    return [v for v in action.args.values() if isinstance(v, str)]


# ------------------------------------------------------------------- rules
class Rule:
    name = "rule"

    def check(self, action: Action, now: float) -> Optional[Result]:
        raise NotImplementedError


class ToolAllowlist(Rule):
    name = "tool_allowlist"

    def __init__(self, allowed):
        self.allowed = allowed

    def check(self, a, now):
        if a.tool not in self.allowed:
            return Result(Decision.DENY, f"tool '{a.tool}' is not allowed", self.name)


class ApprovalTools(Rule):
    name = "approval_tools"

    def __init__(self, tools):
        self.tools = tools

    def check(self, a, now):
        if a.tool in self.tools:
            return Result(Decision.REQUIRE_APPROVAL, f"'{a.tool}' always needs human approval", self.name)


class PaymentLimits(Rule):
    name = "payment_limits"

    def __init__(self, auto, approval):
        self.auto, self.approval = auto, approval

    def check(self, a, now):
        if a.tool != "create_payment":
            return None
        amount = a.args.get("amount")
        if not isinstance(amount, (int, float)) or amount <= 0:
            return Result(Decision.DENY, "payment amount missing or not positive", self.name)
        if amount <= self.auto:
            return None
        if amount <= self.approval:
            return Result(Decision.REQUIRE_APPROVAL, f"amount {amount:,.0f} above auto limit", self.name)
        return Result(Decision.DENY, f"amount {amount:,.0f} above hard limit", self.name)


class PIIPolicy(Rule):
    name = "pii_outbound"

    def __init__(self, outbound):
        self.outbound = outbound

    def check(self, a, now):
        if a.tool not in self.outbound:
            return None
        found = sorted({p for s in _strings(a) for p in detect_pii(s)})
        if found:
            return Result(Decision.DENY, f"raw PII in outbound content: {', '.join(found)}; mask first", self.name)


class RecipientPolicy(Rule):
    name = "recipient"

    def __init__(self, internal_domains):
        self.internal = internal_domains

    def _is_internal(self, email: str) -> bool:
        domain = email.rsplit("@", 1)[-1].lower()
        return any(domain == d or domain.endswith("." + d) for d in self.internal)

    def check(self, a, now):
        if a.tool != "send_email":
            return None
        recipient = a.args.get("recipient")
        if not recipient or "@" not in recipient:
            return Result(Decision.DENY, "recipient required", self.name)
        if not self._is_internal(recipient):
            return Result(Decision.REQUIRE_APPROVAL, "external recipient", self.name)


class NetworkPolicy(Rule):
    name = "network"

    def __init__(self, allowed_hosts):
        self.allowed = allowed_hosts

    def check(self, a, now):
        if a.tool != "http_request":
            return None
        from urllib.parse import urlparse
        host = (urlparse(a.args.get("url", "")).hostname or "").lower()
        if host not in self.allowed:  # exact match: blocks look-alike and suffix tricks
            return Result(Decision.DENY, f"host '{host or 'none'}' not on allowlist", self.name)


class InjectionPolicy(Rule):
    name = "prompt_injection"

    def __init__(self, sensitive):
        self.sensitive = sensitive

    def check(self, a, now):
        if a.source == "untrusted" and a.tool in self.sensitive:
            return Result(Decision.DENY, "sensitive action requested by untrusted content", self.name)
        for s in _strings(a):
            if any(rx.search(s) for rx in INJECTION_PATTERNS):
                return Result(Decision.DENY, "injection phrase detected in arguments", self.name)


class RateLimit(Rule):
    name = "rate_limit"

    def __init__(self, max_actions, window):
        self.max, self.window = max_actions, window
        self.hits: Dict[str, deque] = defaultdict(deque)

    def check(self, a, now):
        q = self.hits[a.agent_id]
        while q and now - q[0] > self.window:
            q.popleft()
        q.append(now)
        if len(q) > self.max:
            return Result(Decision.DENY, f"more than {self.max} actions in {self.window}s", self.name)


class DailySpendLimit(Rule):
    """A money budget: one agent may not move more than `cap` in 24 hours, however small each payment is.
    Payments already above the hard limit are ignored here (another rule denies them), and an amount is
    counted when it is proposed, so a payment waiting for approval still uses up budget."""
    name = "daily_spend_limit"

    def __init__(self, cap, ignore_above, window=86400):
        self.cap, self.ignore_above, self.window = cap, ignore_above, window
        self.spent: Dict[str, deque] = defaultdict(deque)

    def check(self, a, now):
        if a.tool != "create_payment":
            return None
        amount = a.args.get("amount")
        if not isinstance(amount, (int, float)) or isinstance(amount, bool) or amount <= 0 or amount > self.ignore_above:
            return None
        q = self.spent[a.agent_id]
        while q and now - q[0][0] > self.window:
            q.popleft()
        total = sum(x for _, x in q)
        if total + amount > self.cap:
            return Result(Decision.DENY, f"daily spend limit {self.cap:,.0f} would be exceeded ({total:,.0f} already proposed)", self.name)
        q.append((now, amount))


# ------------------------------------------------------------------ engine
class PolicyEngine:
    """Runs every rule; the most restrictive result wins. Every decision is logged."""

    def __init__(self, rules: List[Rule], clock: Callable[[], float] = time.time):
        self.rules, self.clock = rules, clock
        self.audit: List[Dict[str, Any]] = []
        self.last_hits: List[Result] = []  # every rule that objected to the latest action
        self.timings: List[float] = []  # milliseconds each decision took (not part of the hash chain)

    def evaluate(self, action: Action) -> Result:
        started = time.perf_counter()
        now = self.clock()
        hits = [r for r in (rule.check(action, now) for rule in self.rules) if r]
        self.last_hits = hits
        final = max(hits, key=lambda r: SEVERITY[r.decision]) if hits else Result(
            Decision.ALLOW, "no rule objected", "default")
        self._log(action, final, now)
        self.timings.append((time.perf_counter() - started) * 1000)
        return final

    def _log(self, action: Action, result: Result, now: float) -> None:
        prev = self.audit[-1]["hash"] if self.audit else "GENESIS"
        entry = {
            "ts": round(now, 3), "agent": action.agent_id, "tool": action.tool,
            "source": action.source,
            "args": {k: mask_pii(v) if isinstance(v, str) else v for k, v in action.args.items()},
            "decision": result.decision.value, "rule": result.rule, "reason": result.reason,
            "prev": prev,
        }
        entry["hash"] = hashlib.sha256(json.dumps(entry, sort_keys=True).encode()).hexdigest()
        self.audit.append(entry)

    def record_human_decision(self, action: Action, approved: bool, approver: str = "manager") -> Result:
        """Write the human's approve/reject into the audit log, so the record is complete."""
        verdict = "approved" if approved else "rejected"
        res = Result(Decision.ALLOW if approved else Decision.DENY, f"{verdict} by {approver}", "human_approval")
        self._log(action, res, self.clock())
        return res

    def find_tampering(self) -> Optional[int]:
        """Index of the first entry that fails the hash-chain check, or None if the chain is intact."""
        prev = "GENESIS"
        for i, e in enumerate(self.audit):
            body = {k: v for k, v in e.items() if k != "hash"}
            if body["prev"] != prev:
                return i
            if hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest() != e["hash"]:
                return i
            prev = e["hash"]
        return None

    def stats(self) -> Dict[str, Any]:
        """Counts for a dashboard, worked out from the audit log."""
        count = lambda key: {k: sum(1 for e in self.audit if e[key] == k) for k in sorted({e[key] for e in self.audit})}
        ms = sorted(self.timings)
        pick = lambda p: round(ms[min(len(ms) - 1, int(round(p / 100 * (len(ms) - 1))))], 3) if ms else 0.0
        human = [e for e in self.audit if e["rule"] == "human_approval"]
        decided = [e for e in self.audit if e["rule"] != "human_approval"]
        return {
            "entries": len(self.audit),
            "proposed": len(decided),
            "decisions": {d: sum(1 for e in decided if e["decision"] == d) for d in ("allow", "require_approval", "deny")},
            "by_rule": {r: n for r, n in count("rule").items() if r not in ("default", "human_approval")},
            "by_tool": count("tool"),
            "untrusted_blocked": sum(1 for e in decided if e["source"] == "untrusted" and e["decision"] == "deny"),
            "human": {"approved": sum(1 for e in human if e["decision"] == "allow"), "rejected": sum(1 for e in human if e["decision"] == "deny")},
            "decision_ms": {"p50": pick(50), "p95": pick(95)},
        }

    def verify_audit(self) -> bool:
        """Tamper check: recompute the hash chain."""
        return self.find_tampering() is None


def default_engine(config: Optional[Dict[str, Any]] = None, clock=time.time) -> PolicyEngine:
    c = {**DEFAULT_CONFIG, **(config or {})}
    return PolicyEngine([
        ToolAllowlist(c["allowed_tools"]),
        ApprovalTools(c["approval_tools"]),
        PaymentLimits(c["payment_auto_limit"], c["payment_approval_limit"]),
        PIIPolicy(c["outbound_tools"]),
        RecipientPolicy(c["internal_email_domains"]),
        NetworkPolicy(c["allowed_url_hosts"]),
        InjectionPolicy(c["sensitive_tools"]),
        DailySpendLimit(c["daily_spend_limit"], c["payment_approval_limit"]),
        RateLimit(c["max_actions_per_window"], c["window_seconds"]),
    ], clock=clock)


# ---------------------------------------------------------- tool wrapping
class PolicyViolation(Exception):
    pass


def guarded(engine: PolicyEngine, tool_name: str, approver: Optional[Callable[[Action], bool]] = None,
            agent_id: str = "agent-001"):
    """Wrap a tool function. Approval defaults to 'no' if no approver is supplied (safe default)."""
    def deco(fn):
        @functools.wraps(fn)
        def wrapper(*, source: str = "user", **kwargs):
            action = Action(tool_name, kwargs, agent_id, source)
            res = engine.evaluate(action)
            if res.decision == Decision.DENY:
                raise PolicyViolation(f"DENIED by {res.rule}: {res.reason}")
            if res.decision == Decision.REQUIRE_APPROVAL and not (approver and approver(action)):
                raise PolicyViolation(f"NOT APPROVED ({res.rule}): {res.reason}")
            return fn(**kwargs)
        return wrapper
    return deco
