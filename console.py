"""console.py - a web console for BankGuard. No AI, no keys, no packages.

Run:  python3 console.py      then open http://localhost:8001

You propose an action the way an AI agent would. BankGuard decides allow / ask a human / deny,
shows which rules objected, and records everything in a tamper-evident audit log.
Everything is simulated: no real money, email or data moves.
"""
import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from bankguard import DEFAULT_CONFIG, Action, Decision, default_engine, mask_pii

UI_FILE = Path(__file__).parent / "ui" / "console.html"
PORT = int(os.environ.get("BANKGUARD_PORT", "8001"))

# What each tool would do if it were allowed to run. These are pretend tools.
EFFECTS = {
    "create_payment": lambda a: "Payment of INR {:,.0f} to {} created.".format(a.get("amount", 0), a.get("payee") or "the payee"),
    "send_email": lambda a: "Email sent to {}.".format(a.get("recipient", "the recipient")),
    "post_message": lambda a: "Message posted to {}.".format(a.get("channel") or "the channel"),
    "http_request": lambda a: "Fetched {}.".format(a.get("url", "the page")),
    "close_account": lambda a: "Account {} closed.".format(a.get("customer_id", "")),
    "export_data": lambda a: "Data for {} exported.".format(a.get("customer_id", "")),
    "lookup_customer": lambda a: "Customer {} looked up.".format(a.get("customer_id", "")),
    "read_policy": lambda a: "Policy read.",
    "draft_email": lambda a: "Email drafted.",
}


def effect_text(action):
    fn = EFFECTS.get(action.tool)
    return (fn(action.args) if fn else "Tool ran.") + " (simulated, nothing real happened)"


def show_args(args):
    """Arguments as shown on screen: personal data masked, the same way the audit log does it."""
    return {k: mask_pii(v) if isinstance(v, str) else v for k, v in args.items()}


class Session:
    """One engine plus the actions waiting for a human. Held in memory only."""

    def __init__(self):
        self.lock = threading.Lock()
        self.reset()

    def reset(self):
        with self.lock:
            self.engine = default_engine()
            self.pending = {}
            self.counter = 0

    def propose(self, tool, args, source):
        action = Action(tool, args, source=source)
        with self.lock:
            result = self.engine.evaluate(action)
            out = {
                "tool": tool,
                "args": show_args(args),
                "source": source,
                "decision": result.decision.value,
                "rule": result.rule,
                "reason": result.reason,
                "objections": [{"rule": h.rule, "decision": h.decision.value, "reason": h.reason} for h in self.engine.last_hits],
                "audit_index": len(self.engine.audit) - 1,
            }
            if result.decision == Decision.ALLOW:
                out.update(outcome="executed", message=effect_text(action))
            elif result.decision == Decision.DENY:
                out.update(outcome="blocked", message="The tool did not run.")
            else:
                self.counter += 1
                pid = str(self.counter)
                self.pending[pid] = action
                out.update(outcome="pending", pending_id=pid, message="Waiting for a human to approve or reject.")
            return out

    def decide(self, pid, approve):
        with self.lock:
            action = self.pending.pop(str(pid), None)
            if action is None:
                raise KeyError("That request is no longer waiting for approval.")
            self.engine.record_human_decision(action, approve)
            if approve:
                return {"outcome": "executed", "message": effect_text(action), "audit_index": len(self.engine.audit) - 1}
            return {"outcome": "rejected", "message": "Rejected by the approver. The tool did not run.", "audit_index": len(self.engine.audit) - 1}

    def audit(self):
        with self.lock:
            entries = [
                {"index": i, "tool": e["tool"], "source": e["source"], "decision": e["decision"], "rule": e["rule"],
                 "reason": e["reason"], "hash": e["hash"], "prev": e["prev"]}
                for i, e in enumerate(self.engine.audit)
            ]
            return {"entries": entries, "broken_at": self.engine.find_tampering()}

    def stats(self):
        with self.lock:
            return self.engine.stats()

    def export(self):
        """The whole audit log, one JSON object per line, for an auditor or a log system."""
        with self.lock:
            return "\n".join(json.dumps(e, sort_keys=True) for e in self.engine.audit) + "\n"

    def tamper(self, index):
        with self.lock:
            if not 0 <= index < len(self.engine.audit):
                raise KeyError("There is no such entry.")
            entry = self.engine.audit[index]
            entry["decision"] = "allow" if entry["decision"] != "allow" else "deny"

    def config(self):
        c = DEFAULT_CONFIG
        return {
            "auto_limit": c["payment_auto_limit"],
            "approval_limit": c["payment_approval_limit"],
            "internal_domains": sorted(c["internal_email_domains"]),
            "allowed_hosts": sorted(c["allowed_url_hosts"]),
            "tools": sorted(c["allowed_tools"]),
            "approval_tools": sorted(c["approval_tools"]),
            "rate": "%d actions per %d seconds" % (c["max_actions_per_window"], c["window_seconds"]),
            "daily_spend_limit": c["daily_spend_limit"],
        }


SESSION = Session()


def clean_args(raw):
    """Keep only simple values and a sane size. Strings are kept as typed so the rules can inspect them."""
    if not isinstance(raw, dict) or len(raw) > 10:
        raise ValueError("Arguments must be a small object.")
    out = {}
    for k, v in raw.items():
        if not isinstance(k, str) or len(k) > 40:
            raise ValueError("Bad argument name.")
        if isinstance(v, bool) or not isinstance(v, (str, int, float)):
            raise ValueError("Argument '%s' must be text or a number." % k)
        if isinstance(v, str) and len(v) > 500:
            raise ValueError("Argument '%s' is too long." % k)
        out[k] = v
    return out


class Handler(BaseHTTPRequestHandler):
    def _send(self, status, body, content_type="application/json"):
        data = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", content_type + "; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        path = self.path.split("?")[0]
        if path in ("/", "/index.html"):
            return self._send(200, UI_FILE.read_bytes(), "text/html")
        if path == "/api/config":
            return self._send(200, SESSION.config())
        if path == "/api/audit":
            return self._send(200, SESSION.audit())
        if path == "/api/stats":
            return self._send(200, SESSION.stats())
        if path == "/api/export":
            return self._send(200, SESSION.export().encode(), "application/x-ndjson")
        self._send(404, {"error": "Not found."})

    def do_POST(self):
        try:
            length = int(self.headers.get("Content-Length", 0))
            data = json.loads(self.rfile.read(length) or b"{}")
            if not isinstance(data, dict):
                raise ValueError
        except ValueError:
            return self._send(400, {"error": "Send a JSON object."})
        try:
            if self.path == "/api/propose":
                tool = str(data.get("tool", "")).strip()
                source = data.get("source", "user")
                if not tool or len(tool) > 40:
                    raise ValueError("Choose a tool.")
                if source not in ("user", "untrusted"):
                    raise ValueError("Source must be 'user' or 'untrusted'.")
                return self._send(200, SESSION.propose(tool, clean_args(data.get("args", {})), source))
            if self.path == "/api/decide":
                return self._send(200, SESSION.decide(data.get("id"), bool(data.get("approve"))))
            if self.path == "/api/tamper":
                SESSION.tamper(int(data.get("index", -1)))
                return self._send(200, SESSION.audit())
            if self.path == "/api/reset":
                SESSION.reset()
                return self._send(200, {"ok": True})
        except (ValueError, KeyError, TypeError) as e:
            return self._send(400, {"error": str(e.args[0]) if e.args else "Bad request."})
        self._send(404, {"error": "Not found."})

    def log_message(self, fmt, *args):
        pass


def main():
    server = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    print("BankGuard Console is running. Open http://localhost:%d in your browser. Press Ctrl+C to stop." % PORT)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
        sys.exit(0)


if __name__ == "__main__":
    main()
