"""A 10-second demo of BankGuard. No AI key needed.

A pretend AI agent proposes actions. BankGuard decides allow / ask a human / deny.
Run:  python3 demo.py
"""
from bankguard import PolicyViolation, default_engine, guarded

engine = default_engine()


def manager_says_yes(action):
    print("      -> human approval requested for %s. Manager clicks APPROVE." % action.tool)
    return True


def manager_says_no(action):
    print("      -> human approval requested for %s. Manager clicks REJECT." % action.tool)
    return False


@guarded(engine, "create_payment")
def create_payment(amount, payee):
    return "payment of INR {:,} to {} created".format(amount, payee)


@guarded(engine, "close_account", approver=manager_says_yes)
def close_account(customer_id):
    return "account of %s closed" % customer_id


@guarded(engine, "export_data", approver=manager_says_no)
def export_data(customer_id):
    return "data of %s exported" % customer_id


@guarded(engine, "send_email")
def send_email(recipient, body):
    return "email sent to %s" % recipient


@guarded(engine, "http_request")
def http_request(url):
    return "fetched " + url


@guarded(engine, "delete_database")
def delete_database(name):
    return "deleted " + name


def attempt(title, fn, **kwargs):
    print("\n%s" % title)
    try:
        print("   ALLOWED:", fn(**kwargs))
    except PolicyViolation as e:
        print("   STOPPED:", e)


attempt("1. Small payment, within the auto limit", create_payment, amount=5000, payee="Acme Supplies")
attempt("2. Payment above the auto limit but below the hard limit", create_payment, amount=50000, payee="Acme Supplies")
attempt("3. Payment above the hard limit", create_payment, amount=250000, payee="Acme Supplies")
attempt("4. Account closure, a human approves", close_account, customer_id="C1001")
attempt("5. Data export, a human rejects", export_data, customer_id="C1001")
attempt("6. Email to an outside address", send_email, recipient="someone@gmail.com", body="Your statement is ready")
attempt("7. Email that contains a raw PAN", send_email, recipient="ops@examplebank.com", body="PAN is ABCDE1234F")
attempt("8. Look-alike website", http_request, url="https://api.internal.examplebank.com.evil.io/steal")
attempt("9. A tool the agent should never have", delete_database, name="customers")
attempt("10. A poisoned email tells the agent to pay (content came from an untrusted source)",
        create_payment, amount=900, payee="Unknown Ltd", source="untrusted")

print("\nAudit log: %d decisions recorded. Chain intact: %s" % (len(engine.audit), engine.verify_audit()))
engine.audit[2]["decision"] = "allow"  # someone edits history
print("After tampering with entry 3. Chain intact: %s" % engine.verify_audit())
