"""Run the BankGuard eval set and write results.md.

Usage:  python evals/run_evals.py
Exit code is 1 if any UNSAFE ALLOW occurs (the failure a bank cares about most).
"""
import csv
import sys
from collections import defaultdict
from pathlib import Path

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE.parent))

from bankguard import Action, default_engine  # noqa: E402


def load_cases():
    with open(HERE / "tests.csv", newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def to_action(row) -> Action:
    args = {}
    if row["amount"] != "":
        args["amount"] = float(row["amount"])
    for key in ("recipient", "url", "text"):
        if row[key] != "":
            args[key] = row[key]
    return Action(row["tool"], args, source=row["source"])


def main() -> int:
    cases = load_cases()
    by_cat = defaultdict(lambda: [0, 0])
    failures, unsafe, over_block = [], 0, 0
    for row in cases:
        got = default_engine().evaluate(to_action(row))  # fresh engine per case
        ok = got.decision.value == row["expected"]
        by_cat[row["category"]][1] += 1
        by_cat[row["category"]][0] += ok
        if not ok:
            failures.append((row, got))
            if row["expected"] != "allow" and got.decision.value == "allow":
                unsafe += 1
            elif row["expected"] == "allow":
                over_block += 1
    total = len(cases)
    passed = total - len(failures)

    lines = [
        "# BankGuard eval results", "",
        f"- Cases: {total}", f"- Passed: {passed} ({passed / total:.1%})",
        f"- Unsafe allows (must be 0): {unsafe}",
        f"- Over-blocks (safe action wrongly stopped): {over_block}", "",
        "| Category | Passed | Total |", "|---|---|---|",
    ]
    for cat, (p, t) in by_cat.items():
        lines.append(f"| {cat} | {p} | {t} |")
    if failures:
        lines += ["", "## Failures", "", "| id | tool | expected | got | rule | reason |", "|---|---|---|---|---|---|"]
        for row, got in failures:
            lines.append(f"| {row['id']} | {row['tool']} | {row['expected']} | {got.decision.value} | {got.rule} | {got.reason} |")
    out = "\n".join(lines) + "\n"
    (HERE / "results.md").write_text(out, encoding="utf-8")
    print(out)
    return 1 if unsafe else 0


if __name__ == "__main__":
    sys.exit(main())
