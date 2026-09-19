"""The whole workflow in one command: audit a server, generate its policy, enforce it.

    python3 examples/pipeline.py

This is the step that was missing between the two tools. An audit on its own is a report
that somebody has to translate into rules; here the audit *emits* the policy, with the
declaration each rule came from quoted in its rationale, and the gate then enforces it.

policygate is optional for this demo — the policy TOML is plain data — but if it is
importable the demo also shows the decisions the generated policy produces.
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from mcpaudit import audit, extract_tools  # noqa: E402
from mcpaudit.policy_out import summarise, to_policy  # noqa: E402


def generate(example: str) -> tuple[str, list[str]]:
    tools = extract_tools(json.loads((ROOT / "examples" / example).read_text()))
    result = audit(tools)
    policy = to_policy(tools, result, server=example)
    names = [str(t.get("name")) for t in tools]
    print(f"\n{example}: {len(tools)} tool(s) — audit found {summarise(result)}")
    for finding in result.findings:
        print(f"   {finding.severity.upper():<8} [{finding.rule}] {finding.tool}")
    return policy, names


def main() -> int:
    print("=" * 78)
    print("STEP 1 — audit the declarations")

    clean_policy, clean_names = generate("tools_clean.json")
    poisoned_policy, poisoned_names = generate("tools_poisoned.json")

    print("\n" + "=" * 78)
    print("STEP 2 — the generated policy (poisoned server, rules only)\n")
    for line in poisoned_policy.splitlines():
        if line.startswith(("[[rules]]", "id =", "effect =", "tool =")):
            print("   " + line)

    print("\n" + "=" * 78)
    print("STEP 3 — enforce it\n")

    try:
        sys.path.insert(0, str(ROOT.parent / "policygate" / "src"))
        from policygate import Gate, load_policy  # type: ignore
    except ImportError:
        print("   policygate is not importable here, so enforcement is not shown.")
        print("   The policy above is valid TOML and loads with policygate.Gate.from_file.")
        return 0

    with tempfile.TemporaryDirectory() as tmp:
        for label, policy_text, names in (
            ("clean", clean_policy, clean_names),
            ("poisoned", poisoned_policy, poisoned_names),
        ):
            path = Path(tmp) / f"{label}.toml"
            path.write_text(policy_text, encoding="utf-8")
            gate = Gate(load_policy(path))
            print(f"   {label} server policy:")
            for name in names:
                decision = gate.check(name)
                print(f"      {name:<20} -> {decision.effect.value.upper():<9} {decision.rule or ''}")
            uncovered = gate.check("capability_added_later")
            print(f"      {'<uncovered tool>':<20} -> {uncovered.effect.value.upper():<9} (default)")
            print()

    print("The point: a tool that was not in the audit is not allowed just because it is new.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
