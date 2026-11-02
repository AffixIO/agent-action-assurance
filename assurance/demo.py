"""Fictional invoice actions; no network or model credentials required."""

import argparse
import json
from dataclasses import replace
from pathlib import Path
from tempfile import TemporaryDirectory

from . import ActionRequest, Mandate, PolicyGate, SigningKey, ToolPolicy, approve, verify_audit


def run_demo():
    authority, reviewer, auditor = (SigningKey(name) for name in ("authority", "manager", "auditor"))
    now = 1000
    calls = []
    policy = ToolPolicy("invoice.simulate", "v2", review_above_minor=30000, argument_keys=("description",))
    mandate = Mandate(
        "mandate-1",
        "fictional-team",
        "agent-1",
        policy.tool,
        "invoices",
        "demo-host",
        50000,
        100000,
        10,
        900,
        2000,
        can_delegate=True,
    )
    with TemporaryDirectory() as directory:
        gate = PolicyGate(
            Path(directory) / "demo.db",
            audience="demo-host",
            authorities={authority.key_id: authority.public_key},
            reviewers={reviewer.key_id: reviewer.public_key},
            audit_signer=auditor,
            clock=lambda: now,
        )

        def invoice(request):
            calls.append(request.operation_id)
            return {
                "simulated": True,
                "operation_id": request.operation_id,
                "amount_minor": request.amount_minor,
                "currency": request.currency,
            }

        gate.register_tool(policy, invoice)
        gate.add(mandate.signed(authority))
        request = ActionRequest(
            "invoice-150",
            "agent-1",
            policy.tool,
            "invoices/demo",
            "demo-host",
            15000,
            arguments={"description": "Fictional stationery"},
        )
        review = replace(request, operation_id="invoice-450", amount_minor=45000)
        denied = replace(request, operation_id="invoice-750", amount_minor=75000)
        decisions = []

        def execute(label, proposed, token=None, mandate_id="mandate-1"):
            result = gate.execute(proposed, mandate_id, authenticated_agent=proposed.agent_id, approval=token)
            decisions.append(
                {
                    "scenario": label,
                    "decision": result.decision.outcome,
                    "reason": result.decision.reason,
                    "execution": result.state,
                }
            )

        execute("GBP 150", request)
        execute("GBP 450 needs review", review)
        execute("GBP 750 exceeds cap", denied)
        token = approve(
            review, mandate, policy, reviewer, approval_id="review-450", not_before=now, expires_at=1100
        )
        execute(
            "Changed approved arguments", replace(review, arguments={"description": "Different order"}), token
        )
        execute("Approved GBP 450", review, token)
        execute("Replay", review, token)
        child = replace(
            mandate,
            mandate_id="child",
            agent_id="agent-2",
            parent_mandate="mandate-1",
            resource_scope="invoices/team",
            max_amount_minor=10000,
            total_budget_minor=20000,
            max_calls=2,
            can_delegate=False,
        )
        gate.add(child.signed(authority))
        delegated = replace(
            request,
            operation_id="child-invoice",
            agent_id="agent-2",
            resource="invoices/team/1",
            amount_minor=5000,
        )
        execute("Delegated GBP 50", delegated, mandate_id="child")
        gate.revoke("mandate-1")
        execute("Parent revoked", replace(delegated, operation_id="child-after-revoke"), mandate_id="child")
        bundle = gate.export_audit()
        valid = verify_audit(
            bundle,
            trusted_keys={auditor.key_id: auditor.public_key},
            expected_ledger_id=gate.ledger_id,
            expected_checkpoint=bundle["checkpoint"],
        )
        return {
            "mode": "simulation",
            "scenarios": decisions,
            "protected_calls": len(calls),
            "audit_verified": valid,
            "bundle": bundle,
            "audit_public_key": auditor.public_key,
        }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="Print the complete synthetic audit export")
    args = parser.parse_args()
    result = run_demo()
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        for row in result["scenarios"]:
            print(f"{row['scenario']:<30} {row['decision']:<6} {row['reason']}")
        print(f"Protected calls: {result['protected_calls']} | Audit verified: {result['audit_verified']}")


if __name__ == "__main__":
    main()
