import json
from copy import deepcopy
from dataclasses import replace

import pytest

from assurance import SigningKey, verify_audit
from assurance.demo import run_demo


def child(rig, **changes):
    return replace(
        rig.mandate,
        mandate_id="child",
        agent_id="worker",
        parent_mandate="m",
        **{
            "resource_scope": "invoices/team",
            "max_amount_minor": 10000,
            "total_budget_minor": 20000,
            "max_calls": 2,
            "can_delegate": False,
            **changes,
        },
    )


@pytest.mark.parametrize(
    "change",
    [
        {"resource_scope": "secrets"},
        {"max_amount_minor": 50001, "total_budget_minor": 50001},
        {"total_budget_minor": 100001},
        {"max_calls": 6},
        {"expires_at": 201},
        {"not_before": 89},
        {"principal": "other"},
        {"tool": "other"},
        {"currency": "USD"},
        {"audience": "other"},
    ],
)
def test_child_cannot_broaden_any_parent_constraint(rig, change):
    with pytest.raises(ValueError):
        rig.gate.add(child(rig, **change).signed(rig.authority))


def test_ancestor_budget_is_shared_by_siblings(rig):
    for i in range(2):
        mandate = replace(
            child(rig), mandate_id=f"child-{i}", max_amount_minor=30000, total_budget_minor=90000, max_calls=5
        )
        rig.gate.add(mandate.signed(rig.authority))
    for i in range(4):
        request = replace(
            rig.request,
            operation_id=f"child-op-{i}",
            agent_id="worker",
            resource="invoices/team/x",
            amount_minor=30000,
        )
        result = rig.execute(request, mid=f"child-{i % 2}", actor="worker")
        assert result.state == ("COMPLETED" if i < 3 else "BLOCKED")
    assert len(rig.calls) == 3


def test_parent_revocation_invalidates_descendant_after_restart(rig):
    rig.gate.add(child(rig).signed(rig.authority))
    request = replace(rig.request, agent_id="worker", resource="invoices/team/x", amount_minor=1000)
    assert rig.gate.check(request, "child", authenticated_agent="worker").outcome == "ALLOW"
    rig.gate.revoke("m")
    assert (
        rig.execute(request, mid="child", actor="worker", target=rig.new_gate()).decision.reason == "revoked"
    )


def test_child_cannot_delegate_without_permission(rig):
    first = child(rig)
    rig.gate.add(first.signed(rig.authority))
    with pytest.raises(ValueError, match="delegation"):
        rig.gate.add(replace(first, mandate_id="grandchild", parent_mandate="child").signed(rig.authority))


def test_delegation_depth_is_bounded(rig):
    parent = rig.mandate
    for i in range(4):
        parent = replace(parent, mandate_id=f"depth-{i}", parent_mandate=parent.mandate_id)
        rig.gate.add(parent.signed(rig.authority))
    with pytest.raises(ValueError, match="depth"):
        rig.gate.add(
            replace(parent, mandate_id="too-deep", parent_mandate=parent.mandate_id).signed(rig.authority)
        )


def test_mandates_cannot_be_overwritten(rig):
    with pytest.raises(ValueError, match="immutable"):
        rig.gate.add(replace(rig.mandate, max_calls=99).signed(rig.authority))


def test_audit_signature_and_external_checkpoint(rig):
    rig.execute()
    bundle = rig.gate.export_audit()
    checkpoint = deepcopy(bundle["checkpoint"])

    def valid(candidate, pins=None):
        return verify_audit(
            candidate,
            trusted_keys=pins or {"audit": rig.auditor.public_key},
            expected_ledger_id=rig.gate.ledger_id,
            expected_checkpoint=checkpoint,
        )

    assert valid(bundle)
    mutated = deepcopy(bundle)
    mutated["events"][1]["payload"]["details"]["outcome"] = "DENY"
    assert not valid(mutated)
    assert not valid({**bundle, "events": bundle["events"][:-1]})
    assert not valid({**bundle, "events": list(reversed(bundle["events"]))})
    assert not valid(bundle, {"audit": SigningKey("attacker").public_key})


def test_old_signed_bundle_rejected_against_newer_checkpoint(rig):
    before = rig.gate.export_audit()
    rig.execute()
    after = rig.gate.export_audit()
    assert not verify_audit(
        before,
        trusted_keys={"audit": rig.auditor.public_key},
        expected_ledger_id=rig.gate.ledger_id,
        expected_checkpoint=after["checkpoint"],
    )


def test_export_excludes_action_arguments_and_private_keys(rig):
    secret = "fictional-private-invoice-description"
    rig.execute(replace(rig.request, arguments={"description": secret}))
    text = json.dumps(rig.gate.export_audit())
    assert secret not in text
    assert "PRIVATE KEY" not in text
    assert "request_digest" in text


def test_demo_has_exactly_three_simulated_effects():
    report = run_demo()
    assert report["protected_calls"] == 3
    assert report["audit_verified"]
    assert {row["decision"] for row in report["scenarios"]} == {"ALLOW", "REVIEW", "DENY"}
