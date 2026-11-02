from dataclasses import replace
from types import SimpleNamespace

import pytest

from assurance import ActionRequest, Mandate, PolicyGate, SigningKey, ToolPolicy, approve


@pytest.fixture
def rig(tmp_path):
    authority, reviewer, auditor = (SigningKey(key) for key in ("authority", "reviewer", "audit"))
    now, calls = [100], []
    policy = ToolPolicy("invoice", "v1", review_above_minor=30000, argument_keys=("description",))
    mandate = Mandate(
        "m", "owner", "agent", "invoice", "invoices", "host", 50000, 100000, 5, 90, 200, can_delegate=True
    )
    request = ActionRequest(
        "op",
        "agent",
        "invoice",
        "invoices/one",
        "host",
        15000,
        arguments={"description": "Fictional invoice"},
    )

    def handler(action):
        calls.append(action)
        return {"simulated": True}

    def new_gate():
        gate = PolicyGate(
            tmp_path / "state.db",
            audience="host",
            authorities={"authority": authority.public_key},
            reviewers={"reviewer": reviewer.public_key},
            audit_signer=auditor,
            clock=lambda: now[0],
        )
        gate.register_tool(policy, handler)
        return gate

    gate = new_gate()
    gate.add(mandate.signed(authority))

    def execute(action=None, token=None, mid="m", actor="agent", target=None):
        return (target or gate).execute(action or request, mid, authenticated_agent=actor, approval=token)

    def token(action=None, **changes):
        options = {"approval_id": "approval", "not_before": 100, "expires_at": 150, **changes}
        return approve(action or replace(request, amount_minor=45000), mandate, policy, reviewer, **options)

    return SimpleNamespace(**locals())
