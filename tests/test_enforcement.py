import sqlite3
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace

import pytest

from assurance import ActionRequest, EnforcementUnavailable, SigningKey
from assurance.crypto import canonical, strict_loads, verify


def test_allow_review_deny_do_not_dispatch_blocked_requests(rig):
    assert rig.execute().state == "COMPLETED"
    assert (
        rig.execute(replace(rig.request, operation_id="review", amount_minor=45000)).decision.outcome
        == "REVIEW"
    )
    assert (
        rig.execute(replace(rig.request, operation_id="deny", amount_minor=75000)).decision.outcome == "DENY"
    )
    assert len(rig.calls) == 1


def test_review_threshold_cannot_be_disabled_by_agent(rig):
    with pytest.raises(TypeError):
        ActionRequest("op", "agent", "invoice", "invoices/one", "host", requires_review=False)
    request = replace(rig.request, amount_minor=45000)
    assert rig.execute(request).state == "BLOCKED"
    assert rig.execute(request, rig.token(request)).state == "COMPLETED"


@pytest.mark.parametrize(
    "change",
    [
        {"arguments": {"description": "Altered"}},
        {"amount_minor": 46000},
        {"resource": "invoices/two"},
        {"currency": "USD"},
        {"agent_id": "other"},
        {"tool": "other"},
        {"audience": "other"},
        {"operation_id": "other"},
    ],
)
def test_approval_binds_every_material_field(rig, change):
    request = replace(rig.request, amount_minor=45000)
    assert rig.execute(replace(request, **change), rig.token(request)).state == "BLOCKED"
    assert not rig.calls


def test_policy_change_invalidates_existing_approval(rig):
    request = replace(rig.request, amount_minor=45000)
    token = rig.token(request)
    rig.gate.register_tool(replace(rig.policy, version="v2"), rig.handler)
    assert rig.execute(request, token).decision.reason == "approval-binding-mismatch"


@pytest.mark.parametrize("field,value", [("max_amount_minor", 99999), ("agent_id", "other")])
def test_rehashed_mandate_cannot_forge_signature(rig, field, value):
    envelope = rig.mandate.signed(rig.authority)
    envelope["payload"][field] = value
    with pytest.raises(ValueError, match="signature"):
        rig.gate.add(envelope)


def test_unknown_signer_and_wrong_signature_context_fail(rig):
    with pytest.raises(ValueError):
        rig.gate.add(rig.mandate.signed(SigningKey("attacker")))
    with pytest.raises(ValueError):
        verify(rig.token(), {"reviewer": rig.reviewer.public_key}, "mandate")


@pytest.mark.parametrize("now", [89, 200, 201])
def test_mandate_time_boundaries(rig, now):
    rig.now[0] = now
    assert rig.execute().state == "BLOCKED"
    assert not rig.calls


@pytest.mark.parametrize("now", [99, 150])
def test_approval_time_boundaries(rig, now):
    request = replace(rig.request, amount_minor=45000)
    token = rig.token(request)
    rig.now[0] = now
    assert rig.execute(request, token).state == "BLOCKED"


@pytest.mark.parametrize("kind,identity", [("key", "reviewer"), ("approval", "approval")])
def test_approval_revocation(rig, kind, identity):
    request = replace(rig.request, amount_minor=45000)
    token = rig.token(request)
    rig.gate.revoke(identity, kind=kind)
    assert rig.execute(request, token).state == "BLOCKED"


def test_authority_key_revocation(rig):
    rig.gate.revoke("authority", kind="key")
    assert rig.execute().decision.reason == "revoked"


def test_preview_is_not_execution_authority(rig):
    assert rig.gate.check(rig.request, "m", authenticated_agent="agent").outcome == "ALLOW"
    assert not rig.calls
    rig.gate.revoke("m")
    assert rig.execute().state == "BLOCKED"


def test_authenticated_identity_is_separate_from_claimed_identity(rig):
    assert rig.execute(actor="attacker").decision.reason == "authenticated-actor-mismatch"


@pytest.mark.parametrize("resource", ["invoices-other/one", "invoices2/one", "invoice/one"])
def test_resource_scope_uses_segment_boundaries(rig, resource):
    assert rig.execute(replace(rig.request, resource=resource)).decision.reason == "resource-out-of-scope"


@pytest.mark.parametrize(
    "resource", ["invoices/../secret", "invoices/%2e%2e/secret", "invoices//x", "invoices/./x"]
)
def test_encoded_and_traversal_resources_rejected(rig, resource):
    with pytest.raises(ValueError):
        replace(rig.request, resource=resource)


@pytest.mark.parametrize("value", [True, -1, 1.5, float("nan"), float("inf"), 2**53])
def test_invalid_amounts_fail_at_boundary(rig, value):
    with pytest.raises(ValueError):
        replace(rig.request, amount_minor=value)


def test_noncanonical_json_rejected():
    for raw in ['{"a":1,"a":2}', '{"amount":NaN}', '{"a":1.1}']:
        with pytest.raises(ValueError):
            strict_loads(raw)
    with pytest.raises(ValueError):
        canonical({"a": "x" * 65536})


def test_unknown_arguments_fail(rig):
    assert (
        rig.execute(replace(rig.request, arguments={"force": True})).decision.reason
        == "argument-schema-mismatch"
    )


def test_restart_preserves_replay_state(rig):
    rig.execute()
    assert rig.execute(target=rig.new_gate()).decision.reason == "replay"
    assert len(rig.calls) == 1


def test_one_use_mandate_cannot_be_reused_with_new_operation_id(rig):
    single = replace(rig.mandate, mandate_id="single", max_calls=1)
    rig.gate.add(single.signed(rig.authority))
    assert rig.execute(mid="single").state == "COMPLETED"
    assert (
        rig.execute(replace(rig.request, operation_id="fresh"), mid="single").decision.reason == "call-limit"
    )


def test_concurrent_connections_dispatch_once(rig):
    gates = [rig.new_gate() for _ in range(12)]
    with ThreadPoolExecutor(max_workers=12) as pool:
        results = list(pool.map(lambda gate: rig.execute(target=gate), gates))
    assert sum(r.state == "COMPLETED" for r in results) == 1
    assert len(rig.calls) == 1


def test_concurrent_budget_never_overspends(rig):
    requests = [replace(rig.request, operation_id=f"op-{i}", amount_minor=30000) for i in range(8)]
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda request: rig.execute(request, target=rig.new_gate()), requests))
    assert sum(r.state == "COMPLETED" for r in results) == 3
    assert sum(r.amount_minor for r in rig.calls) == 90000


def test_uncertain_effect_is_never_automatically_retried(rig):
    def failing(request):
        rig.calls.append(request)
        raise TimeoutError("possibly completed remotely")

    rig.gate.register_tool(rig.policy, failing)
    assert rig.execute().state == "UNCERTAIN"
    assert rig.gate.operation_state("op") == "UNCERTAIN"
    assert rig.execute(target=rig.new_gate()).decision.reason == "replay"
    assert len(rig.calls) == 1


def test_crash_after_reservation_stays_reserved(rig):
    def crash(_):
        raise SystemExit()

    rig.gate.register_tool(rig.policy, crash)
    with pytest.raises(SystemExit):
        rig.execute()
    assert rig.gate.operation_state("op") == "RESERVED"
    assert rig.execute(target=rig.new_gate()).decision.reason == "replay"


def test_storage_failure_performs_zero_tool_calls(rig):
    with sqlite3.connect(rig.gate.database) as db:
        db.execute("DROP TABLE operations")
    with pytest.raises(EnforcementUnavailable):
        rig.execute()
    assert not rig.calls


def test_request_input_is_snapshotted_before_dispatch(rig):
    approved = replace(rig.request, amount_minor=45000)
    token = rig.token(approved)

    def handler(snapshot):
        approved.arguments["description"] = "Mutated by caller"
        assert snapshot.arguments["description"] == "Fictional invoice"
        return {"simulated": True}

    rig.gate.register_tool(rig.policy, handler)
    assert rig.execute(approved, token).state == "COMPLETED"


def test_duplicate_operation_with_different_payload_is_still_rejected(rig):
    rig.execute()
    assert rig.execute(replace(rig.request, amount_minor=1000)).decision.reason == "replay"
    assert len(rig.calls) == 1


def test_reissued_approval_id_cannot_authorise_a_second_operation(rig):
    first = replace(rig.request, amount_minor=45000)
    second = replace(first, operation_id="second")
    assert rig.execute(first, rig.token(first)).state == "COMPLETED"
    assert rig.execute(second, rig.token(second)).decision.reason == "approval-replay"
    assert len(rig.calls) == 1


def test_signed_empty_approval_id_is_rejected(rig):
    request = replace(rig.request, amount_minor=45000)
    payload = rig.token(request)["payload"]
    payload["approval_id"] = ""
    assert rig.execute(request, rig.reviewer.sign("approval", payload)).state == "BLOCKED"


def test_tool_mutation_does_not_rewrite_original_request_evidence(rig):
    expected = rig.request.fingerprint

    def handler(snapshot):
        snapshot.arguments["description"] = "Tool-local mutation"
        return {"simulated": True}

    rig.gate.register_tool(rig.policy, handler)
    rig.execute()
    events = rig.gate.export_audit()["events"]
    assert events[-1]["payload"]["details"]["request_digest"] == expected


def test_result_log_failure_leaves_reserved_operation_not_safe_to_retry(rig):
    def handler(request):
        rig.calls.append(request)
        with sqlite3.connect(rig.gate.database) as db:
            db.execute("DROP TABLE audit")
        return {"simulated": True}

    rig.gate.register_tool(rig.policy, handler)
    with pytest.raises(EnforcementUnavailable):
        rig.execute()
    assert len(rig.calls) == 1
    assert rig.gate.operation_state("op") == "RESERVED"
