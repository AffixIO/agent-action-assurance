"""Independent processes share durable state, not Python locks or in-memory sets."""

import multiprocessing
from concurrent.futures import ProcessPoolExecutor
from dataclasses import asdict, replace

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from assurance import ActionRequest, PolicyGate, SigningKey, ToolPolicy


def dispatch(values):
    database, authority, audit_key, request = values
    # Ephemeral test key shared through process IPC only, never committed or printed.
    auditor = SigningKey("audit", Ed25519PrivateKey.from_private_bytes(audit_key))
    gate = PolicyGate(
        database,
        audience="host",
        authorities={"authority": authority},
        reviewers={},
        audit_signer=auditor,
        clock=lambda: 100,
    )
    gate.register_tool(
        ToolPolicy("invoice", "v1", review_above_minor=30000, argument_keys=("description",)),
        lambda _: {"simulated": True},
    )
    return gate.execute(ActionRequest(**request), "m", authenticated_agent="agent").state


def test_multiple_processes_share_replay_and_budget_reservations(rig):
    common = (rig.gate.database, rig.authority.public_key, rig.auditor._key.private_bytes_raw())
    requests = [
        asdict(replace(rig.request, operation_id=f"op-{i % 4}", amount_minor=30000)) for i in range(12)
    ]
    with ProcessPoolExecutor(max_workers=4, mp_context=multiprocessing.get_context("spawn")) as pool:
        results = list(pool.map(dispatch, [(*common, request) for request in requests]))
    assert results.count("COMPLETED") == 3
    assert results.count("BLOCKED") == 9
    assert rig.execute().decision.reason == "budget-exhausted"
