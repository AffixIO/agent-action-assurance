from assurance import ActionRequest, Mandate, PolicyGate

def gate():
    g = PolicyGate(); g.add(Mandate.issue("m", "human", "agent", "payments.create", "payment/", 500, 100)); return g

def test_allow_review_deny():
    g = gate()
    assert g.check(ActionRequest("a", "agent", "payments.create", "payment/1", 100), "m", 1).outcome == "ALLOW"
    assert g.check(ActionRequest("b", "agent", "payments.create", "payment/2", 100, True), "m", 1).outcome == "REVIEW"
    assert g.check(ActionRequest("c", "agent", "payments.create", "payment/3", 501), "m", 1).outcome == "DENY"

def test_replay_expiry_revocation_and_scope_fail_closed():
    g = gate(); g.check(ActionRequest("a", "agent", "payments.create", "payment/1", 100), "m", 1)
    assert g.check(ActionRequest("a", "agent", "payments.create", "payment/1", 100), "m", 1).reason == "replay"
    assert g.check(ActionRequest("b", "agent", "payments.create", "other/1", 100), "m", 1).reason == "resource-out-of-scope"
    assert g.check(ActionRequest("c", "agent", "payments.create", "payment/2", 100), "m", 100).reason == "expired"
    g.revoke("m"); assert g.check(ActionRequest("d", "agent", "payments.create", "payment/2", 100), "m", 1).reason == "revoked"

def test_audit_is_tamper_evident():
    g = gate(); g.check(ActionRequest("a", "agent", "payments.create", "payment/1", 1), "m", 1)
    assert g.verify_audit(); g.audit[0]["evidence"] = "changed"; assert not g.verify_audit()
