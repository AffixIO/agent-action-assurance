from assurance import ActionRequest, Mandate, PolicyGate

gate = PolicyGate()
gate.add(Mandate.issue("m-1", "operator-1", "agent-1", "invoice.create", "invoice/", 500, 2000))
for request in [
    ActionRequest("op-1", "agent-1", "invoice.create", "invoice/123", 150),
    ActionRequest("op-2", "agent-1", "invoice.create", "invoice/124", 450, requires_review=True),
    ActionRequest("op-3", "agent-1", "invoice.create", "invoice/125", 750),
]:
    decision = gate.check(request, "m-1", now=1000)
    print(request.operation_id, decision.outcome, decision.reason)
print("audit-chain", gate.verify_audit())
