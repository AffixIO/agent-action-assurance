# Integrating a tool without trusting the model

Start with [the runnable demo](../assurance/demo.py). These Python interfaces belong to this reference project, not the AffixIO SDK.

1. The trusted host provisions separate issuer, reviewer and audit keys. Pin public keys through a trusted channel. Demo keys are disposable, not a storage mechanism.
2. Configure file-backed SQLite and a stable audience. Reopen with the same audit signer and audience after restart; mismatches are rejected.
3. Register a handler and ToolPolicy at trusted startup. Do not expose registration or a direct handler route to agents.
4. Add an authority-signed Mandate. Specify integer minor units, aggregate budget, call limit, scope and expiry. Add parents before children.
5. Validate input as ActionRequest. At a JSON boundary use assurance.crypto.strict_loads() before construction to reject duplicate keys. Preserve operation IDs; new IDs are not a safe retry strategy.
6. Supply authenticated_agent from actual host authentication, not the untrusted request. Call execute(), not a preview followed by a direct call.
7. For REVIEW, show the full request through trusted UX. A separate reviewer calls approve() after inspection. Resubmit unchanged with that approval.
8. Reconcile UNCERTAIN and outstanding RESERVED operations before further business action. Never refund or replace IDs just because a response was lost.
9. Export audit records and retain checkpoints independently. Verify using separately provisioned pins and ledger IDs.

## Adapter responsibilities

argument_keys enforces an exact set of field names, not a complete business schema. Validate values and resolve resources without traversal, SSRF, aliases or hidden amount overrides. Keep all consequential inputs in the signed request. The callback must use that snapshot rather than reread mutable model state.

Handlers and policy are trusted startup configuration. Do not hot-swap them during in-flight requests. Deploy policy versions deliberately; changed policy digests invalidate outstanding approvals.

Children require centrally signed grants and parent delegation permission. This is not a self-delegation protocol.

## Verifying an export

```python
from assurance import verify_audit

valid = verify_audit(
    received_bundle,
    trusted_keys=trusted_audit_key_map,
    expected_ledger_id=known_ledger_id,
    expected_checkpoint=independently_retained_checkpoint,
)
```

These variables are inputs your host must provision. Never obtain trust pins or the expected checkpoint solely from incoming evidence. A valid old checkpoint does not establish current freshness.

## MCP and existing policy systems

An MCP adapter can place this gate behind authenticated transport. This project does not implement MCP or OAuth. Audience binding here does not replace protocol token checks, consent, scopes or client authentication. Existing enterprise policy systems remain authoritative for grant issuance and review requirements, not model-generated policy.
