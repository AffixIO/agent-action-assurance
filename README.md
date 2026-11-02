# Agent Action Assurance

AI agents are moving from answering questions to calling tools, changing records and initiating workflows. The security gap is not only “is this agent logged in?” It is “is this exact action authorised, within scope, still valid, and independently auditable?”

This small reference implementation places a fail-closed policy gate before an action. It evaluates a scoped mandate against the exact agent, tool, resource, value, expiry, review requirement and one-use operation ID. It records ALLOW, REVIEW and DENY outcomes in a hash-chained audit trail.

## Quickstart

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install pytest
pytest -q
python demo.py
```

Expected demo decisions:

```text
op-1 ALLOW allowed
op-2 REVIEW human-review-required
op-3 DENY value-out-of-scope
audit-chain True
```

## What it demonstrates

- Task-scoped mandates instead of standing permission
- Exact tool and resource binding
- Value limits
- Human-review gates
- Expiry and explicit revocation
- One-use replay protection
- Tamper-evident audit evidence
- No external action is executed when the result is REVIEW or DENY

## Research basis

The design follows the direction of current NIST agent-identity work: agents need distinct identity and credential lifecycles, task-level authorisation, non-repudiation, and logs protected from modification by the agent being observed. See the official sources linked below.

## AffixIO integration boundary

This is a local simulation and does not invent AffixIO SDK methods. A production adapter should use documented AffixIO proof and verification interfaces, bind evidence to the canonical action arguments, pin trusted signers, and keep private keys outside the application and repository. The gate must sit before the protected tool invocation, not after it.

## Limitations

The example does not provide key management, network transport, OAuth, a database, a production cryptographic signature scheme, sub-agent delegation, or a real payment or tool connector. Those are deliberate follow-on engineering tasks requiring threat modelling and security review.

## Status

Research example. Simulated decisions only. No external system is called and no real action is performed.

## Sources

- [NIST: Design Tenets for Agent Identity Management Systems](https://www.nist.gov/blogs/cybersecurity-insights/design-tenets-agent-identity-management-systems)
- [NIST: Summary of comments on agent identity and authorization](https://pages.nist.gov/nccoe-ai-identity/summary-of-comments.html)
- [NIST: Agent identity and authorization concept paper](https://www.nccoe.nist.gov/sites/default/files/2026-02/accelerating-the-adoption-of-software-and-ai-agent-identity-and-authorization-concept-paper.pdf)

## Contributing

Keep examples fictional, add tests for every policy change, and never commit credentials, private keys, personal data or production payloads.

## License

MIT
