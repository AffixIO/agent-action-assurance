# Threat model and deployment checklist

## Intended attacker

An untrusted agent may propose arbitrary supported data, replay requests, edit fields, reuse approval tokens, seek broader delegation or submit simultaneous operations. It may cause a tool to time out. It cannot legitimately administer the host, sign as issuer/reviewer, modify the database, change the clock or replace callbacks.

| Threat | Tested control | Remaining boundary |
|---|---|---|
| Change reviewed amount, resource, currency or arguments | Full request digest in approval | Adapter must pass exactly those inputs to the tool |
| Disable review | Host-owned policy | Protected policy administration |
| Forge authority or substitute public keys | Verification against configured pins | A compromised pinned signer remains compromised |
| Broaden delegation | Ancestor attenuation | Authority centrally approves every grant |
| Spend root allowance through siblings | Shared ancestor counters | Separate roots have separate budgets |
| Replay across workers/restarts | Atomic SQLite reservation and unique IDs | Workers must share the supported store and keys |
| New operation ID on a one-use mandate | Durable mandate call count | Business-level deduplication still needs stable IDs |
| Race revocation | Check within reservation transaction | No cancellation after reservation |
| Rewrite/truncate exported logs | Signatures plus independently retained checkpoint | Host controlling signer and checkpoints can forge history |
| Crash after dispatch | Reservation stays consumed | Reconciliation required; no exactly-once promise |
| Sensitive log details | Raw arguments omitted | IDs and guessable hashes still leak information |

## Non-guarantees

This does not detect prompt injection or determine whether an instruction is wise. It enforces trusted configuration. It cannot prevent bypass if an agent has the underlying tool credentials. It does not make inaccurate sources truthful, prove a human actually reviewed a request, or establish legal non-repudiation.

Ed25519 is not post-quantum. The optional ML-DSA-65 envelope protects a separate manifest; it does not upgrade the issuer, reviewer or Python audit signatures. Neither layer is a zero-knowledge proof of the decision.

SQLite is not immutable or authenticated as a whole. A malicious administrator, disk rollback or stale backup restoration can reset replay, budget and revocation state. Independently retained checkpoints may expose inconsistent history but are not an execution-state anti-rollback mechanism. Do not use an unsupported network filesystem.

## Before production

- Authenticate outside the model. Supply authenticated_agent from a trusted session.
- Isolate tool credentials, signer keys, pins and database from agents. Use managed keys, protected backups and independently secured recovery.
- Define key rotation, role separation, revocation distribution and compromise-time handling. These lifecycle mechanisms are not implemented.
- Add tool-specific value schemas and semantic checks. Current argument policy checks **names**, not semantics or URLs.
- Derive amount, currency and resource from the same trusted object dispatched to the tool.
- Use a reliable host clock; monitor drift and rollback. The demo uses synthetic time.
- Build review UX showing exactly what is signed. Protect approve(), add(), revoke() and register_tool() as privileged interfaces.
- Use destination idempotency and reconciliation. Preserve operation identity through retries and restores.
- Rate-limit requests and bound audit growth. Every preview and denial adds an event; no built-in retention or denial-of-service protection exists.
- Retain checkpoints independently; define access, retention, monitoring and recovery. Verify restored state before execution resumes.
- Threat-model each adapter, test its real storage topology and obtain independent security assessment.

All shipped demonstrations remain fictional and local. Real connectors are separate integrations, not enabled by a flag.
