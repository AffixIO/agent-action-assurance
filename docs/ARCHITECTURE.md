# Architecture

| Component | Responsibility | Trust |
|---|---|---|
| ActionRequest | Canonical, bounded, integer-valued proposal | Untrusted until checked |
| Mandate | Signed limits and parent reference | Issuer key independently pinned |
| ToolPolicy | Review threshold, version, allowed argument names | Host configuration, never model output |
| approve() | Sign exact reviewed request and its context | Separate reviewer key |
| PolicyGate | Validate, reserve, dispatch and record | Trusted host boundary |
| SQLite | Replay IDs, usage, revocations, immutable mandate IDs, audit | Local trusted filesystem |
| Audit signer | Ed25519 event and checkpoint signatures | Separate from issuer and reviewer |
| SDK adapter | ML-DSA-signed manifest over exported artifacts | Separate pinned SDK signer |

## Transaction boundary

Each decision takes an immediate SQLite transaction. Successful execution checks every ancestor, reserves the operation and review token, increments every ancestor's amount and call usage, and writes a signed decision atomically. Only after commit does the registered tool run.

The result is recorded in a second transaction. An arbitrary external side effect cannot be rolled back by SQLite. A timeout, exception, invalid result encoding or interrupted process must not refund the reservation automatically.

```text
unseen operation → RESERVED → COMPLETED
                         └→ UNCERTAIN
```

A crash or final logging failure can leave RESERVED. Both RESERVED and UNCERTAIN need trusted reconciliation, not a new ID and blind retry. COMPLETED means the callback returned a canonically encodable result and its digest was logged, not independent proof of a remote business fact.

Review and denial create audit entries but reserve neither IDs nor budgets. A reviewed request may be resubmitted unchanged with valid approval. An allowed preview consumes no budget but cannot serve as an execution token.

Revocation's linearisation point is the reservation transaction. Revocation committed beforehand blocks dispatch. A later revocation does not cancel reserved or in-flight actions. Production systems may need cancellation or a fresh downstream check.

## Delegation

The authority signs both root and child grants. Agents do not self-issue grants. A child references an existing parent, has the same principal, tool, audience and currency, and only narrows scope, limits and validity. The parent must allow delegation. Chains are limited to five mandates including the root. Every request checks all ancestor signatures, times and revocations.

Each ancestor is charged, so siblings cannot each spend a root allowance independently. Separate roots have separate budgets; issuing several roots for one business budget needs upstream accounting.

## Evidence

Events contain request and policy digests, chain digests, decision, reason, reservation status, sequence, ledger ID and the previous signed event's digest. Execution events include the original request digest and observed result digest. Raw arguments and private keys are not exported. Revocation targets are hashed.

A verifier needs the audit public key, expected ledger ID and **independently retained signed checkpoint**. Its count and chain head expose mutation, reorder, truncation and substitution relative to that checkpoint. Taking a checkpoint only from the untrusted bundle cannot establish freshness. The demonstration verifies its fresh checkpoint in-process, not through a transparency service.

The optional SDK signs an outer manifest containing the audit export and scenarios. It does not replace Python chain verification or prove the callback's assertion true.

## Deliberately absent

Authentication, OAuth, MCP transport, prompting, network serving, production payments, distributed consensus, automatic retries, key rotation/recovery, audit retention and a human approval interface. AffixIO's SDK is not modified.
