# Migrating from the original example

Version 0.2 is a breaking revision of this research repository, **not a change to AffixIO's SDK**.

| Original | Version 0.2 |
|---|---|
| Floating-point value | Integer minor units, per-action and aggregate caps, explicit currency |
| Client chooses requires_review | Host ToolPolicy and separately signed approval |
| Bare mandate | Authority-signed grant verified against pins |
| In-memory replay set | File-backed SQLite and durable consumption |
| Resource prefix match | Literal segments with boundary-aware scope |
| Hash-only audit | Signed events and checkpoint |
| Caller decides to invoke | execute() owns reservation and dispatch |

Start with a new database. There is no automatic migration of historical unsigned evidence or in-memory state. Do not present old logs as newly authenticated history. Preserve them separately and reconcile outstanding work first.

Review policy, budgets and principals explicitly. Persist keys securely for continuity; the demo intentionally generates new keys each run. Key rotation and audit-signer migration are not implemented.
