# Agent Action Assurance

[![Tests](https://github.com/AffixIO/agent-action-assurance/actions/workflows/test.yml/badge.svg)](https://github.com/AffixIO/agent-action-assurance/actions/workflows/test.yml)
![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)
![License MIT](https://img.shields.io/badge/license-MIT-green)

**Put a verifiable boundary between an agent proposing an action and a tool performing it.**

A working research example for teams connecting AI agents to business systems. Signed mandates define what an agent may do. A host-controlled gate checks the exact request, asks for approval where required, reserves shared limits, then calls the tool. Signed evidence records the decision and the observed outcome.

The invoices are fictional. The cryptographic signatures, persisted state and adversarial tests are real. No LLM account, API key, payment provider or external service is needed to run the demo.

**Status: v0.2 research prototype, not a production security product or compliance certification.** This version changes the original Python example interfaces. Read [migration notes](docs/MIGRATION.md) before updating an existing integration.

## Five-minute quickstart

Python 3.10 or later, with Git and pip:

```sh
git clone https://github.com/AffixIO/agent-action-assurance.git
cd agent-action-assurance
python3 -m venv .venv
. .venv/bin/activate
python -m pip install '.[dev]'
python -m pytest -q
agent-assurance
```

On Windows, activate with `.venv\Scripts\Activate.ps1`. If `python3` is unavailable, use your Python 3.10+ executable. There is no package-registry release to install by name: the command above installs this checkout.

Expected demo:

```text
GBP 150                        ALLOW  allowed
GBP 450 needs review           REVIEW human-review-required
GBP 750 exceeds cap            DENY   value-out-of-scope
Changed approved arguments     DENY   approval-binding-mismatch
Approved GBP 450               ALLOW  allowed
Replay                         DENY   replay
Delegated GBP 50                ALLOW  allowed
Parent revoked                 DENY   revoked
Protected calls: 3 | Audit verified: True
```

The example permits **£500 per action**, with a separate **£1,000 cumulative mandate budget**. Review is required above £300. Amounts are integer pence, never floating-point pounds. Each run uses a temporary database and fresh demo keys; actual restart tests reuse their database and keys.

## Three decisions, one execution boundary

| Decision | Meaning | Does the tool run? |
|---|---|---|
| ALLOW | The request is currently authorised; execution atomically reserves limits before dispatch. | Yes, through `execute()` only. |
| REVIEW | Host policy requires a separate reviewer to approve this exact request. | No. |
| DENY | Identity, signature, scope, time, budget, revocation or replay checks failed. | No. |

`check()` is a preview, **not an executable permit**. `execute()` rechecks everything. An approved decision is also not a claim that the tool succeeded: execution is recorded separately as `COMPLETED`, `UNCERTAIN`, or an outstanding `RESERVED` operation.

```text
Agent proposes request
        ↓
Trusted host supplies authenticated identity
        ↓
Verify mandate chain + review token + current policy
        ↓
SQLite transaction: reserve operation, approval, ancestor budgets and call limits
        ↓
Registered tool receives a snapshot of the authorised request
        ↓
Signed outcome → chained audit → independently retained checkpoint
```

## What is implemented

- **Signed, audience-bound mandates.** Agent, principal, tool, literal resource scope, currency, expiry, per-action cap, aggregate budget and call count are covered by the signature.
- **Host-owned review policy.** The agent cannot turn off review with a request flag. Approval binds the full request, mandate and policy version.
- **Constrained delegation.** Child grants cannot expand parent authority. Every ancestor's budget and call allowance is shared across descendants. Parent revocation invalidates its descendants on the next check.
- **Persistent replay protection.** Duplicate operation IDs and consumed approvals are rejected across threads, processes and restarts using one SQLite database.
- **Fail-closed execution.** Unknown tools, invalid evidence and unavailable enforcement storage cannot trigger a new dispatch. An uncertain effect is not automatically retried.
- **Signed audit evidence.** Ed25519-signed, hash-linked events plus a signed checkpoint support verification with an independently pinned key and retained checkpoint.
- **Working AffixIO SDK adapter.** The published `affixio@2.0.4` package signs an evidence manifest using its local ML-DSA-65 functionality and verifies it against an explicit signer pin.

## Add AffixIO evidence verification

The Python gate works independently. To wrap its synthetic audit export with the **actual published SDK**, install Node.js 22.13+ and pnpm 11.25.0, then, from the activated Python environment:

```sh
cd integrations/affixio
pnpm install --frozen-lockfile --ignore-scripts
pnpm test
agent-assurance --json | node evidence.mjs
```

The final output includes `integrityValid: true` and `signatureValid: true`. No API key is needed for these local SDK utilities. This does not imply that hosted AffixIO APIs are unauthenticated or free.

The adapter uses documented `createLocalSigningKeyPair`, `createEvidenceBundle` and `verifyEvidenceBundle` interfaces. It explicitly maps the key pair's snake-case fields to the signing options' camel-case fields. It never trusts a key merely because it is embedded in evidence.

**Know what you verified:** the SDK checks the outer artifact integrity and trusted manifest signature. It does not validate the inner Python event chain, establish source truth, prove that a real action happened, or run a zero-knowledge proof. Python `verify_audit()` checks the inner chain separately. The core uses Ed25519; adding an ML-DSA envelope does not make the whole system post-quantum secure. [Integration details](integrations/affixio/README.md).

## Connect your own agent

Use the same boundary regardless of which model proposes the action. Keep the model outside the authority, review and tool-registration paths. Do not hand it a signing key or a direct tool bypass.

Start with the [complete runnable demo](assurance/demo.py), then read [the integration guide](docs/INTEGRATION.md). `authenticated_agent` must come from trusted host authentication, not a field supplied by the model. The demo uses a fixed synthetic identity; this repository does not implement authentication.

The example is useful for evaluating internal agent workflows such as invoice preparation, scoped record changes and controlled automation. It is not an OAuth server, a payment processor, an MCP transport, a replacement for your organisation's policy system or evidence of a partnership with any vendor.

## Research and security boundaries

The design is informed by the October 2026 [NIST agent identity tenets](https://www.nist.gov/blogs/cybersecurity-insights/design-tenets-agent-identity-management-systems), the [OWASP agent security guidance](https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html), transaction-authorisation guidance, and MCP security guidance. [Research decisions and source links](docs/RESEARCH.md) distinguish implemented controls from future work.

Before adapting it, read the [threat model](docs/THREAT-MODEL.md). In particular:

- A signature attests to what its trusted signer signed, not that the statement is true.
- SQLite and the signing keys must be outside the agent's control. This is not a tamper-proof database or a distributed exactly-once executor.
- A separately retained checkpoint detects truncated or substituted history relative to that checkpoint. This demo has no independent transparency service or trusted timestamp authority.
- Real deployments need strong authentication, managed keys and recovery, tool-specific validation, operational monitoring, retention controls and independent review.
- Audit exports omit raw tool arguments but include operation IDs and hashes. Hashes can reveal guessable information; this is not a privacy or anonymisation guarantee.

## Development

```sh
python -m pip install -e '.[dev]'
python -m pytest -q
ruff check .
ruff format --check .
python -m build
```

CI tests Python 3.10, 3.12 and 3.13, builds and smoke-tests the installed wheel, and exercises the published AffixIO SDK plus the end-to-end demo. The suite includes forged signatures, changed approval fields, policy changes, time boundaries, ancestor revocation, sibling budgets, concurrent processes, crashes, storage failure and audit tampering.

See [validation results](docs/VALIDATION.md), [architecture](docs/ARCHITECTURE.md), [security reporting](SECURITY.md), [contributing](CONTRIBUTING.md) and [changelog](CHANGELOG.md). Contributions should bring a reproducible failure case or a tested integration, not unverifiable security claims.

MIT licensed. Built by AffixIO. No production systems are contacted by the demonstration.
