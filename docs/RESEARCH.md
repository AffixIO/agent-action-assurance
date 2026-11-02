# Research and design decisions

Reviewed 2 November 2026. Primary sources only. These references explain design choices; they do not certify this implementation or imply endorsement.

## Why this sector

The target is **enterprise agent automation at the tool-execution boundary**. Authentication alone does not establish whether a proposed action is within a particular delegated task. Current NIST work explicitly discusses agent-specific identities, delegation, task-scoped permissions and auditable activity. This is a concrete integration problem with a demonstrable local test surface.

This choice is a technical-fit hypothesis, not market-size research or evidence that customers will buy it. Demand validation needs workflow owners, security teams and a scoped pilot. We avoid regulated payment settlement and unsupported claims about device or licence detection.

| Primary source | Design consequence | Implementation and boundary |
|---|---|---|
| [NIST: Design Tenets for Agent Identity Management Systems, 27 October 2026](https://www.nist.gov/blogs/cybersecurity-insights/design-tenets-agent-identity-management-systems) | Separate identity, authority, policy and evidence. Bound delegation and lifetimes. | Signed mandates, separate trusted actor input, ancestor checks and reviewer pins. No identity provider or enterprise key lifecycle. |
| [OWASP AI Agent Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html) | Enforce outside the model, before tools execute; validate requests. | Registered tools, argument-key allowlists, snapshots and atomic reservations. Business-specific validation still belongs in a trusted adapter. |
| [OWASP Transaction Authorization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Transaction_Authorization_Cheat_Sheet.html) | Bind review to the operation presented and reject replay. | Reviewer signature binds every request field, policy digest and mandate digest. Host decides when review is required. |
| [MCP security best practices](https://modelcontextprotocol.io/docs/2025-11-25/tutorials/security/security_best_practices) | Avoid confused deputies and trusting credentials for the wrong audience. | Audience binding. No MCP or OAuth implementation claimed; adapters must separately satisfy those protocols. |
| [RFC 9396: OAuth Rich Authorization Requests](https://www.rfc-editor.org/rfc/rfc9396.html) | Specific authorisation details are more expressive than broad scopes. | Tool, resource, value, currency and arguments are bound. This schema is not an RFC 9396 implementation. |
| [RFC 8693: OAuth Token Exchange](https://www.rfc-editor.org/rfc/rfc8693.html) | Distinguish delegation from impersonation. | Principal and acting agent are separate, and parent chain digests remain in evidence. No token-exchange endpoint. |
| [RFC 8785: JSON Canonicalization Scheme](https://www.rfc-editor.org/rfc/rfc8785.html) | Signing needs an unambiguous serialisation contract. | Restricted versioned Python JSON profile below. **Not JCS compatible.** |
| [cryptography: Ed25519](https://cryptography.io/en/latest/hazmat/primitives/asymmetric/ed25519/) | Use a supported signature implementation, not plain hashes as authority. | Ed25519 through cryptography, role-specific keys and external pin maps. |
| [SQLite transactions](https://www.sqlite.org/lang_transaction.html) | Serialise changes before dispatch to avoid concurrent double consumption. | BEGIN IMMEDIATE, unique IDs and shared ancestor usage. Threads and independent processes tested. |
| [AffixIO SDK: independent evidence verification](https://github.com/AffixIO/SDK#independent-evidence-verification) | Use supported public interfaces and precise verification claims. | Published npm 2.0.4, real local signed bundle, explicit signer pin, legacy v1 rejected, positive and adversarial tests. |

## Changes driven by the research

The original example used a client-controlled review flag, plain hash chaining, in-memory replay state and weak one-use enforcement. Version 0.2 replaces these with host policy, signed approvals, signed checkpoints and durable atomic consumption. It adds constrained delegation and records uncertain outcomes without retrying automatically.

The signature boundary includes operation ID, actor, tool, resource, audience, amount, currency and complete arguments. Review cannot transfer to a changed request even if its value stays below budget.

## Canonical data profile

Python's signing domain is `assurance.signature.v1`. Protected fields include schema, algorithm, kind, key ID and payload. JSON keys are sorted using Python string order, separators have no whitespace, and strings use `ensure_ascii=True`. Arrays retain order. Only JSON strings, booleans, null, arrays, string-key objects and integers within ±(2^53−1) are allowed. Floats, duplicate keys at `strict_loads()`, excessive nesting and payloads over 64 KiB are rejected. No Unicode normalisation occurs. Limits apply per signed object, not a whole ledger.

This is narrower than ordinary JSON and is not JCS. Do not guess at cross-language serialisation. The optional SDK bundle has its own documented canonicalisation and signature schema; the two layers do not share signature bytes.

## Questions before a pilot

1. Who owns agent-to-principal mappings and issuer/reviewer pins?
2. How does a reviewer see trusted, unambiguous details of exactly what is signed?
3. Can every action path be forced through the gate without a direct API bypass?
4. How are policy, keys, revocation and clocks distributed across hosts?
5. How are uncertain outcomes reconciled using the destination's native idempotency?
6. Who independently retains checkpoints, monitors gaps and approves recovery?

These require answers from the integrating organisation. This repository does not silently choose production policy on its behalf.
