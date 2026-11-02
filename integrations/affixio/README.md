# Published AffixIO SDK integration

This example uses **affixio@2.0.4 from npm**, not a replacement SDK. The lockfile fixes dependency versions and registry integrity hashes.

Requirements: Node 22.13+, pnpm 11.25.0 and the Python project installed in the active environment. From repository root:

```sh
cd integrations/affixio
pnpm install --frozen-lockfile --ignore-scripts
pnpm test
agent-assurance --json | node evidence.mjs
```

If needed, install pnpm with `npm install --global pnpm@11.25.0`. The SDK tree contains dependencies for other features; this demo uses local signing/evidence utilities only. Installation downloads dependencies. The demo does not call a hosted API or payment service.

## Supported interfaces

- createLocalSigningKeyPair() from affixio returns secret_key_b64 and public_key_b64.
- createEvidenceBundle() from affixio/workflows takes signing.secretKeyB64, publicKeyB64 and hmacSecret. The adapter explicitly maps those fields.
- verifyEvidenceBundle() uses a separately supplied trustedPublicKeys list and rejectLegacyV1: true.

These interfaces are [documented publicly](https://github.com/AffixIO/SDK#independent-evidence-verification) and checked against installed 2.0.4. SDK interfaces remain unchanged.

## What verification means

The SDK signs the manifest with its HMAC-SHA256 + ML-DSA-65 local-signature envelope. Independent verification checks artifact digests and the pinned ML-DSA signature. It does **not** check the secret HMAC, generate a ZK proof or contact a hosted service. No API key is required for this local path.

The Python demo verifies its own chain before export. signAuditExport() only checks export shape; it does not verify inner Ed25519 signatures. A valid outer envelope can wrap false or invalid source data. Third-party exports need independent inner verification with trusted audit keys and checkpoints before being treated as decision evidence.

Demo keys and HMAC secrets stay in memory and are never printed. The demo pin comes from its own trusted generation step. Deployments need independent provisioning and key lifecycle management.

Tests cover intact evidence, altered artifacts/manifests, unsigned evidence, wrong pins and missing pins. Python enforcement is tested separately, not inferred from envelope success.
