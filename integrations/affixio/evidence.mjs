import { randomBytes } from 'node:crypto';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createLocalSigningKeyPair } from 'affixio';
import { createEvidenceBundle, verifyEvidenceBundle } from 'affixio/workflows';

// These are public, documented SDK interfaces. No hosted API or entitlement calls.
export function createSigner() {
  const keys = createLocalSigningKeyPair();
  return { secretKeyB64: keys.secret_key_b64, publicKeyB64: keys.public_key_b64,
    hmacSecret: randomBytes(32).toString('hex') };
}

export function signAuditExport(report, signing) {
  if (report?.mode !== 'simulation' || report?.bundle?.schema !== 'assurance.audit.v1') {
    throw new TypeError('Expected a synthetic assurance demo export');
  }
  return createEvidenceBundle([
    { name: 'assurance-audit', data: report.bundle },
    { name: 'demo-results', data: { mode: report.mode, scenarios: report.scenarios } },
  ], { signing });
}

export async function verifyBundle(bundle, pinnedPublicKey) {
  return verifyEvidenceBundle(bundle, {
    trustedPublicKeys: [pinnedPublicKey], rejectLegacyV1: true,
  });
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const chunks = [];
  for await (const chunk of process.stdin) chunks.push(chunk);
  const report = JSON.parse(Buffer.concat(chunks).toString('utf8'));
  const signing = createSigner();
  // Pin is taken from trusted local configuration, never from the supplied bundle.
  const pin = signing.publicKeyB64;
  const bundle = signAuditExport(report, signing);
  const result = await verifyBundle(bundle, pin);
  if (!result.integrityValid || !result.signatureValid) throw new Error(JSON.stringify(result));
  console.log(JSON.stringify({ mode: 'simulation', sdk: 'affixio@2.0.4',
    signature: 'ML-DSA-65', result, verifies: 'artifact integrity and trusted manifest signature' }, null, 2));
}
