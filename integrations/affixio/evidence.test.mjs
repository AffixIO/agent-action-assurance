import assert from 'node:assert/strict';
import test from 'node:test';
import { createSigner, signAuditExport, verifyBundle } from './evidence.mjs';

const report = { mode: 'simulation', bundle: { schema: 'assurance.audit.v1', events: [] }, scenarios: [] };

test('published SDK signs and independently verifies an evidence manifest', async () => {
  const signer = createSigner();
  const bundle = signAuditExport(report, signer);
  const result = await verifyBundle(bundle, signer.publicKeyB64);
  assert.equal(result.integrityValid, true);
  assert.equal(result.signatureValid, true);
});

test('modified artifact fails manifest integrity', async () => {
  const signer = createSigner();
  const bundle = signAuditExport(report, signer);
  bundle.artifacts[0].data.events.push({ tampered: true });
  assert.equal((await verifyBundle(bundle, signer.publicKeyB64)).integrityValid, false);
});

test('embedded signer is not trusted without a matching external pin', async () => {
  const bundle = signAuditExport(report, createSigner());
  assert.equal((await verifyBundle(bundle, createSigner().publicKeyB64)).signatureValid, false);
});

test('missing trust pin fails closed', async () => {
  const bundle = signAuditExport(report, createSigner());
  const result = await verifyBundle(bundle, undefined);
  assert.equal(result.signatureValid, false);
});

test('changed manifest fails trusted signature verification', async () => {
  const signer = createSigner();
  const bundle = signAuditExport(report, signer);
  bundle.manifest.createdAt = '2000-01-01T00:00:00.000Z';
  assert.equal((await verifyBundle(bundle, signer.publicKeyB64)).signatureValid, false);
});

test('unsigned artifact collection is not accepted as trusted evidence', async () => {
  const signer = createSigner();
  const bundle = signAuditExport(report, signer);
  bundle.signature = null;
  assert.equal((await verifyBundle(bundle, signer.publicKeyB64)).signatureValid, false);
});
