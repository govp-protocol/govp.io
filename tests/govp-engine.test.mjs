import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';

import {
  evaluateStatus,
  loadJsonRecord,
  normalizeCanonical,
  normalizeFieldName,
  parseRecord,
  parseStatus,
  signingInput,
  verifyFields,
  verifyText,
} from '../govp/assets/govp-engine.js';
import { verifySource } from '../govp/assets/verify-source.js';

const textVectors = JSON.parse(await readFile(new URL(
  '../govp/conformance/vectors.json', import.meta.url,
), 'utf8'));
const jsonVectors = JSON.parse(await readFile(new URL(
  '../govp/conformance/json-vectors.json', import.meta.url,
), 'utf8'));
const statusVectors = JSON.parse(await readFile(new URL(
  '../govp/conformance/status-vectors.json', import.meta.url,
), 'utf8'));
const STATUS_NOW = Date.parse('2026-08-05T22:09:00Z');

async function sha256Hex(bytes) {
  const digest = await crypto.subtle.digest('SHA-256', bytes);
  return Array.from(new Uint8Array(digest))
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('');
}

test('all GOVP-1 text conformance vectors match the approved reference', async () => {
  assert.equal(textVectors.domain, 'GOVP::record.v1\\0');
  for (const vector of textVectors.vectors) {
    const fields = parseRecord(vector.record);
    const result = await verifyFields(fields);
    const expected = vector.expected;
    assert.equal(fields['govp-id'], expected.govp_id, `${vector.name}: id`);
    assert.equal(result.checks.format, expected.format_ok, `${vector.name}: format`);
    assert.equal(result.checks.signature, expected.signature_ok, `${vector.name}: signature`);
    assert.equal(result.checks['govp-id'], expected.govpid_ok, `${vector.name}: govp-id`);
    assert.equal(result.ok, expected.core_valid, `${vector.name}: core`);
    assert.equal(
      await sha256Hex(signingInput(fields)),
      expected.signing_input_sha256,
      `${vector.name}: signing input`,
    );
  }
});

test('all JSON conformance vectors load or reject identically', async () => {
  for (const vector of jsonVectors.vectors) {
    if (vector.expected.load_ok) {
      const loaded = loadJsonRecord(vector.payload);
      const result = await verifyFields(loaded.fields, { bundle: loaded.bundle });
      assert.equal(result.ok, vector.expected.core_valid, vector.name);
    } else {
      assert.throws(() => loadJsonRecord(vector.payload), new RegExp(vector.expected.error), vector.name);
    }
  }
});

test('status vectors, freshness and normalized aliases fail closed', async () => {
  const record = await readFile(new URL('../.well-known/govp.txt', import.meta.url), 'utf8');
  const statusText = await readFile(new URL('../.well-known/govp/revoked.json', import.meta.url), 'utf8');
  const fields = parseRecord(record);
  const status = parseStatus(statusText);

  for (const vector of statusVectors.vectors) {
    const result = await evaluateStatus(fields, vector.status);
    assert.equal(result.checks['status-format'], vector.expected.schema_valid, vector.name);
  }

  const options = {
    recordFetchedUrl: fields.canonical,
    fetchedUrl: status.canonical,
    now: STATUS_NOW,
  };
  const stale = await evaluateStatus(fields, {
    ...status,
    generated_at: '2026-08-05T22:03:59Z',
  }, options);
  assert.equal(stale.snapshotValid, true);
  assert.equal(stale.snapshotTrusted, true);
  assert.equal(stale.checks['status-fresh'], false);
  assert.equal(stale.currentlyTrusted, false);

  const future = await evaluateStatus(fields, {
    ...status,
    generated_at: '2026-08-05T22:10:01Z',
  }, options);
  assert.equal(future.checks['status-fresh'], false);
  assert.equal(future.currentlyTrusted, false);

  const revokedStatus = {
    ...status,
    generated_at: '2026-08-05T22:09:00Z',
    revoked_records: [{
      govp_id: fields['govp-id'],
      revoked_at: '2026-08-05T22:08:00Z',
      reason: 'withdrawn',
    }],
  };
  const aliased = { ...fields, 'Govp-ID': fields['govp-id'] };
  delete aliased['govp-id'];
  const revoked = await evaluateStatus(aliased, revokedStatus, options);
  assert.equal(revoked.checks.core, true);
  assert.equal(revoked.checks['record-not-revoked'], false);
  assert.equal(revoked.currentlyTrusted, false);
});

test('strict Ed25519 encodings reject identity points and non-canonical scalars', async () => {
  const valid = textVectors.vectors.find((vector) => vector.expected.core_valid);
  const fields = parseRecord(valid.record);
  const identity = Buffer.concat([Buffer.from([1]), Buffer.alloc(31)]);
  const signature = Buffer.from(fields.signature, 'base64');
  const order = 2n ** 252n + 27742317777372353535851937790883648493n;
  const highS = Buffer.alloc(32);
  let scalar = order;
  for (let index = 0; index < 32; index += 1) {
    highS[index] = Number(scalar & 0xffn);
    scalar >>= 8n;
  }

  assert.equal((await verifyFields({
    ...fields,
    'public-key': identity.toString('base64'),
  })).checks.signature, false);
  assert.equal((await verifyFields({
    ...fields,
    signature: Buffer.concat([identity, signature.subarray(32)]).toString('base64'),
  })).checks.signature, false);
  assert.equal((await verifyFields({
    ...fields,
    signature: Buffer.concat([signature.subarray(0, 32), highS]).toString('base64'),
  })).checks.signature, false);
});

test('the browser controller verifies text records and JSON bundles', async () => {
  assert.equal((await verifySource(textVectors.vectors[0].record)).ok, true);
  const validBundle = jsonVectors.vectors.find((vector) => vector.expected.core_valid);
  assert.ok(validBundle, 'a core-valid JSON bundle fixture is required');
  assert.equal((await verifySource(JSON.stringify(validBundle.payload))).ok, true);
});

test('the approved synthetic example verifies with its exact asset', async () => {
  const record = await readFile(new URL('../govp/examples/manufacturing-record.govp.txt', import.meta.url), 'utf8');
  const asset = new Uint8Array(await readFile(new URL(
    '../govp/examples/manufacturing-record.statement.txt', import.meta.url,
  )));
  assert.equal((await verifyText(record, { assetBytes: asset })).ok, true);
  const tampered = new Uint8Array([...asset, 0]);
  assert.equal((await verifyText(record, { assetBytes: tampered })).ok, false);
});

test('govp.io publishes a valid canonical identity and discovery record', async () => {
  const record = await readFile(new URL('../.well-known/govp.txt', import.meta.url), 'utf8');
  const asset = new Uint8Array(await readFile(new URL(
    '../.well-known/govp/govp.io-stewardship.txt', import.meta.url,
  )));
  const result = await verifyText(record, {
    assetBytes: asset,
    fetchedUrl: 'https://govp.io/.well-known/govp.txt',
  });
  assert.equal(result.ok, true);
  assert.equal(result.checks.canonical, true);
  assert.equal(result.checks.asset, true);

  const index = JSON.parse(await readFile(new URL(
    '../.well-known/govp/index.json', import.meta.url,
  ), 'utf8'));
  assert.equal(index.format, 'GOVP-DISCOVERY-1');
  assert.equal(index.canonical, 'https://govp.io/.well-known/govp.txt');
  assert.equal(index.status, 'https://govp.io/.well-known/govp/revoked.json');
  assert.equal(index.records.length, 2);
  assert.equal(index.records[0].govp_id, result.fields['govp-id']);
  assert.equal(index.records[0].asset_sha256, result.fields['asset-sha256']);

  const publishedCopy = await readFile(new URL(
    `../.well-known/govp/${result.fields['govp-id']}.govp`, import.meta.url,
  ), 'utf8');
  const publishedResult = await verifyText(publishedCopy, {
    assetBytes: asset,
    fetchedUrl: index.records[0].record,
  });
  assert.equal(publishedResult.ok, true);
  assert.equal(publishedResult.fields['govp-id'], result.fields['govp-id']);
  assert.notEqual(publishedCopy, record);

  const releaseEntry = index.records.find((entry) => (
    entry.asset === 'https://github.com/govp-protocol/govp/releases/download/v0.1.11/GOVP-0.1.11-source.zip'
  ));
  assert.ok(releaseEntry, 'the current 0.1.11 source release must be discoverable');
  assert.equal(
    releaseEntry.asset_sha256,
    '89d45080fbdff7cca7efbaf1027d205ed14295c1d33e6a35be4722bb88c0296a',
  );
  const releaseRecord = await readFile(new URL(
    `../.well-known/govp/${releaseEntry.govp_id}.govp`, import.meta.url,
  ), 'utf8');
  const releaseResult = await verifyText(releaseRecord, {
    fetchedUrl: releaseEntry.record,
  });
  assert.equal(releaseResult.ok, true);
  assert.equal(releaseResult.checks.signature, true);
  assert.equal(releaseResult.checks.canonical, true);
  assert.equal(releaseResult.fields['asset-sha256'], releaseEntry.asset_sha256);
  assert.equal(releaseResult.fields['govp-id'], releaseEntry.govp_id);

  const status = JSON.parse(await readFile(new URL(
    '../.well-known/govp/revoked.json', import.meta.url,
  ), 'utf8'));
  assert.equal(status.format, 'GOVP-STATUS-1');
  assert.equal(status.canonical, index.status);
  assert.equal(status.authority, 'https-origin');
  assert.deepEqual(status.revoked_records, []);
  assert.equal(status.keys.length, 2);
  const expectedKeys = new Set([
    result.fields['public-key'],
    releaseResult.fields['public-key'],
  ]);
  for (const key of status.keys) {
    assert.equal(expectedKeys.delete(key.public_key), true);
    assert.equal(key.state, 'active');
    assert.equal(
      key.key_id,
      `sha256:${await sha256Hex(Buffer.from(key.public_key, 'base64'))}`,
    );
  }
  assert.equal(expectedKeys.size, 0);
});

test('canonical normalization preserves scheme, www, path and explicit port boundaries', () => {
  const canonical = 'https://www.example.test:443/path/';
  assert.equal(normalizeCanonical(canonical), canonical);
  assert.notEqual(normalizeCanonical('http://www.example.test:443/path/'), canonical);
  assert.notEqual(normalizeCanonical('https://example.test:443/path/'), canonical);
  assert.notEqual(normalizeCanonical('https://www.example.test:443/path'), canonical);
  assert.equal(normalizeCanonical('https://EXAMPLE.test:8443/a'), 'https://example.test:8443/a');
});

test('format checks enforce RFC 3986 ASCII URLs and stable RFC 3339 fractions', async () => {
  const base = parseRecord(textVectors.vectors[0].record);
  for (const fraction of ['1', '12', '123', '1234', '12345', '123456', '1234567', '123456789']) {
    const fields = { ...base, 'generated-at': `2026-01-01T00:00:00.${fraction}Z` };
    assert.equal((await verifyFields(fields)).checks.format, true, fraction);
  }
  assert.equal((await verifyFields({ ...base, 'generated-at': '2016-12-31T23:59:60Z' })).checks.format, true);
  assert.equal((await verifyFields({ ...base, 'generated-at': '2026-01-01T00:00:00.Z' })).checks.format, false);
  assert.equal((await verifyFields({ ...base, evidence: 'https://example.test/évidence' })).checks.format, false);
  assert.equal((await verifyFields({ ...base, evidence: 'https://example.test/%C3%A9vidence' })).checks.format, true);
  assert.equal((await verifyFields({ ...base, evidence: 'https://example.test/%zz' })).checks.format, false);
});

test('signed extensions, exact trimming and advisories match GOVP 0.1.11', async () => {
  assert.equal(normalizeFieldName(' X-Évidence\u00a0'), 'x-Évidence');
  assert.match(new TextDecoder().decode(signingInput({ version: 'GOVP-1', __extension: 'signed' })), /__extension: signed/);

  const base = parseRecord(textVectors.vectors[0].record);
  const control = await verifyFields({ ...base, publisher: 'Example\u0001 Organization' });
  assert.deepEqual(control.warnings, ['signed-non-printable-text']);
  const nonHttp = await verifyFields({ ...base, evidence: 'data:text/plain,example' });
  assert.equal(nonHttp.checks.format, true);
  assert.deepEqual(nonHttp.warnings, ['non-http-evidence-scheme']);
});

test('lone surrogates and bare carriage returns cannot become signing bytes', async () => {
  const base = parseRecord(textVectors.vectors[0].record);
  const surrogate = await verifyFields({ ...base, 'asset-id': '\ud800' });
  assert.equal(surrogate.checks.format, false);
  assert.equal(surrogate.checks.signature, false);
  assert.throws(() => signingInput({ version: 'GOVP-1', 'asset-id': '\ud800' }), /Unicode scalar/);

  const parsed = parseRecord(textVectors.vectors[0].record.replace(
    'Publisher: winery.example\n',
    'Publisher: winery.example\r \n',
  ));
  assert.equal((await verifyFields(parsed)).checks.format, false);
});
