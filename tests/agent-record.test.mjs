import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createHash, createPublicKey } from 'node:crypto';
import { test } from 'node:test';
import { parseRecord, verifyText } from '../govp/assets/govp-engine.js';

const fixture = new URL('../govp/examples/agent-record/', import.meta.url);
const read = (name) => readFile(new URL(name, fixture));

test('agent teaching fixture distinguishes changed statement from changed signature', async () => {
  const record = (await read('agent-record.govp.txt')).toString('utf8');
  const original = await read('agent-record.json');
  const changed = await read('agent-record.tampered.json');
  const changedRecord = (await read('agent-record.tampered.govp.txt')).toString('utf8');
  for (const [name, text, assetBytes, ok, signature, asset] of [
    ['original', record, original, true, true, true],
    ['changed statement', record, changed, false, true, false],
    ['changed record', changedRecord, original, false, false, true],
  ]) {
    const result = await verifyText(text, { assetBytes });
    assert.equal(result.ok, ok, name);
    assert.equal(result.checks.signature, signature, name);
    assert.equal(result.checks.asset, asset, name);
    assert.equal(result.checks.format, true, name);
    assert.equal(result.checks['govp-id'], true, name);
    assert.equal(result.checks.canonical, null, name);
  }
  const statement = JSON.parse(original);
  assert.equal(statement.synthetic, true);
  assert.deepEqual(statement.events.map((event) => event.type),
    ['proposal', 'authorization', 'action', 'proposal', 'refusal']);
  assert.equal(JSON.parse(changed).events.at(-1).decision, 'allow');
  assert.equal(statement.events.at(-1).decision, 'deny');
  assert.equal(createHash('sha256').update(await read('operation-A.txt')).digest('hex'),
    statement.events[2].artifact_sha256);
  const publicKey = createPublicKey(await read('demonstration-public-key.pem'));
  assert.equal(publicKey.export({ format: 'jwk' }).x,
    Buffer.from(parseRecord(record)['public-key'], 'base64').toString('base64url'));
});
