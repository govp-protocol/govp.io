import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';

import worker from '../worker.js';

const template = await readFile(new URL(
  '../.well-known/govp/revoked.json', import.meta.url,
), 'utf8');

const env = {
  ASSETS: {
    async fetch() {
      return new Response(template, {
        headers: {
          'Content-Length': String(Buffer.byteLength(template)),
          'Content-Type': 'application/json',
          ETag: 'stale-template-etag',
        },
      });
    },
  },
};

test('the public status endpoint stamps every response at request time', async () => {
  const before = Date.now();
  const response = await worker.fetch(
    new Request('https://govp.io/.well-known/govp/revoked.json'),
    env,
  );
  const after = Date.now();
  const payload = await response.json();
  const generatedAt = Date.parse(payload.generated_at);

  assert.equal(response.status, 200);
  assert.ok(generatedAt >= before && generatedAt <= after);
  assert.notEqual(payload.generated_at, JSON.parse(template).generated_at);
  assert.equal(response.headers.get('cache-control'), 'no-store');
  assert.equal(response.headers.get('access-control-allow-origin'), '*');
  assert.equal(response.headers.get('etag'), null);
  assert.equal(response.headers.get('content-length'), null);
});

test('HEAD receives the same live contract without a response body', async () => {
  const response = await worker.fetch(
    new Request('https://govp.io/.well-known/govp/revoked.json', { method: 'HEAD' }),
    env,
  );
  assert.equal(response.status, 200);
  assert.equal(await response.text(), '');
  assert.equal(response.headers.get('cache-control'), 'no-store');
});
