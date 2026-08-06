import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';

const read = (path) => readFile(new URL(`../${path}`, import.meta.url), 'utf8');

test('the public site exposes reproducible Python and JavaScript installation paths', async () => {
  const [home, quickstart, integration, download, llms] = await Promise.all([
    read('index.html'),
    read('govp/quickstart.html'),
    read('govp/integration.html'),
    read('govp/download.html'),
    read('llms.txt'),
  ]);

  for (const page of [home, quickstart, download, llms]) {
    assert.match(page, /python -m pip install govp==0\.1\.11/);
    assert.match(page, /npm install @govp\/verifier@0\.1\.8/);
  }

  assert.match(quickstart, /import \{ verifyText \} from '@govp\/verifier'/);
  assert.match(integration, /<h2>Python API<\/h2>/);
  assert.match(integration, /<h2>JavaScript API<\/h2>/);
  assert.match(download, /https:\/\/www\.npmjs\.com\/package\/@govp\/verifier\/v\/0\.1\.8/);
  assert.match(download, /https:\/\/github\.com\/govp-protocol\/govp-js\/releases\/tag\/v0\.1\.8/);
  assert.match(download, /https:\/\/pypi\.org\/project\/govp\/0\.1\.11\//);
  assert.match(llms, /Canonical protocol source: https:\/\/github\.com\/govp-protocol\/govp/);
  assert.match(llms, /JavaScript source: https:\/\/github\.com\/govp-protocol\/govp-js/);
});
