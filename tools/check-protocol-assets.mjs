import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';

const manifest = JSON.parse(await readFile(new URL('../PROTOCOL-SOURCE.json', import.meta.url), 'utf8'));
assert.equal(manifest.format, 'govp-protocol-source-v1');
assert.equal(manifest.version, '0.1.10');
assert.match(manifest.commit, /^[0-9a-f]{40}$/);
assert.match(manifest.tree, /^[0-9a-f]{40}$/);
assert.match(manifest.source_zip_sha256, /^[0-9a-f]{64}$/);

for (const [relativePath, expected] of Object.entries(manifest.artifacts)) {
  const bytes = await readFile(new URL(`../${relativePath}`, import.meta.url));
  const actual = createHash('sha256').update(bytes).digest('hex');
  assert.equal(actual, expected, `${relativePath} differs from the approved protocol source`);
}

console.log(`Verified ${Object.keys(manifest.artifacts).length} normative GOVP 0.1.10 artifacts.`);
