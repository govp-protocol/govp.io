import assert from 'node:assert/strict';
import { readdir, readFile, stat } from 'node:fs/promises';
import { dirname, extname, join, normalize, relative, resolve } from 'node:path';

const root = resolve(new URL('..', import.meta.url).pathname);
const ignored = new Set(['.git', '.github', '.wrangler', 'node_modules', 'dist']);
const redirects = new Set([
  '/govp/',
  '/govp/index.html',
  '/govp.html',
  '/govp/adopt.html',
  '/govp/api.html',
  '/govp/badge.html',
  '/govp/compare.html',
  '/govp/evidence.html',
  '/govp/govp-verificador-standalone.html',
  '/govp/network.html',
  '/govp/platforms.html',
  '/govp/playground.html',
  '/govp/technology.html',
  '/govp/verify-offline.html',
]);

async function walk(directory) {
  const output = [];
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    if (ignored.has(entry.name)) continue;
    const path = join(directory, entry.name);
    if (entry.isDirectory()) output.push(...await walk(path));
    else output.push(path);
  }
  return output;
}

async function exists(path) {
  try {
    return (await stat(path)).isFile();
  } catch {
    return false;
  }
}

function localTarget(source, href) {
  const withoutFragment = href.split('#', 1)[0].split('?', 1)[0];
  if (!withoutFragment || /^(?:[a-z]+:|\/\/)/i.test(withoutFragment)) return null;
  const absoluteUrlPath = withoutFragment.startsWith('/')
    ? normalize(withoutFragment)
    : normalize(`/${relative(root, resolve(dirname(source), withoutFragment))}`);
  return absoluteUrlPath.replaceAll('\\', '/');
}

const files = await walk(root);
const textExtensions = new Set(['.css', '.html', '.js', '.json', '.md', '.sh', '.txt', '.xml', '.yaml', '.yml']);
const banned = [
  /\b[A-Z0-9._%+-]+@(?:gmail|hotmail|outlook)\.com\b/i,
  /(?:^|["'\s])\/Users\//,
  /[A-Z]:\\Users\\/i,
  /BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY/,
];

let checkedLinks = 0;
for (const file of files) {
  if (!textExtensions.has(extname(file)) && !['LICENSE', 'NOTICE'].includes(file.split('/').pop())) continue;
  const text = await readFile(file, 'utf8');
  for (const pattern of banned) assert.doesNotMatch(text, pattern, `${relative(root, file)} contains ${pattern}`);
  if (extname(file) === '.json') JSON.parse(text);
  if (extname(file) !== '.html') continue;

  assert.match(text, /<html[^>]+lang="[^"]+"/i, `${relative(root, file)} has no language`);
  assert.match(text, /<title>[^<]+<\/title>/i, `${relative(root, file)} has no title`);
  assert.match(text, /<meta name="description" content="[^"]+">/i, `${relative(root, file)} has no description`);
  assert.match(text, /<meta property="og:image" content="https:\/\/govp\.io\/govp\/assets\/govp-social-preview\.png">/i, `${relative(root, file)} has no canonical social preview`);
  assert.match(text, /<meta name="twitter:card" content="summary_large_image">/i, `${relative(root, file)} has no large social card`);
  assert.match(text, /<main\b/i, `${relative(root, file)} has no main landmark`);
  assert.equal((text.match(/<h1\b/gi) || []).length, 1, `${relative(root, file)} must have exactly one h1`);
  for (const match of text.matchAll(/<img\b[^>]*>/gi)) {
    assert.match(match[0], /\salt="[^"]*"/i, `${relative(root, file)} has an image without alt text`);
  }
  const ids = Array.from(text.matchAll(/\sid="([^"]+)"/g), (match) => match[1]);
  assert.equal(new Set(ids).size, ids.length, `${relative(root, file)} has duplicate ids`);
  for (const match of text.matchAll(/\s(?:href|src)="([^"]+)"/g)) {
    const target = localTarget(file, match[1]);
    if (target === null || target.startsWith('/downloads/')) continue;
    checkedLinks += 1;
    if (redirects.has(target)) continue;
    const direct = resolve(root, `.${target}`);
    const candidates = target.endsWith('/')
      ? [join(direct, 'index.html')]
      : extname(target)
        ? [direct]
        : [direct, `${direct}.html`, join(direct, 'index.html')];
    assert.equal(
      (await Promise.all(candidates.map(exists))).some(Boolean),
      true,
      `${relative(root, file)} links to missing ${match[1]}`,
    );
  }
  for (const match of text.matchAll(/<a\b[^>]*target="_blank"[^>]*>/gi)) {
    assert.match(match[0], /rel="[^"]*noopener[^"]*"/i, `${relative(root, file)} has an unsafe target=_blank`);
  }
}

const socialPreview = await readFile(join(root, 'govp/assets/govp-social-preview.png'));
assert.equal(socialPreview.subarray(1, 4).toString('ascii'), 'PNG', 'social preview is not a PNG');
assert.equal(socialPreview.readUInt32BE(16), 1280, 'social preview width must be 1280');
assert.equal(socialPreview.readUInt32BE(20), 640, 'social preview height must be 640');
assert.ok(socialPreview.byteLength < 1_000_000, 'social preview must remain below 1 MB');

console.log(`Checked ${files.length} files and ${checkedLinks} internal asset links.`);
