/**
 * govp.io — static protocol documentation and immutable release downloads.
 *
 * No user account, record or verification result is stored by this Worker.
 */

const SECURITY_HEADERS = {
  'Content-Security-Policy': [
    "default-src 'self'",
    "base-uri 'self'",
    "connect-src 'self'",
    "font-src 'self' data:",
    "form-action 'self' mailto:",
    "frame-ancestors 'none'",
    "img-src 'self' data:",
    "object-src 'none'",
    "script-src 'self'",
    "style-src 'self'",
  ].join('; '),
  'Cross-Origin-Opener-Policy': 'same-origin',
  'Permissions-Policy': 'camera=(), geolocation=(), microphone=(), payment=(), usb=()',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
};

const TEXT = 'text/plain; charset=utf-8';
const JSON_CT = 'application/json; charset=utf-8';
const YAML_CT = 'application/yaml; charset=utf-8';
const DOWNLOAD_PREFIX = '/downloads/';

const REDIRECTS = new Map([
  ['/govp/', '/'],
  ['/govp/index.html', '/'],
  ['/govp.html', '/'],
  ['/govp/adopt.html', '/govp/governance.html'],
  ['/govp/api.html', '/govp/integration.html'],
  ['/govp/badge.html', '/govp/integration.html'],
  ['/govp/compare.html', '/govp/composition.html'],
  ['/govp/evidence.html', '/govp/examples.html'],
  ['/govp/govp-verificador-standalone.html', '/govp/verify.html'],
  ['/govp/network.html', '/govp/trust-model.html'],
  ['/govp/platforms.html', '/govp/docs.html'],
  ['/govp/playground.html', '/govp/verify.html'],
  ['/govp/technology.html', '/govp/protocol.html'],
  ['/govp/verify-offline.html', '/govp/verify.html'],
]);

function isPublicArtifact(path) {
  return path === '/.well-known/govp.txt'
    || path.startsWith('/.well-known/govp/')
    || path === '/install.sh'
    || path === '/llms.txt'
    || path === '/PROTOCOL-SOURCE.json'
    || path.startsWith('/govp/conformance/')
    || path.startsWith('/govp/examples/')
    || path.startsWith('/govp/schemas/')
    || path === '/govp/spec/govp-1.txt';
}

function contentTypeFor(path) {
  if (path === '/install.sh') return 'text/x-shellscript; charset=utf-8';
  if (path === '/.well-known/govp.txt') return TEXT;
  if (path.startsWith('/.well-known/govp/') && !path.endsWith('.json')) return TEXT;
  if (path === '/llms.txt' || path.endsWith('.govp') || path.endsWith('.govp.txt') || path.endsWith('.statement.txt')) return TEXT;
  if (path === '/govp/spec/govp-1.txt') return TEXT;
  if (path.endsWith('.json')) return JSON_CT;
  if (path.endsWith('.yaml') || path.endsWith('.yml')) return YAML_CT;
  return null;
}

function decorate(response, path) {
  const headers = new Headers(response.headers);
  for (const [key, value] of Object.entries(SECURITY_HEADERS)) headers.set(key, value);

  const contentType = contentTypeFor(path);
  if (contentType) headers.set('Content-Type', contentType);
  if (isPublicArtifact(path)) headers.set('Access-Control-Allow-Origin', '*');

  if (path === '/.well-known/govp/revoked.json') {
    headers.set('Cache-Control', 'no-store');
  } else if (path.endsWith('.js') || path.endsWith('.css') || path.endsWith('.svg')) {
    headers.set('Cache-Control', 'public, max-age=86400');
  } else if (!headers.has('Cache-Control')) {
    headers.set('Cache-Control', 'public, max-age=300');
  }

  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

function candidatesFor(path) {
  if (path.endsWith('/')) return [`${path}index.html`];
  const last = path.split('/').pop() || '';
  if (last.includes('.')) return [path];
  return [`${path}.html`, `${path}/index.html`];
}

async function fetchAsset(env, origin, request, path) {
  let lastResponse = null;
  for (const candidate of candidatesFor(path)) {
    const assetRequest = new Request(new URL(candidate, origin), request);
    const response = await env.ASSETS.fetch(assetRequest);
    if (response.status !== 404) return response;
    lastResponse = response;
  }
  return lastResponse;
}

async function fetchCurrentStatus(request, env, origin) {
  const path = '/.well-known/govp/revoked.json';
  const template = await env.ASSETS.fetch(new URL(path, origin));
  if (template.status !== 200) return decorate(template, path);
  let payload;
  try {
    payload = await template.json();
  } catch {
    return new Response('Invalid status template.\n', {
      status: 500,
      headers: SECURITY_HEADERS,
    });
  }
  payload.generated_at = new Date().toISOString();
  const headers = new Headers(template.headers);
  for (const name of ['Content-Length', 'ETag', 'Last-Modified']) headers.delete(name);
  const body = request.method === 'HEAD' ? null : `${JSON.stringify(payload, null, 2)}\n`;
  return decorate(new Response(body, { status: 200, headers }), path);
}

function downloadContentType(key) {
  if (key.endsWith('.exe')) return 'application/vnd.microsoft.portable-executable';
  if (key.endsWith('.tar.gz')) return 'application/gzip';
  if (key.endsWith('.whl') || key.endsWith('.zip')) return 'application/zip';
  if (key.endsWith('SHA256SUMS')) return TEXT;
  return 'application/octet-stream';
}

async function fetchDownload(request, env, path) {
  const key = path.slice(DOWNLOAD_PREFIX.length);
  if (!/^(cli|python|source)\/[A-Za-z0-9._/-]+$/.test(key) || key.includes('..')) {
    return new Response('Invalid download path.\n', { status: 400, headers: SECURITY_HEADERS });
  }

  const object = request.method === 'HEAD'
    ? await env.RELEASES.head(key)
    : await env.RELEASES.get(key);
  if (!object) {
    return new Response('Release asset not found.\n', { status: 404, headers: SECURITY_HEADERS });
  }

  const filename = key.split('/').pop() || 'download';
  const headers = new Headers(SECURITY_HEADERS);
  headers.set('Cache-Control', 'public, max-age=31536000, immutable');
  headers.set('Content-Disposition', `attachment; filename="${filename}"`);
  headers.set('Content-Length', String(object.size));
  headers.set('Content-Type', downloadContentType(key));
  headers.set('ETag', object.httpEtag);

  return new Response(request.method === 'HEAD' ? null : object.body, { headers });
}

function decodePath(pathname) {
  try {
    return decodeURIComponent(pathname);
  } catch {
    return null;
  }
}

function isSafePath(path) {
  return !path.includes('\\')
    && !path.includes('\0')
    && !path.split('/').some((segment) => segment === '..' || segment === '.');
}

export default {
  async fetch(request, env) {
    try {
      const url = new URL(request.url);
      const path = decodePath(url.pathname);
      if (path === null || !isSafePath(path)) {
        return new Response('Invalid URL encoding.\n', { status: 400, headers: SECURITY_HEADERS });
      }

      if (request.method === 'OPTIONS' && isPublicArtifact(path)) {
        return new Response(null, {
          status: 204,
          headers: {
            ...SECURITY_HEADERS,
            'Access-Control-Allow-Methods': 'GET, HEAD, OPTIONS',
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Max-Age': '86400',
          },
        });
      }

      if (request.method !== 'GET' && request.method !== 'HEAD') {
        return new Response('Method not allowed.\n', {
          status: 405,
          headers: { ...SECURITY_HEADERS, Allow: 'GET, HEAD, OPTIONS' },
        });
      }

      const redirect = REDIRECTS.get(path);
      if (redirect) {
        return new Response(null, {
          status: 308,
          headers: { ...SECURITY_HEADERS, Location: new URL(redirect, url.origin).toString() },
        });
      }

      if (path.startsWith(DOWNLOAD_PREFIX)) return fetchDownload(request, env, path);

      if (path === '/.well-known/govp/revoked.json') {
        return fetchCurrentStatus(request, env, url.origin);
      }

      const response = await fetchAsset(env, url.origin, request, path);
      if (!response || response.status === 404) {
        const notFound = await env.ASSETS.fetch(new URL('/404.html', url.origin));
        return decorate(new Response(notFound.body, { status: 404, headers: notFound.headers }), '/404.html');
      }
      return decorate(response, path);
    } catch (error) {
      console.error(JSON.stringify({
        message: 'unhandled request error',
        error: error instanceof Error ? error.message : String(error),
      }));
      return new Response('Internal server error.\n', { status: 500, headers: SECURITY_HEADERS });
    }
  },
};
