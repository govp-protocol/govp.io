# Deploying govp.io

The canonical protocol site is deployed as the Cloudflare Worker `govp-io`.
Static documentation is served from the repository root. Immutable release
objects may be served from the private R2 bucket `govp-releases`, but the site
must not advertise an object until its release manifest and checksum exist.

## Canonical repository and domains

- Repository: `govp-protocol/govp.io`
- Production branch: `main`
- Domains: `https://govp.io/` and `https://www.govp.io/`

No product application, user session, verification result or personal record
belongs in this repository or Worker.

## Rebuild and validate

```sh
npm ci
npm run build
npm test
npm run check:deploy
```

The build is deterministic from the tracked specification and page source.
Validation checks the browser verifier against the normative conformance
vectors, validates internal links and confirms hashes in `PROTOCOL-SOURCE.json`.

## Deploy

```sh
npx wrangler@4.118.0 deploy
```

After deployment, check the two production hostnames, security headers, the
plain-text specification, JSON vectors, Schema and local browser verifier.
Confirm that the deployed specification hash matches the canonical protocol
repository before making a publication announcement.

Also require these public protocol-identity resources to return `200`, the
declared content type and `Access-Control-Allow-Origin: *`:

- `/.well-known/govp.txt`;
- `/.well-known/govp/index.json`;
- the GOVP-ID record listed by that index;
- its public stewardship statement.

The identity signing key is generated and held outside this repository. Never
place its private half in the Worker, static assets, GitHub or release bundle.
