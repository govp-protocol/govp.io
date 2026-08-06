# govp.io

Official website, rendered documentation and browser verifier for the GOVP
open protocol.

The normative protocol source lives in
[`govp-protocol/govp`](https://github.com/govp-protocol/govp). This repository
publishes byte-identical copies of the GOVP-1 specification, JSON Schema and
conformance vectors. [`PROTOCOL-SOURCE.json`](PROTOCOL-SOURCE.json) pins their
approved source commit and checksums.

## Scope

- explain GOVP-1, its trust boundaries and its honest limits;
- document composition with signing, attestation and transparency ecosystems;
- publish stable specification, schema and conformance URLs;
- publish the domain's signed GOVP identity and discovery index under
  `/.well-known/`;
- provide a client-side verifier that sends no record to a server;
- preserve versioned documentation and audited source provenance;
- deploy the static site through a minimal Cloudflare Worker.

Commercial products and implementations outside the audited protocol are not
part of this repository.

## Validate

```sh
npm ci
npm run build
npm test
npx wrangler deploy --dry-run
```

## Deploy

Production deployment is described in [`DEPLOY-cloudflare.md`](DEPLOY-cloudflare.md).
The Worker uses the `RELEASES` R2 binding for immutable, versioned downloads.

## Ownership and license

Website code and content are MIT-licensed. Copyright is held by Brilyetz
Holding S.L.; Gemacode is its brand. The MIT license does not grant rights to
the GOVP or Gemacode names—see [`TRADEMARKS.md`](TRADEMARKS.md).
