# GOVP website content

This directory contains the rendered GOVP-1 documentation, the byte-identical
normative artifacts pinned by `../PROTOCOL-SOURCE.json`, a fully synthetic
example, an independent browser verifier and deployment copies of the canonical
visual assets maintained in `govp-protocol/govp/brand`.

The browser verifier is tested against both canonical conformance suites. It
processes records and selected assets locally, applies explicit size bounds and
does not fetch evidence URLs. Automated or remote verification should use the
reference CLI in `govp-protocol/govp`.

Run the complete website validation from the repository root:

```sh
npm ci
npm run build
npm test
```

Do not add product downloads, customer records, live identities, signing keys,
private services or application sessions to this public protocol directory.
