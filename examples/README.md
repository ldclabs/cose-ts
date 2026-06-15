# cose-ts Examples

These examples use the public package subpath imports that downstream projects
should use. In this repository, `pnpm run examples` runs them through Vitest
with aliases that point those subpaths at `src/`, so the examples are checked
before publishing.

Run all examples:

```bash
pnpm run examples
```

Available recipes:

- `sign1-ed25519.ts`: sign and verify a `COSE_Sign1` payload.
- `encrypt0-aesgcm.ts`: encrypt and decrypt with an implicit AES-GCM content
  key.
- `encrypt-aeskw.ts`: encrypt for a recipient using AES Key Wrap.
- `mac0-hmac.ts`: create and verify a `COSE_Mac0` tag.
- `cwt-sign1.ts`: sign CWT claims with `COSE_Sign1` and validate them.
