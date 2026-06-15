# AGENTS.md

This repository implements COSE and CWT primitives in TypeScript. This file is
the fast path for AI coding agents working in the repo or generating code that
uses `@ldclabs/cose-ts`.

## Start Here

1. Import from package subpaths, not from the package root.
2. Pick the COSE structure before picking the algorithm.
3. Keep `externalData` identical across encode and decode paths.
4. Let message helpers generate IVs unless the protocol defines its own nonce
   allocation.
5. Run the example suite when changing public APIs, README snippets, or docs.

## Import Contract

Use this:

```ts
import { Sign1Message } from '@ldclabs/cose-ts/sign1'
import { Ed25519Key } from '@ldclabs/cose-ts/ed25519'
```

Do not use this:

```ts
import { Sign1Message } from '@ldclabs/cose-ts'
```

The package root intentionally has no runtime barrel. The supported public
entry points are the subpaths listed in `README.md` and
`docs/agent-guide.md`.

## Structure Selection

| Goal                                       | Use                                   | Key class                                     |
| ------------------------------------------ | ------------------------------------- | --------------------------------------------- |
| One signer signs payload bytes             | `Sign1Message`                        | `Ed25519Key` or `ECDSAKey`                    |
| Several signers sign one payload           | `SignMessage`                         | `Ed25519Key` or `ECDSAKey`                    |
| Encrypt with an already shared content key | `Encrypt0Message`                     | `AesGcmKey` or `ChaCha20Poly1305Key`          |
| Encrypt for recipients with wrapped keys   | `EncryptMessage`                      | content key plus `AesKwKey` recipient KEK     |
| MAC with an already shared MAC key         | `Mac0Message`                         | `HMACKey`                                     |
| MAC for recipients with wrapped keys       | `MacMessage`                          | content MAC key plus `AesKwKey` recipient KEK |
| CWT signed as COSE_Sign1                   | `Claims`, `Validator`, `Sign1Message` | `Ed25519Key` or `ECDSAKey`                    |

## Key Construction

Factory argument order differs by key type. Get the first argument right:

- `generate(kid?)`: `Ed25519Key`, `ChaCha20Poly1305Key` (algorithm is fixed).
- `generate(alg, kid?)`: `ECDSAKey`, `AesGcmKey`, `AesKwKey`, `HMACKey`.
- `generate(crv, kid?)`: `ECDHKey` (and `crv` is first on every `ECDHKey`
  factory).
- `HMACKey.fromSecret(secret, alg, kid?)`: algorithm is the second argument,
  unlike every other `fromSecret`.

Recipient lists are positional: `new EncryptMessage(payload, protected,
unprotected, recipients)` (4th) but `new MacMessage(payload, protected,
unprotected, tag, recipients)` (5th — the 4th slot is the tag). See the full
cheat sheet in `docs/agent-guide.md`.

## Runnable Examples

Use `examples/` for copyable recipes:

- `examples/sign1-ed25519.ts`
- `examples/encrypt0-aesgcm.ts`
- `examples/encrypt-aeskw.ts`
- `examples/mac0-hmac.ts`
- `examples/cwt-sign1.ts`

Run them with:

```bash
pnpm run examples
```

## Common Failure Modes

- Root import fails: switch to a subpath import.
- Signature, MAC, or decrypt verification fails: check key, algorithm header,
  payload bytes, tags, and `externalData`.
- Header validation fails: do not duplicate labels across protected and
  unprotected buckets. Put `crit` in the protected bucket.
- Encryption rejects `Partial IV`: this library recognizes it but does not
  implement Partial IV handling yet. Use a full IV or add explicit support.
- Recipient recovery fails: use `Recipient.keyWrap(kek)` for AES-KW, and pass
  the same KEK candidate to `fromBytes`.

## Change Checklist

Before finishing a change:

```bash
pnpm run examples
pnpm test
pnpm run build
pnpm run lint
git diff --check
```

If a change affects only docs, still run `pnpm run examples` when snippets,
imports, or public API names changed.
