# AI Agent Guide for cose-ts

This guide is written for AI agents and code-generation workflows. It keeps the
public contract compact, explicit, and easy to test.

## One-Minute Contract

- Use subpath imports such as `@ldclabs/cose-ts/sign1`.
- Do not import from `@ldclabs/cose-ts`; the root is not a runtime barrel.
- Use `Uint8Array` for payloads, keys, signatures, ciphertexts, IVs, and
  external authenticated data.
- Pass the same `externalData` bytes to both `toBytes` and `fromBytes`.
- Use IANA constants from `@ldclabs/cose-ts/iana` instead of hard-coded
  algorithm labels when possible.
- Prefer the message classes over hand-building CBOR arrays.

## Choose the Right Message

| Requirement           | Use                          | Example                       |
| --------------------- | ---------------------------- | ----------------------------- |
| Single signature      | `Sign1Message`               | `examples/sign1-ed25519.ts`   |
| Multiple signatures   | `SignMessage`                | `src/sign.test.ts`            |
| Shared-key encryption | `Encrypt0Message`            | `examples/encrypt0-aesgcm.ts` |
| Recipient encryption  | `EncryptMessage`             | `examples/encrypt-aeskw.ts`   |
| Shared-key MAC        | `Mac0Message`                | `examples/mac0-hmac.ts`       |
| Recipient MAC         | `MacMessage`                 | `src/mac.test.ts`             |
| Signed CWT            | `Claims` plus `Sign1Message` | `examples/cwt-sign1.ts`       |

Use the smallest structure that matches the protocol. For example, if the
receiver already knows the content encryption key, use `Encrypt0Message`
instead of `EncryptMessage`.

## Import Map

| Need                      | Import                                            |
| ------------------------- | ------------------------------------------------- |
| COSE_Sign1                | `@ldclabs/cose-ts/sign1`                          |
| COSE_Sign                 | `@ldclabs/cose-ts/sign`                           |
| COSE_Encrypt0             | `@ldclabs/cose-ts/encrypt0`                       |
| COSE_Encrypt              | `@ldclabs/cose-ts/encrypt`                        |
| COSE_Mac0                 | `@ldclabs/cose-ts/mac0`                           |
| COSE_Mac                  | `@ldclabs/cose-ts/mac`                            |
| COSE headers              | `@ldclabs/cose-ts/header`                         |
| COSE keys                 | `@ldclabs/cose-ts/key`, `@ldclabs/cose-ts/keyset` |
| Recipients                | `@ldclabs/cose-ts/recipient`                      |
| CWT claims and validation | `@ldclabs/cose-ts/cwt`                            |
| Constants                 | `@ldclabs/cose-ts/iana`                           |
| Byte and CBOR helpers     | `@ldclabs/cose-ts/utils`                          |
| Ed25519                   | `@ldclabs/cose-ts/ed25519`                        |
| ECDSA                     | `@ldclabs/cose-ts/ecdsa`                          |
| ECDH                      | `@ldclabs/cose-ts/ecdh`                           |
| AES-GCM                   | `@ldclabs/cose-ts/aesgcm`                         |
| ChaCha20/Poly1305         | `@ldclabs/cose-ts/chacha20poly1305`               |
| HMAC                      | `@ldclabs/cose-ts/hmac`                           |
| AES-KW                    | `@ldclabs/cose-ts/aeskw`                          |

## Key Construction Cheat Sheet

Factory argument order is **not** uniform across key types. Read this table
before calling `generate` / `fromSecret` / `fromPublic`; the wrong first
argument is the most common agent mistake with this library.

| Key class             | `generate(...)`        | `fromSecret(...)`         | `fromPublic(...)`        |
| --------------------- | ---------------------- | ------------------------- | ------------------------ |
| `Ed25519Key`          | `(kid?)`               | `(secret, kid?)`          | `(pubkey, kid?)`         |
| `ECDSAKey`            | `(alg, kid?)`          | `(secret, kid?)`          | `(pubkey, kid?)`         |
| `AesGcmKey`           | `(alg, kid?)`          | `(secret, kid?)`          | —                        |
| `ChaCha20Poly1305Key` | `(kid?)`               | `(secret, kid?)`          | —                        |
| `AesKwKey`            | `(alg, kid?)`          | `(secret, kid?)`          | —                        |
| `HMACKey`             | `(alg, kid?)`          | `(secret, `**`alg`**`, kid?)` | —                    |
| `ECDHKey`             | `(`**`crv`**`, kid?)`  | `(`**`crv`**`, secret, kid?)` | `(`**`crv`**`, pubkey, kid?)` |

Watch out for the highlighted cases:

- `Ed25519Key` and `ChaCha20Poly1305Key` have a fixed algorithm, so the first
  `generate` argument is the optional `kid`, not an algorithm.
- `HMACKey.fromSecret` takes the algorithm as its **second** argument, unlike
  every other `fromSecret`.
- `ECDHKey` takes the **curve first** on `generate`, `fromSecret`, and
  `fromPublic`.

`alg` and `crv` values come from `@ldclabs/cose-ts/iana` (for example
`iana.AlgorithmES256`, `iana.AlgorithmA128GCM`, `iana.AlgorithmHMAC_256_256`,
`iana.EllipticCurveX25519`). `kid` is optional everywhere and is CBOR-encoded
into the COSE_Key. Call `key.public()` to get a verify/share-only copy with the
private material stripped.

## Message Constructor Argument Order

The recipient-carrying messages take headers as positional arguments before the
recipient list, so pass `undefined` for the headers you do not set.

| Constructor                                                  | Recipients position |
| ----------------------------------------------------------- | ------------------- |
| `new EncryptMessage(payload, protected?, unprotected?, recipients?)` | 4th argument |
| `new MacMessage(payload, protected?, unprotected?, tag?, recipients?)` | **5th** argument (the 4th is the tag) |
| `new SignMessage(payload, protected?, unprotected?, signatures?)` | 4th argument (optional; auto-created per key) |

```ts
// Correct: recipients are the 4th arg on EncryptMessage, the 5th on MacMessage.
new EncryptMessage(payload, undefined, undefined, [Recipient.keyWrap(kek)])
new MacMessage(payload, undefined, undefined, undefined, [Recipient.keyWrap(kek)])
```

## Safe Recipes

### Sign and verify bytes

Use `Sign1Message` with an Ed25519 or ECDSA key. Verification must use the
public key and the same external authenticated data.

```ts
const signingKey = Ed25519Key.generate()
const aad = utf8ToBytes('profile:v1')
const cose = new Sign1Message(utf8ToBytes('hello')).toBytes(signingKey, aad)
const verified = Sign1Message.fromBytes(signingKey.public(), cose, aad)
```

### Encrypt with an implicit content key

Use `Encrypt0Message` when the protocol already shares the content encryption
key. The helper creates a full IV if one is not supplied.

```ts
const key = AesGcmKey.generate(iana.AlgorithmA128GCM)
const aad = utf8ToBytes('profile:v1')
const cose = await new Encrypt0Message(plaintext).toBytes(key, aad)
const decrypted = await Encrypt0Message.fromBytes(key, cose, aad)
```

### Encrypt for a recipient

Use `EncryptMessage` with a content encryption key and a recipient key
encryption key. `Recipient.keyWrap(kek)` wraps the content key with AES-KW.

```ts
const cek = AesGcmKey.generate(iana.AlgorithmA256GCM)
const kek = AesKwKey.generate(iana.AlgorithmA256KW, 'recipient-1')
const cose = await new EncryptMessage(plaintext, undefined, undefined, [
  Recipient.keyWrap(kek)
]).toBytes(cek, aad)
const decrypted = await EncryptMessage.fromBytes([kek], cose, aad)
```

### Create and validate a CWT

Encode claims as the payload of a `Sign1Message`, then wrap the signed bytes in
the CWT tag.

```ts
const claims = new Claims()
claims.iss = 'issuer'
claims.aud = 'service'
claims.sub = 'user-123'
claims.exp = Math.floor(Date.now() / 1000) + 3600

const token = withCWTTag(new Sign1Message(claims.toBytes()).toBytes(key, aad))
const signed = Sign1Message.fromBytes(key.public(), token, aad)
new Validator({
  expectedIssuer: 'issuer',
  expectedAudience: 'service'
}).validate(Claims.fromBytes(signed.payload))
```

## Header Rules Agents Usually Miss

- Protected headers are authenticated; unprotected headers are metadata.
- The same header label must not appear in both buckets.
- `crit` must be protected.
- `alg` is validated against the key algorithm when present.
- `IV` and `Partial IV` cannot appear in the same security layer.
- `Partial IV` is currently rejected by encryption helpers.
- `kid` is only a selection hint. It is not proof of identity.

## Error-to-Repair Map

| Error text contains           | Likely fix                                                         |
| ----------------------------- | ------------------------------------------------------------------ |
| `no package root entry point` | Import from a subpath module.                                      |
| `alg mismatch`                | Align the protected `alg` header with the key algorithm.           |
| `signature mismatch`          | Check public key, payload, signature, tag, and `externalData`.     |
| `tag mismatch`                | Check MAC key, payload, protected headers, and `externalData`.     |
| `decryption failed`           | Check KEK/CEK, recipient mode, IV, ciphertext, and `externalData`. |
| `Partial IV is not supported` | Use full IV handling or implement Partial IV support first.        |
| `key_ops ... does not permit` | Use a key whose `key_ops` allows the requested operation.          |

## Testing Agent-Generated Code

Run the runnable examples and full project gates:

```bash
pnpm run examples
pnpm test
pnpm run build
pnpm run lint
git diff --check
```

When only generated snippets changed, `pnpm run examples` is the minimum check.
When message, header, key, recipient, or utility code changed, run all gates.
