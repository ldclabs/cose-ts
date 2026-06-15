# Keys, Algorithms, COSE and CWT

[![CI](https://github.com/ldclabs/cose-ts/actions/workflows/ci.yml/badge.svg)](https://github.com/ldclabs/cose-ts/actions/workflows/ci.yml)
[![NPM version](http://img.shields.io/npm/v/@ldclabs/cose-ts.svg)](https://www.npmjs.com/package/@ldclabs/cose-ts)
[![License](http://img.shields.io/badge/license-mit-blue.svg?style=flat-square)](https://raw.githubusercontent.com/ldclabs/cose-ts/main/LICENSE)

_A TypeScript library for the [CBOR Object Signing and Encryption (COSE)][cose-spec] and [CBOR Web Token (CWT)][cwt-spec]._

- Golang version: [https://github.com/ldclabs/cose](https://github.com/ldclabs/cose)
- Rust version: [https://github.com/ldclabs/cose2](https://github.com/ldclabs/cose2)

## Install

```bash
npm install @ldclabs/cose-ts
# or
pnpm add @ldclabs/cose-ts
```

The package is ESM-only and requires Node.js 20.19+ or a modern browser runtime.
Import from subpath modules such as `@ldclabs/cose-ts/sign1`; the package root
is not a barrel entry point.

## AI Agent Guide

If you are using an AI coding agent, start with [AGENTS.md](AGENTS.md) and
[docs/agent-guide.md](docs/agent-guide.md). The short contract is: choose the
COSE structure first, import from a package subpath, keep `externalData`
identical across encode/decode paths, and run `pnpm run examples` when snippets
or public APIs change.

Runnable recipes live in [examples](examples/):

- `sign1-ed25519.ts`
- `encrypt0-aesgcm.ts`
- `encrypt-aeskw.ts`
- `mac0-hmac.ts`
- `cwt-sign1.ts`

## What It Provides

COSE defines compact CBOR structures for signatures, encryption, MACs, keys,
and key sets. This library implements the RFC 9052 structures and common RFC
9053 algorithms in TypeScript.

- COSE messages: `COSE_Sign`, `COSE_Sign1`, `COSE_Encrypt`, `COSE_Encrypt0`,
  `COSE_Mac`, `COSE_Mac0`, `COSE_recipient`, `COSE_KeySet`.
- CWT: claims, validation, and CWT-tag helpers.
- Signing: ECDSA (`ES256`, `ES384`, `ES512`) and Ed25519.
- Encryption: AES-GCM and ChaCha20/Poly1305.
- MAC: HMAC-SHA-256/384/512 variants.
- Key wrap: AES-KW (`A128KW`, `A192KW`, `A256KW`).
- KDF and key agreement helpers: HKDF-SHA and ECDH curves P-256, P-384, P-521,
  X25519.

## Quick Start

### Sign and Verify with COSE_Sign1

```typescript
import { Ed25519Key } from '@ldclabs/cose-ts/ed25519'
import { Sign1Message } from '@ldclabs/cose-ts/sign1'
import { utf8ToBytes } from '@ldclabs/cose-ts/utils'

const privateKey = Ed25519Key.generate()
const publicKey = privateKey.public()

const signed = new Sign1Message(utf8ToBytes('hello')).toBytes(privateKey)
const verified = Sign1Message.fromBytes(publicKey, signed)

console.log(new TextDecoder().decode(verified.payload)) // "hello"
```

### Encrypt with an Implicit Key

Use `COSE_Encrypt0` when sender and receiver already know the content
encryption key.

```typescript
import { AesGcmKey } from '@ldclabs/cose-ts/aesgcm'
import { Encrypt0Message } from '@ldclabs/cose-ts/encrypt0'
import * as iana from '@ldclabs/cose-ts/iana'
import { utf8ToBytes } from '@ldclabs/cose-ts/utils'

const key = AesGcmKey.generate(iana.AlgorithmA128GCM)

const ciphertext = await new Encrypt0Message(utf8ToBytes('secret')).toBytes(key)

const plaintext = await Encrypt0Message.fromBytes(key, ciphertext)
console.log(new TextDecoder().decode(plaintext.payload)) // "secret"
```

### Encrypt for Recipients with AES Key Wrap

Use `COSE_Encrypt` when the content encryption key needs to be carried for one
or more recipients. The content encryption key protects the payload; each
recipient key encryption key wraps that content key.

```typescript
import * as iana from '@ldclabs/cose-ts/iana'
import { AesKwKey } from '@ldclabs/cose-ts/aeskw'
import { ChaCha20Poly1305Key } from '@ldclabs/cose-ts/chacha20poly1305'
import { EncryptMessage } from '@ldclabs/cose-ts/encrypt'
import { Recipient } from '@ldclabs/cose-ts/recipient'
import { utf8ToBytes } from '@ldclabs/cose-ts/utils'

const cek = ChaCha20Poly1305Key.generate()
const kek = AesKwKey.generate(iana.AlgorithmA256KW, utf8ToBytes('kek-1'))

const encrypted = await new EncryptMessage(
  utf8ToBytes('This is the content.'),
  undefined,
  undefined,
  [Recipient.keyWrap(kek)]
).toBytes(cek)

const decrypted = await EncryptMessage.fromBytes([kek], encrypted)
console.log(new TextDecoder().decode(decrypted.payload))
```

### Create and Validate a CWT

```typescript
import { Claims, Validator, withCWTTag } from '@ldclabs/cose-ts/cwt'
import { Ed25519Key } from '@ldclabs/cose-ts/ed25519'
import { Sign1Message } from '@ldclabs/cose-ts/sign1'
import { randomBytes } from '@ldclabs/cose-ts/utils'

const key = Ed25519Key.generate()

const claims = new Claims()
claims.iss = 'issuer'
claims.aud = 'service'
claims.sub = 'user-123'
claims.exp = Math.floor(Date.now() / 1000) + 3600
claims.cti = randomBytes(16)

const token = withCWTTag(new Sign1Message(claims.toBytes()).toBytes(key))
const signed = Sign1Message.fromBytes(key.public(), token)
const decodedClaims = Claims.fromBytes(signed.payload)

new Validator({
  expectedIssuer: 'issuer',
  expectedAudience: 'service'
}).validate(decodedClaims)
```

## Core Concepts

### Headers

COSE headers are split into protected and unprotected buckets. Protected headers
are encoded as a byte string and are included in the signature, MAC, or AEAD
authenticated data. Unprotected headers are metadata only.

```typescript
import * as iana from '@ldclabs/cose-ts/iana'
import { Header } from '@ldclabs/cose-ts/header'

const protectedHeader = new Header().setParam(
  iana.HeaderParameterContentType,
  'application/cwt'
)
```

The library validates RFC 9052 header rules when encoding and decoding:
duplicate labels across header buckets are rejected, `crit` must be protected,
common header value types are checked, and `IV` and `Partial IV` cannot appear
in the same security layer. `Partial IV` is recognized but not yet supported by
the encryption helpers.

### External Authenticated Data

Every `toBytes` / `fromBytes` method for signatures, MACs, and AEAD encryption
accepts optional `externalData`. Pass the exact same bytes on verification or
decryption, or authentication will fail.

```typescript
const aad = new TextEncoder().encode('coap-code-and-options')
const signed = new Sign1Message(payload).toBytes(privateKey, aad)
Sign1Message.fromBytes(publicKey, signed, aad)
```

### Tags

Message classes accept tagged and untagged inputs. Use the static `withTag`
helpers when a protocol expects the standard COSE tag.

```typescript
const tagged = Sign1Message.withTag(new Sign1Message(payload).toBytes(key))
const parsed = Sign1Message.fromBytes(key.public(), tagged)
```

### Keys and Key IDs

Keys are COSE_Key maps. `generate()` creates a fresh key, `fromSecret()` and
`fromPublic()` import raw key material, and `public()` removes private
parameters when available. If a key has a `kid`, message helpers copy it into
the unprotected header as a key-selection hint.

Use `key_ops` when a key should be restricted to a specific operation. The
operation is enforced by signing, verification, encryption, decryption, MAC, and
key-wrap helpers.

## Module Guide

| Use case                    | Import                                            | Main exports                             |
| --------------------------- | ------------------------------------------------- | ---------------------------------------- |
| Single-signer signatures    | `@ldclabs/cose-ts/sign1`                          | `Sign1Message`                           |
| Multi-signer signatures     | `@ldclabs/cose-ts/sign`                           | `SignMessage`, `Signature`               |
| Single-recipient encryption | `@ldclabs/cose-ts/encrypt0`                       | `Encrypt0Message`                        |
| Enveloped encryption        | `@ldclabs/cose-ts/encrypt`                        | `EncryptMessage`                         |
| Single-key MAC              | `@ldclabs/cose-ts/mac0`                           | `Mac0Message`                            |
| Recipient-based MAC         | `@ldclabs/cose-ts/mac`                            | `MacMessage`                             |
| Recipients                  | `@ldclabs/cose-ts/recipient`                      | `Recipient`                              |
| CWT                         | `@ldclabs/cose-ts/cwt`                            | `Claims`, `Validator`, `withCWTTag`      |
| COSE headers                | `@ldclabs/cose-ts/header`                         | `Header`, `verifyHeaders`                |
| COSE keys                   | `@ldclabs/cose-ts/key`, `@ldclabs/cose-ts/keyset` | `Key`, `KeySet`                          |
| Algorithm constants         | `@ldclabs/cose-ts/iana`                           | COSE, CWT, and CBOR tag constants        |
| CBOR and byte helpers       | `@ldclabs/cose-ts/utils`                          | `encodeCBOR`, `decodeCBOR`, byte helpers |
| Ed25519                     | `@ldclabs/cose-ts/ed25519`                        | `Ed25519Key`                             |
| ECDSA                       | `@ldclabs/cose-ts/ecdsa`                          | `ECDSAKey`                               |
| ECDH                        | `@ldclabs/cose-ts/ecdh`                           | `ECDHKey`                                |
| AES-GCM                     | `@ldclabs/cose-ts/aesgcm`                         | `AesGcmKey`                              |
| ChaCha20/Poly1305           | `@ldclabs/cose-ts/chacha20poly1305`               | `ChaCha20Poly1305Key`                    |
| HMAC                        | `@ldclabs/cose-ts/hmac`                           | `HMACKey`                                |
| AES-KW                      | `@ldclabs/cose-ts/aeskw`                          | `AesKwKey`                               |

## Interoperability Notes

- CBOR output uses deterministic RFC 8949 map ordering for integer and text
  labels. Decoding rejects duplicate map keys.
- Protected empty headers are encoded as a zero-length byte string, and decoding
  accepts both the zero-length byte string and encoded empty-map forms.
- `COSE_recipient` currently provides direct mode and AES-KW helpers. Unknown
  recipient algorithms can be parsed, but key recovery is only implemented for
  supported helpers.
- `kid` values are hints, not unique identifiers. If several keys share a
  `kid`, callers should try each candidate key.
- Text-string algorithm labels are accepted by generic header validation, but
  built-in algorithms use the registered integer labels from `iana`.

## Development

```bash
pnpm install
pnpm run examples
pnpm test
pnpm run build
pnpm run lint
```

Tests include RFC 9052 structure checks, RFC example vectors, runnable examples,
agent-oriented misuse checks, and coverage for encoding edge cases.

## Security Notes

- Always authenticate application context through `externalData` when protocol
  metadata affects security decisions.
- Reusing a nonce/IV with the same AEAD key is unsafe. Let the message helpers
  generate IVs unless your protocol has its own nonce allocation scheme.
- `compareBytes` is lexicographic and exits early; use `equalBytes` for
  secret-derived values such as MAC tags.
- This library does not choose algorithms or key-management policy for an
  application profile. Protocols should specify which COSE structures,
  algorithms, tags, and external authenticated data are required.

## Reference

1. [RFC9052: CBOR Object Signing and Encryption (COSE)][cose-spec]
2. [RFC8392: CBOR Web Token (CWT)][cwt-spec]
3. [RFC9053: CBOR Object Signing and Encryption (COSE): Initial Algorithms][algorithms-spec]
4. [IANA: CBOR Object Signing and Encryption (COSE)][iana-cose]
5. [IANA: CBOR Web Token (CWT) Claims][iana-cwt]
6. [IANA: Concise Binary Object Representation (CBOR) Tags][iana-cbor-tags]

[cbor]: https://datatracker.ietf.org/doc/html/rfc8949
[cose-spec]: https://datatracker.ietf.org/doc/html/rfc9052
[cwt-spec]: https://datatracker.ietf.org/doc/html/rfc8392
[algorithms-spec]: https://datatracker.ietf.org/doc/html/rfc9053
[iana-cose]: https://www.iana.org/assignments/cose/cose.xhtml
[iana-cwt]: https://www.iana.org/assignments/cwt/cwt.xhtml
[iana-cbor-tags]: https://www.iana.org/assignments/cbor-tags/cbor-tags.xhtml

## License

Copyright © 2022-2026 [LDC Labs](https://github.com/ldclabs).

ldclabs/cose-ts is licensed under the MIT License. See [LICENSE](LICENSE) for the full license text.
