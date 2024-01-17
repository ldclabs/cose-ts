# Keys, Algorithms, COSE and CWT

[![CI](https://github.com/ldclabs/cose-ts/actions/workflows/ci.yml/badge.svg)](https://github.com/ldclabs/cose-ts/actions/workflows/ci.yml)
[![NPM version](http://img.shields.io/npm/v/@ldclabs/cose-ts.svg)](https://www.npmjs.com/package/@ldclabs/cose-ts)
[![License](http://img.shields.io/badge/license-mit-blue.svg?style=flat-square)](https://raw.githubusercontent.com/ldclabs/cose-ts/main/LICENSE)

*A TypeScript library for the [CBOR Object Signing and Encryption (COSE)][cose-spec] and [CBOR Web Token (CWT)][cwt-spec].*

+ Golang version: [https://github.com/ldclabs/cose](https://github.com/ldclabs/cose)
+ Rust version: [https://github.com/google/coset](https://github.com/google/coset)

## Introduction

COSE is a standard for signing and encrypting data in the [CBOR][cbor] data format. It is designed to be simple and efficient, and to be usable in constrained environments. It is intended to be used in a variety of applications, including the Internet of Things, and is designed to be extensible to support new algorithms and applications.

## Features

- Key: Full support.
- Algorithms:
  - Signing: ECDSA, Ed25519;
  - Encryption: AES-GCM, ChaCha20/Poly1305;
  - MAC: HMAC;
- COSE: COSE_Encrypt0, COSE_Mac0, COSE_Sign1.
- CWT: Full support.

## Packages

| Package                                                                                  | Import                            | Description                                                                                                                                                                                                                                                                                |
| ---------------------------------------------------------------------------------------- | --------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| [cwt](https://github.com/ldclabs/cose-ts/blob/main/src/cwt.ts)                           | @ldclabs/cose-ts/cwt              | exports: class `Claims`, function `withCWTTag`, interface `ValidatorOpts`, class `Validator`                                                                                                                                                                                               |
| [encrypt0](https://github.com/ldclabs/cose-ts/blob/main/src/encrypt0.ts)                 | @ldclabs/cose-ts/encrypt0         | exports: class `Encrypt0Message`                                                                                                                                                                                                                                                           |
| [sign1](https://github.com/ldclabs/cose-ts/blob/main/src/sign1.ts)                       | @ldclabs/cose-ts/sign1            | exports: class `Sign1Message`                                                                                                                                                                                                                                                              |
| [mac0](https://github.com/ldclabs/cose-ts/blob/main/src/mac0.ts)                         | @ldclabs/cose-ts/mac0             | exports: class `Mac0Message`                                                                                                                                                                                                                                                               |
| [iana](https://github.com/ldclabs/cose-ts/blob/main/src/iana.ts)                         | @ldclabs/cose-ts/iana             | [IANA: COSE][iana-cose] + [IANA: CWT][iana-cwt] + [IANA: CBOR Tags][iana-cbor-tags]                                                                                                                                                                                                        |
| [ed25519](https://github.com/ldclabs/cose-ts/blob/main/src/ed25519.ts)                   | @ldclabs/cose-ts/ed25519          | exports: class `Ed25519Key`                                                                                                                                                                                                                                                                |
| [ecdsa](https://github.com/ldclabs/cose-ts/blob/main/src/ecdsa.ts)                       | @ldclabs/cose-ts/ecdsa            | exports: class `ECDSAKey`, function `getCrv`, function `getCurve`                                                                                                                                                                                                                          |
| [hmac](https://github.com/ldclabs/cose-ts/blob/main/src/hmac.ts)                         | @ldclabs/cose-ts/hmac             | exports: class `HMACKey`                                                                                                                                                                                                                                                                   |
| [aesgcm](https://github.com/ldclabs/cose-ts/blob/main/src/aesgcm.ts)                     | @ldclabs/cose-ts/aesgcm           | exports: class `AesGcmKey`                                                                                                                                                                                                                                                                 |  |
| [chacha20poly1305](https://github.com/ldclabs/cose-ts/blob/main/src/chacha20poly1305.ts) | @ldclabs/cose-ts/chacha20poly1305 | exports: class `ChaCha20Poly1305Key`                                                                                                                                                                                                                                                       |
| [key](https://github.com/ldclabs/cose-ts/blob/main/src/key.ts)                           | @ldclabs/cose-ts/key              | exports: class `Key`, interface `Encryptor`, interface `MACer`, interface `Signer`, interface `Verifier`                                                                                                                                                                                   |
| [hash](https://github.com/ldclabs/cose-ts/blob/main/src/hash.ts)                         | @ldclabs/cose-ts/hash             | exports: `hmac`, `sha256`, `sha384`, `sha512`, `sha3_256`, `sha3_384`, `sha3_512`, function `getHash`                                                                                                                                                                                      |
| [header](https://github.com/ldclabs/cose-ts/blob/main/src/header.ts)                     | @ldclabs/cose-ts/header           | exports: class `Header`                                                                                                                                                                                                                                                                    |
| [map](https://github.com/ldclabs/cose-ts/blob/main/src/map.ts)                           | @ldclabs/cose-ts/map              | exports: class `KVMap`, type `RawMap`, type `AssertFn<T>`, `assertText`, `assertInt`, `assertIntOrText`, `assertBytes`, `assertBool`, `assertMap`                                                                                                                                          |
| [tag](https://github.com/ldclabs/cose-ts/blob/main/src/tag.ts)                           | @ldclabs/cose-ts/tag              | exports: function `withTag`, function `skipTag`, and many consts                                                                                                                                                                                                                           |
| [utils](https://github.com/ldclabs/cose-ts/blob/main/src/utils.ts)                       | @ldclabs/cose-ts/utils            | exports: `bytesToHex`, `hexToBytes`,                                                                                                               `utf8ToBytes`, `randomBytes`, `toBytes`, `concatBytes`, `bytesToBase64Url`, `base64ToBytes`, `compareBytes`, `decodeCBOR`, `encodeCBOR` |

## Examples

### CWT in Sign1Message with Ed25519 Key

```typescript
import { utf8ToBytes, randomBytes, compareBytes } from '@ldclabs/cose-ts/utils'
import { Validator, Claims, withCWTTag } from '@ldclabs/cose-ts/cwt'
import { Ed25519Key } from '@ldclabs/cose-ts/ed25519'
import { Sign1Message } from '@ldclabs/cose-ts/sign1'

// get key
const privKey = Ed25519Key.generate()
// const privKey = Ed25519Key.fromSecret(32_bytes_secret)
const pubKey = privKey.public()
// const pubKey = Ed25519Key.fromPublic(32_bytes_public)

// signing
const claims = new Claims()
claims.iss = 'ldclabs'
claims.aud = 'cose-ts'
claims.sub = 'tester'
claims.exp = Math.floor(Date.now() / 1000) + 3600
claims.cti = randomBytes(16)

const cwtMsg = new Sign1Message(claims.toBytes())
const cwtData = cwtMsg.toBytes(privKey, utf8ToBytes('@ldclabs/cose-ts'))
// const cwtDataWithTag = withCWTTag(cwtData)

// verifying
const cwtMsg2 = Sign1Message.fromBytes(
  pubKey,
  cwtData, // or cwtDataWithTag
  utf8ToBytes('@ldclabs/cose-ts')
)
const claims2 = Claims.fromBytes(cwtMsg2.payload)
const validator = new Validator({ expectedIssuer: 'ldclabs' })
validator.validate(claims2)
assert.equal(claims2.iss, claims.iss)
assert.equal(claims2.aud, claims.aud)
assert.equal(claims2.sub, claims.sub)
assert.equal(claims2.exp, claims.exp)
assert.equal(compareBytes(claims2.cti, claims.cti), 0)
```

## Security Reviews

Todo.

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
Copyright © 2022-2024 [LDC Labs](https://github.com/ldclabs).

ldclabs/cose-ts is licensed under the MIT License. See [LICENSE](LICENSE) for the full license text.
