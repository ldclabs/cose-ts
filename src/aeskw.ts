// (c) 2023-present, LDC Labs. All rights reserved.
// See the file LICENSE for licensing terms.

import { aeskw } from '@noble/ciphers/aes'
import * as iana from './iana'
import { RawMap, assertBytes } from './map'
import { Key, type KeyWrapper } from './key'
import { randomBytes, decodeCBOR } from './utils'

// AesKwKey implements the AES Key Wrap content key distribution method for COSE
// as defined in RFC 9053.
// https://datatracker.ietf.org/doc/html/rfc9053#name-aes-key-wrap.
export class AesKwKey extends Key implements KeyWrapper {
  static fromBytes(data: Uint8Array): AesKwKey {
    return new AesKwKey(decodeCBOR(data))
  }

  static generate<T>(alg: number, kid?: T): AesKwKey {
    return AesKwKey.fromSecret(randomBytes(getKeySize(alg)), kid)
  }

  static fromSecret<T>(secret: Uint8Array, kid?: T): AesKwKey {
    const alg = getAlg(assertBytes(secret, 'secret'))
    const key = new AesKwKey()
    key.alg = alg
    if (kid != null) {
      key.setKid(kid)
    }
    key.setParam(iana.SymmetricKeyParameterK, secret)
    return key
  }

  constructor(kv?: RawMap) {
    super(kv)

    this.kty = iana.KeyTypeSymmetric
  }

  getSecretKey(): Uint8Array {
    return this.getBytes(iana.SymmetricKeyParameterK, 'k')
  }

  // wrapKey wraps (encrypts) the given content encryption key with this KEK.
  wrapKey(cek: Uint8Array): Uint8Array {
    return aeskw(this.getSecretKey()).encrypt(cek)
  }

  // unwrapKey unwraps (decrypts) the wrapped content encryption key.
  unwrapKey(wrapped: Uint8Array): Uint8Array {
    return aeskw(this.getSecretKey()).decrypt(wrapped)
  }
}

function getKeySize(alg: number): number {
  switch (alg) {
    case iana.AlgorithmA128KW:
      return 16
    case iana.AlgorithmA192KW:
      return 24
    case iana.AlgorithmA256KW:
      return 32
    default:
      throw new Error(`cose-ts: unsupported AES-KW alg ${alg}`)
  }
}

function getAlg(key: Uint8Array): number {
  switch (key.length) {
    case 16:
      return iana.AlgorithmA128KW
    case 24:
      return iana.AlgorithmA192KW
    case 32:
      return iana.AlgorithmA256KW
    default:
      throw new Error(`cose-ts: unsupported AES-KW key length ${key.length}`)
  }
}
