// (c) 2023-present, LDC Labs. All rights reserved.
// See the file LICENSE for licensing terms.

import * as iana from './iana'
import { RawMap, assertBytes } from './map'
import { Key, type MACer } from './key'
import { randomBytes, decodeCBOR } from './utils'
import { hmac, getHash } from './hash'


// TODO: more checks
// HMACKey implements message authentication code algorithm HMAC for COSE as defined in RFC9053.
// https://datatracker.ietf.org/doc/html/rfc9053#name-hash-based-message-authenti.
export class HMACKey extends Key implements MACer {
  static fromBytes(data: Uint8Array): HMACKey {
    return new HMACKey(decodeCBOR(data))
  }

  static generate<T>(alg: number, kid?: T): HMACKey {
    return HMACKey.fromSecret(randomBytes(getKeySize(alg)), alg, kid)
  }

  static fromSecret<T>(secret: Uint8Array, alg: number, kid?: T): HMACKey {
    if (assertBytes(secret, 'secret').length != getKeySize(alg)) {
      throw new Error(
        `cose-ts: HMACKey.fromSecret: secret size mismatch, expected ${getKeySize(
          alg
        )}, got ${secret.length}`
      )
    }

    const key = new HMACKey()
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

  mac(message: Uint8Array): Uint8Array {
    const hash = getHash(this.alg as number)
    const tag = hmac(hash, this.getSecretKey(), message)
    return tag.subarray(0, getTagSize(this.alg as number))
  }
}

function getKeySize(alg: number): number {
  switch (alg) {
    case iana.AlgorithmHMAC_256_64:
      return 32
    case iana.AlgorithmHMAC_256_256:
      return 32
    case iana.AlgorithmHMAC_384_384:
      return 48
    case iana.AlgorithmHMAC_512_512:
      return 64
    default:
      throw new Error(`cose-ts: unsupported HMAC alg ${alg}`)
  }
}

function getTagSize(alg: number): number {
  switch (alg) {
    case iana.AlgorithmHMAC_256_64:
      return 8
    case iana.AlgorithmHMAC_256_256:
      return 32
    case iana.AlgorithmHMAC_384_384:
      return 48
    case iana.AlgorithmHMAC_512_512:
      return 64
    default:
      throw new Error(`cose-ts: unsupported HMAC alg ${alg}`)
  }
}
