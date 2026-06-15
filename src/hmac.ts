// (c) 2023-present, LDC Labs. All rights reserved.
// See the file LICENSE for licensing terms.

import * as iana from './iana'
import { RawMap, assertBytes } from './map'
import { Key, type MACer } from './key'
import { randomBytes, decodeCBOR } from './utils'
import { hmac, getHash } from './hash'

// TODO: more checks
/**
 * HMACKey implements the HMAC message authentication code algorithm for COSE,
 * as defined in RFC 9053. Use it with {@link Mac0Message} or {@link MacMessage}.
 *
 * Construction signature: `generate(alg, kid?)`, but note that `fromSecret`
 * takes the algorithm as its SECOND argument: `fromSecret(secret, alg, kid?)`.
 * This ordering differs from the other key types — see the key-construction
 * cheat sheet in `docs/agent-guide.md`.
 *
 * @example
 * ```ts
 * const key = HMACKey.generate(iana.AlgorithmHMAC_256_256)
 * const cose = new Mac0Message(payload).toBytes(key)
 * Mac0Message.fromBytes(key, cose)
 * ```
 *
 * @see https://datatracker.ietf.org/doc/html/rfc9053#name-hash-based-message-authenti
 */
export class HMACKey extends Key implements MACer {
  /** Decodes a COSE_Key from CBOR bytes into an HMACKey. */
  static fromBytes(data: Uint8Array): HMACKey {
    return new HMACKey(decodeCBOR(data))
  }

  /**
   * Generates a new random HMAC key for the given algorithm.
   *
   * @param alg - The HMAC algorithm, e.g. `iana.AlgorithmHMAC_256_256`,
   *   `iana.AlgorithmHMAC_384_384`, or `iana.AlgorithmHMAC_512_512`.
   * @param kid - Optional key id.
   */
  static generate<T>(alg: number, kid?: T): HMACKey {
    return HMACKey.fromSecret(randomBytes(getKeySize(alg)), alg, kid)
  }

  /**
   * Imports an HMAC key from raw bytes.
   *
   * Note: unlike the other key types, the algorithm is the SECOND parameter
   * (not the kid). The secret length must match the algorithm: HMAC 256/64 and
   * 256/256 = 32 bytes, 384/384 = 48 bytes, 512/512 = 64 bytes.
   *
   * @param secret - The raw HMAC key bytes.
   * @param alg - The HMAC algorithm, e.g. `iana.AlgorithmHMAC_256_256`.
   * @param kid - Optional key id.
   */
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
    // The same primitive is used both to create and to verify a tag, so accept
    // a key authorized for either MAC operation.
    this.verifyOps(iana.KeyOperationMacCreate, iana.KeyOperationMacVerify)
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
