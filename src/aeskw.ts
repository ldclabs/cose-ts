// (c) 2023-present, LDC Labs. All rights reserved.
// See the file LICENSE for licensing terms.

import { aeskw } from '@noble/ciphers/aes.js'
import * as iana from './iana'
import { Key, type KeyWrapper } from './key'
import { RawMap, assertBytes } from './map'
import { decodeCBOR, randomBytes } from './utils'

/**
 * AesKwKey implements the AES Key Wrap content-key distribution method for
 * COSE, as defined in RFC 9053. Use it as a recipient key-encryption key (KEK)
 * via `Recipient.keyWrap(kek)` with {@link EncryptMessage} or {@link MacMessage}.
 *
 * Construction signature: `generate(alg, kid?)` — the first argument is the
 * algorithm (`A128KW`/`A192KW`/`A256KW`), which selects the key size.
 *
 * @example
 * ```ts
 * const kek = AesKwKey.generate(iana.AlgorithmA256KW, 'recipient-1')
 * const cose = await new EncryptMessage(payload, undefined, undefined, [
 *   Recipient.keyWrap(kek)
 * ]).toBytes(cek)
 * const out = await EncryptMessage.fromBytes([kek], cose)
 * ```
 *
 * @see https://datatracker.ietf.org/doc/html/rfc9053#name-aes-key-wrap
 */
export class AesKwKey extends Key implements KeyWrapper {
  /** Decodes a COSE_Key from CBOR bytes into an AesKwKey. */
  static fromBytes(data: Uint8Array): AesKwKey {
    return new AesKwKey(decodeCBOR(data))
  }

  /**
   * Generates a new random AES-KW key-encryption key for the given algorithm.
   *
   * @param alg - The AES-KW algorithm: `iana.AlgorithmA128KW`,
   *   `iana.AlgorithmA192KW`, or `iana.AlgorithmA256KW`.
   * @param kid - Optional key id.
   */
  static generate<T>(alg: number, kid?: T): AesKwKey {
    return AesKwKey.fromSecret(randomBytes(getKeySize(alg)), kid)
  }

  /**
   * Imports an AES-KW key from raw bytes. The algorithm is inferred from the
   * key length (16 → A128KW, 24 → A192KW, 32 → A256KW).
   *
   * @param secret - The raw key bytes (16, 24, or 32 bytes).
   * @param kid - Optional key id.
   */
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
