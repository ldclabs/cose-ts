// (c) 2023-present, LDC Labs. All rights reserved.
// See the file LICENSE for licensing terms.

import { gcm } from '@noble/ciphers/webcrypto.js'
import * as iana from './iana'
import { Key, type Encryptor } from './key'
import { RawMap, assertBytes } from './map'
import { decodeCBOR, randomBytes } from './utils'

// TODO: more checks
/**
 * AesGcmKey implements the AES-GCM content encryption algorithm for COSE, as
 * defined in RFC 9053. Use it as the content key with {@link Encrypt0Message}
 * or {@link EncryptMessage}.
 *
 * Construction signature: `generate(alg, kid?)` — the first argument is the
 * algorithm (`A128GCM`/`A192GCM`/`A256GCM`), which selects the key size.
 *
 * @example
 * ```ts
 * const key = AesGcmKey.generate(iana.AlgorithmA128GCM)
 * const cose = await new Encrypt0Message(payload).toBytes(key)
 * const out = await Encrypt0Message.fromBytes(key, cose)
 * ```
 *
 * @see https://datatracker.ietf.org/doc/html/rfc9053#name-aes-gcm
 */
export class AesGcmKey extends Key implements Encryptor {
  /** Decodes a COSE_Key from CBOR bytes into an AesGcmKey. */
  static fromBytes(data: Uint8Array): AesGcmKey {
    return new AesGcmKey(decodeCBOR(data))
  }

  /**
   * Generates a new random AES-GCM key for the given algorithm.
   *
   * @param alg - The AES-GCM algorithm: `iana.AlgorithmA128GCM`,
   *   `iana.AlgorithmA192GCM`, or `iana.AlgorithmA256GCM`.
   * @param kid - Optional key id.
   */
  static generate<T>(alg: number, kid?: T): AesGcmKey {
    return AesGcmKey.fromSecret(randomBytes(getKeySize(alg)), kid)
  }

  /**
   * Imports an AES-GCM key from raw bytes. The algorithm is inferred from the
   * key length (16 → A128GCM, 24 → A192GCM, 32 → A256GCM).
   *
   * @param secret - The raw key bytes (16, 24, or 32 bytes).
   * @param kid - Optional key id.
   */
  static fromSecret<T>(secret: Uint8Array, kid?: T): AesGcmKey {
    const alg = getAlg(assertBytes(secret, 'secret'))
    const key = new AesGcmKey()
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

  nonceSize(): number {
    return 12
  }

  getSecretKey(): Uint8Array {
    return this.getBytes(iana.SymmetricKeyParameterK, 'k')
  }

  async encrypt(
    plaintext: Uint8Array,
    nonce: Uint8Array,
    aad?: Uint8Array
  ): Promise<Uint8Array> {
    this.verifyOps(iana.KeyOperationEncrypt)
    const cipher = gcm(this.getSecretKey(), nonce, aad)
    return cipher.encrypt(plaintext)
  }

  async decrypt(
    ciphertext: Uint8Array,
    nonce: Uint8Array,
    aad?: Uint8Array
  ): Promise<Uint8Array> {
    this.verifyOps(iana.KeyOperationDecrypt)
    const cipher = gcm(this.getSecretKey(), nonce, aad)
    return cipher.decrypt(ciphertext)
  }
}

function getKeySize(alg: number): number {
  switch (alg) {
    case iana.AlgorithmA128GCM:
      return 16
    case iana.AlgorithmA192GCM:
      return 24
    case iana.AlgorithmA256GCM:
      return 32
    default:
      throw new Error(`cose-ts: unsupported AES-GCM alg ${alg}`)
  }
}

function getAlg(key: Uint8Array): number {
  switch (key.length) {
    case 16:
      return iana.AlgorithmA128GCM
    case 24:
      return iana.AlgorithmA192GCM
    case 32:
      return iana.AlgorithmA256GCM
    default:
      throw new Error(`cose-ts: unsupported AES-GCM key length ${key.length}`)
  }
}
