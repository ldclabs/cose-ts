// (c) 2023-present, LDC Labs. All rights reserved.
// See the file LICENSE for licensing terms.

import { chacha20poly1305 } from '@noble/ciphers/chacha.js'
import * as iana from './iana'
import { Key, type Encryptor } from './key'
import { RawMap, assertBytes } from './map'
import { decodeCBOR, randomBytes } from './utils'

// TODO: more checks
/**
 * ChaCha20Poly1305Key implements the ChaCha20/Poly1305 content encryption
 * algorithm for COSE, as defined in RFC 9053. Use it as the content key with
 * {@link Encrypt0Message} or {@link EncryptMessage}.
 *
 * Construction signature: `generate(kid?)` — the algorithm is fixed, so the
 * first argument is the optional key id, not the algorithm. The key is always
 * 32 bytes.
 *
 * @example
 * ```ts
 * const key = ChaCha20Poly1305Key.generate()
 * const cose = await new Encrypt0Message(payload).toBytes(key)
 * const out = await Encrypt0Message.fromBytes(key, cose)
 * ```
 *
 * @see https://datatracker.ietf.org/doc/html/rfc9053#name-chacha20-and-poly1305
 */
export class ChaCha20Poly1305Key extends Key implements Encryptor {
  /** Decodes a COSE_Key from CBOR bytes into a ChaCha20Poly1305Key. */
  static fromBytes(data: Uint8Array): ChaCha20Poly1305Key {
    return new ChaCha20Poly1305Key(decodeCBOR(data))
  }

  /**
   * Generates a new random ChaCha20/Poly1305 key (32 bytes).
   *
   * @param kid - Optional key id.
   */
  static generate<T>(kid?: T): ChaCha20Poly1305Key {
    return ChaCha20Poly1305Key.fromSecret(randomBytes(32), kid)
  }

  /**
   * Imports a ChaCha20/Poly1305 key from raw bytes.
   *
   * @param secret - The 32-byte key.
   * @param kid - Optional key id.
   */
  static fromSecret<T>(secret: Uint8Array, kid?: T): ChaCha20Poly1305Key {
    assertBytes(secret, 'secret')
    if (secret.length !== 32) {
      throw new Error(
        `cose-ts: ChaCha20Poly1305Key.fromSecret: secret size mismatch, expected 32, got ${secret.length}`
      )
    }
    const key = new ChaCha20Poly1305Key()
    if (kid != null) {
      key.setKid(kid)
    }
    key.setParam(iana.SymmetricKeyParameterK, secret)
    return key
  }

  constructor(kv?: RawMap) {
    super(kv)

    this.kty = iana.KeyTypeSymmetric
    this.alg = iana.AlgorithmChaCha20Poly1305
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
    const cipher = chacha20poly1305(this.getSecretKey(), nonce, aad)
    return Promise.resolve(cipher.encrypt(plaintext))
  }

  async decrypt(
    ciphertext: Uint8Array,
    nonce: Uint8Array,
    aad?: Uint8Array
  ): Promise<Uint8Array> {
    this.verifyOps(iana.KeyOperationDecrypt)
    const cipher = chacha20poly1305(this.getSecretKey(), nonce, aad)
    return Promise.resolve(cipher.decrypt(ciphertext))
  }
}
