// (c) 2023-present, LDC Labs. All rights reserved.
// See the file LICENSE for licensing terms.

import { chacha20poly1305 } from '@noble/ciphers/chacha'
import * as iana from './iana'
import { RawMap, assertBytes } from './map'
import { Key, type Encryptor } from './key'
import { randomBytes, decodeCBOR } from './utils'

// TODO: more checks
// ChaCha20Poly1305Key implements content encryption algorithm ChaCha20/Poly1305 for COSE as defined in RFC9053.
// https://datatracker.ietf.org/doc/html/rfc9053#name-chacha20-and-poly1305.
export class ChaCha20Poly1305Key extends Key implements Encryptor {
  static fromBytes(data: Uint8Array): ChaCha20Poly1305Key {
    return new ChaCha20Poly1305Key(decodeCBOR(data))
  }

  static generate<T>(kid?: T): ChaCha20Poly1305Key {
    return ChaCha20Poly1305Key.fromSecret(randomBytes(32), kid)
  }

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
    const cipher = chacha20poly1305(this.getSecretKey(), nonce, aad)
    return Promise.resolve(cipher.encrypt(plaintext))
  }

  async decrypt(
    ciphertext: Uint8Array,
    nonce: Uint8Array,
    aad?: Uint8Array
  ): Promise<Uint8Array> {
    const cipher = chacha20poly1305(this.getSecretKey(), nonce, aad)
    return Promise.resolve(cipher.decrypt(ciphertext))
  }
}
