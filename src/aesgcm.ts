// (c) 2023-present, LDC Labs. All rights reserved.
// See the file LICENSE for licensing terms.

import { randomBytes } from '@noble/ciphers/webcrypto/utils'
import { utf8ToBytes } from '@noble/ciphers/utils'
import { gcm } from '@noble/ciphers/webcrypto/aes'
import * as iana from './iana'
import { RawMap, assertBytes } from './map'
import { Key, type Encryptor } from './key'

export class AesGcmKey extends Key implements Encryptor {
  static generate(alg: number, kid?: string): AesGcmKey {
    const key = new AesGcmKey()
    key.kty = iana.KeyTypeSymmetric
    key.alg = alg
    if (kid) {
      key.kid = utf8ToBytes(kid)
    }
    key.setParam(iana.SymmetricKeyParameterK, randomBytes(getKeySize(alg)))
    return key
  }

  static fromSecret(secret: Uint8Array, kid?: string): AesGcmKey {
    const alg = getAlg(assertBytes(secret, 'secret'))
    const key = new AesGcmKey()
    key.kty = iana.KeyTypeSymmetric
    key.alg = alg
    if (kid) {
      key.kid = utf8ToBytes(kid)
    }
    key.setParam(iana.SymmetricKeyParameterK, secret)
    return key
  }

  constructor(kv?: RawMap) {
    super(kv)
  }

  nonceSize(): number {
    return 12
  }

  getSecretKey(): Uint8Array {
    // TODO: more checks
    // https://datatracker.ietf.org/doc/html/rfc9053#name-aes-gcm.
    return this.getBytes(iana.SymmetricKeyParameterK, 'k')
  }

  async encrypt(
    plaintext: Uint8Array,
    nonce: Uint8Array,
    aad?: Uint8Array
  ): Promise<Uint8Array> {
    const cipher = gcm(this.getSecretKey(), nonce, aad)
    return cipher.encrypt(plaintext)
  }

  async decrypt(
    ciphertext: Uint8Array,
    nonce: Uint8Array,
    aad?: Uint8Array
  ): Promise<Uint8Array> {
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
