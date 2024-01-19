// (c) 2023-present, LDC Labs. All rights reserved.
// See the file LICENSE for licensing terms.

import { gcm } from '@noble/ciphers/webcrypto/aes'
import * as iana from './iana'
import { RawMap, assertBytes } from './map'
import { Key, type Encryptor } from './key'
import { randomBytes } from './utils'

// TODO: more checks
// AesGcmKey implements content encryption algorithm AES-GCM for COSE as defined in RFC9053.
// https://datatracker.ietf.org/doc/html/rfc9053#name-aes-gcm.
export class AesGcmKey extends Key implements Encryptor {
  static generate(alg: number, kid?: Uint8Array): AesGcmKey {
    return AesGcmKey.fromSecret(randomBytes(getKeySize(alg)), kid)
  }

  static fromSecret(secret: Uint8Array, kid?: Uint8Array): AesGcmKey {
    const alg = getAlg(assertBytes(secret, 'secret'))
    const key = new AesGcmKey()
    key.alg = alg
    if (kid) {
      key.kid = kid
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
