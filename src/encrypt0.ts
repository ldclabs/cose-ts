// (c) 2023-present, LDC Labs. All rights reserved.
// See the file LICENSE for licensing terms.

import { randomBytes } from '@noble/ciphers/webcrypto/utils'
import { KVMap, RawMap } from './map'
import { Key, type Encryptor } from './key'
import * as iana from './iana'
import { decode, encode } from './utils'
import { skipTag, CwtPrefix, Encrypt0MessagePrefix } from './tag'

export class Encrypt0Message {
  payload: Uint8Array
  protected: KVMap | null = null
  unprotected: KVMap | null = null

  private static toEnc(
    protectedHeader: Uint8Array,
    externalData?: Uint8Array
  ): Uint8Array {
    return encode([
      'Encrypt0',
      protectedHeader,
      externalData ?? new Uint8Array(),
    ])
  }

  static async fromBytes(
    key: Key & Encryptor,
    coseData: Uint8Array,
    externalData?: Uint8Array
  ): Promise<Encrypt0Message> {
    let data = skipTag(coseData, CwtPrefix)
    data = skipTag(data, Encrypt0MessagePrefix)

    const [protectedBytes, unprotected, ciphertext] = decode(data) as [
      Uint8Array,
      RawMap,
      Uint8Array
    ]
    const protectedHeader = KVMap.fromBytes(protectedBytes)
    const unprotectedHeader = new KVMap(unprotected)
    if (protectedHeader.has(iana.HeaderParameterAlg)) {
      const alg = protectedHeader.getInt(iana.HeaderParameterAlg)
      if (alg !== key.alg) {
        throw new Error(
          `cose-ts: Encrypt0Message.fromBytes: alg mismatch, expected ${alg}, got ${key.alg}`
        )
      }
    }

    const ivSize = key.nonceSize()
    // TODO: support partial iv
    const iv = unprotectedHeader.getBytes(iana.HeaderParameterIV)
    if (iv.length !== ivSize) {
      throw new Error(
        `cose-ts: Encrypt0Message.fromBytes: iv size mismatch, expected ${ivSize}, got ${iv.length}`
      )
    }

    const plaintext = await key.decrypt(
      ciphertext,
      iv,
      Encrypt0Message.toEnc(protectedBytes, externalData)
    )

    return new Encrypt0Message(plaintext, protectedHeader, unprotectedHeader)
  }

  static withTag(coseData: Uint8Array): Uint8Array {
    const data = new Uint8Array(
      coseData.length + Encrypt0MessagePrefix.length - 1
    )
    data.set(Encrypt0MessagePrefix)
    data.set(coseData.subarray(1), Encrypt0MessagePrefix.length)
    return data
  }

  constructor(
    payload: Uint8Array,
    protectedHeader?: KVMap,
    unprotected?: KVMap
  ) {
    this.payload = payload
    this.protected = protectedHeader ?? null
    this.unprotected = unprotected ?? null
  }

  async toBytes(
    key: Key & Encryptor,
    externalData?: Uint8Array
  ): Promise<Uint8Array> {
    if (this.protected == null) {
      this.protected = new KVMap()
      if (key.has(iana.KeyParameterAlg)) {
        this.protected.setParam(iana.HeaderParameterAlg, key.alg)
      }
    } else if (this.protected.has(iana.HeaderParameterAlg)) {
      const alg = this.protected.getInt(iana.HeaderParameterAlg)
      if (alg !== key.alg) {
        throw new Error(
          `cose-ts: Encrypt0Message.toBytes: alg mismatch, expected ${alg}, got ${key.alg}`
        )
      }
    }

    if (this.unprotected == null) {
      this.unprotected = new KVMap()
      if (key.has(iana.KeyParameterKid)) {
        this.unprotected.setParam(iana.HeaderParameterKid, key.kid)
      }
    }

    const ivSize = key.nonceSize()
    // TODO: support partial iv
    if (!this.unprotected.has(iana.HeaderParameterIV)) {
      this.unprotected.setParam(iana.HeaderParameterIV, randomBytes(ivSize))
    }
    const iv = this.unprotected.getBytes(iana.HeaderParameterIV)
    if (iv.length !== ivSize) {
      throw new Error(
        `cose-ts: Encrypt0Message.toBytes: iv size mismatch, expected ${ivSize}, got ${iv.length}`
      )
    }

    const protectedBytes = this.protected.toBytes()
    const ciphertext = await key.encrypt(
      this.payload,
      iv,
      Encrypt0Message.toEnc(protectedBytes, externalData)
    )

    return encode([protectedBytes, this.unprotected.toRaw(), ciphertext])
  }
}
