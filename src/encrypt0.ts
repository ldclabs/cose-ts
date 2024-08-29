// (c) 2023-present, LDC Labs. All rights reserved.
// See the file LICENSE for licensing terms.

import { randomBytes } from './utils'
import { Header } from './header'
import { RawMap } from './map'
import { Key, type Encryptor } from './key'
import * as iana from './iana'
import { decodeCBOR, encodeCBOR } from './utils'
import {
  skipTag,
  withTag,
  CwtPrefix,
  Encrypt0MessagePrefix,
  CBORSelfPrefix
} from './tag'

// Encrypt0Message represents a COSE_Encrypt0 object.
//
// Reference https://datatracker.ietf.org/doc/html/rfc9052#name-single-recipient-encrypted.
export class Encrypt0Message {
  payload: Uint8Array
  // protected header parameters: iana.HeaderParameterAlg, iana.HeaderParameterCrit.
  protected: Header | null = null
  // Other header parameters.
  unprotected: Header | null = null

  private static encBytes(
    protectedHeader: Uint8Array,
    externalData?: Uint8Array
  ): Uint8Array {
    return encodeCBOR([
      'Encrypt0',
      protectedHeader,
      externalData ?? new Uint8Array()
    ])
  }

  static async fromBytes(
    key: Key & Encryptor,
    coseData: Uint8Array,
    externalData?: Uint8Array
  ): Promise<Encrypt0Message> {
    const data = skipTag(
      Encrypt0MessagePrefix,
      skipTag(CwtPrefix, skipTag(CBORSelfPrefix, coseData))
    )

    const [protectedBytes, unprotected, ciphertext] = decodeCBOR(data) as [
      Uint8Array,
      RawMap,
      Uint8Array
    ]
    const protectedHeader = Header.fromBytes(protectedBytes)
    const unprotectedHeader = new Header(unprotected)
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
      Encrypt0Message.encBytes(protectedBytes, externalData)
    )

    return new Encrypt0Message(plaintext, protectedHeader, unprotectedHeader)
  }

  static withTag(coseData: Uint8Array): Uint8Array {
    return withTag(Encrypt0MessagePrefix, coseData)
  }

  constructor(
    payload: Uint8Array,
    protectedHeader?: Header,
    unprotected?: Header
  ) {
    this.payload = payload
    this.protected = protectedHeader
      ? new Header(protectedHeader.toRaw())
      : null
    this.unprotected = unprotected ? new Header(unprotected.toRaw()) : null
  }

  async toBytes(
    key: Key & Encryptor,
    externalData?: Uint8Array
  ): Promise<Uint8Array> {
    if (this.protected == null) {
      this.protected = new Header()
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
      this.unprotected = new Header()
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
      Encrypt0Message.encBytes(protectedBytes, externalData)
    )

    return encodeCBOR([protectedBytes, this.unprotected.toRaw(), ciphertext])
  }
}
