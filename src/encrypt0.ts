// (c) 2023-present, LDC Labs. All rights reserved.
// See the file LICENSE for licensing terms.

import { randomBytes } from './utils'
import { Header, verifyHeaders } from './header'
import { RawMap, assertIntOrText } from './map'
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

/**
 * Encrypt0Message represents a COSE_Encrypt0 object.
 *
 * Use this structure when the recipient already knows the content encryption
 * key. The protected header bytes and optional externalData are authenticated
 * as AEAD additional data.
 *
 * @example
 * ```ts
 * const key = AesGcmKey.generate(iana.AlgorithmA128GCM)
 * const aad = utf8ToBytes('profile:v1')
 * const cose = await new Encrypt0Message(plaintext).toBytes(key, aad)
 * const decrypted = await Encrypt0Message.fromBytes(key, cose, aad)
 * ```
 *
 * Reference https://datatracker.ietf.org/doc/html/rfc9052#name-single-recipient-encrypted.
 */
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
    verifyHeaders(protectedHeader, unprotectedHeader)
    if (protectedHeader.has(iana.HeaderParameterAlg)) {
      const alg = protectedHeader.getType(
        iana.HeaderParameterAlg,
        assertIntOrText,
        'alg'
      )
      if (alg !== key.alg) {
        throw new Error(
          `cose-ts: Encrypt0Message.fromBytes: alg mismatch, expected ${alg}, got ${key.alg}`
        )
      }
    }

    assertIVParams(protectedHeader, unprotectedHeader, 'fromBytes')

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

  /**
   * @param payload - The plaintext bytes to encrypt.
   * @param protectedHeader - Optional protected (authenticated) header. When
   *   omitted, `toBytes` creates one and sets `alg` from the content key.
   * @param unprotected - Optional unprotected header. `toBytes` puts the
   *   generated IV here unless one is already set.
   */
  constructor(
    payload: Uint8Array,
    protectedHeader?: Header,
    unprotected?: Header
  ) {
    this.payload = payload
    this.protected = protectedHeader
      ? new Header(protectedHeader.clone())
      : null
    this.unprotected = unprotected ? new Header(unprotected.clone()) : null
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
      const alg = this.protected.getType(
        iana.HeaderParameterAlg,
        assertIntOrText,
        'alg'
      )
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

    verifyHeaders(this.protected, this.unprotected)
    assertIVParams(this.protected, this.unprotected, 'toBytes')

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

// assertIVParams enforces the IV rules from RFC 9052 §3.1: the full IV and the
// Partial IV header parameters MUST NOT both be present in the same layer.
// Partial IV is not supported yet, so its presence is rejected outright.
function assertIVParams(
  protectedHeader: Header,
  unprotectedHeader: Header,
  fn: string
): void {
  const hasPartialIV =
    protectedHeader.has(iana.HeaderParameterPartialIV) ||
    unprotectedHeader.has(iana.HeaderParameterPartialIV)

  if (hasPartialIV) {
    throw new Error(
      `cose-ts: Encrypt0Message.${fn}: Partial IV is not supported`
    )
  }
}
