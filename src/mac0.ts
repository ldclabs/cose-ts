// (c) 2023-present, LDC Labs. All rights reserved.
// See the file LICENSE for licensing terms.

import { Header, verifyHeaders } from './header'
import { RawMap, assertIntOrText } from './map'
import { Key, type MACer } from './key'
import * as iana from './iana'
import { decodeCBOR, encodeCBOR, equalBytes } from './utils'
import {
  skipTag,
  withTag,
  CwtPrefix,
  Mac0MessagePrefix,
  CBORSelfPrefix
} from './tag'

// Mac0Message represents a COSE_Mac0 object.
//
// Use this structure when the MAC key is known implicitly. The tag covers the
// protected header bytes, optional externalData, and payload through the RFC
// 9052 MAC_structure.
//
// Reference https://datatracker.ietf.org/doc/html/rfc9052#name-maced-messages-with-implici.
export class Mac0Message {
  payload: Uint8Array
  // protected header parameters: iana.HeaderParameterAlg, iana.HeaderParameterCrit.
  protected: Header | null = null
  // Other header parameters.
  unprotected: Header | null = null

  private static macBytes(
    payload: Uint8Array,
    protectedHeader: Uint8Array,
    externalData?: Uint8Array
  ): Uint8Array {
    return encodeCBOR([
      'MAC0',
      protectedHeader,
      externalData ?? new Uint8Array(),
      payload
    ])
  }

  static fromBytes(
    key: Key & MACer,
    coseData: Uint8Array,
    externalData?: Uint8Array
  ): Mac0Message {
    const data = skipTag(
      Mac0MessagePrefix,
      skipTag(CwtPrefix, skipTag(CBORSelfPrefix, coseData))
    )

    const [protectedBytes, unprotected, payload, tag] = decodeCBOR(data) as [
      Uint8Array,
      RawMap,
      Uint8Array,
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
          `cose-ts: Mac0Message.fromBytes: alg mismatch, expected ${alg}, got ${key.alg}`
        )
      }
    }

    const t = key.mac(
      Mac0Message.macBytes(payload, protectedBytes, externalData)
    )
    if (!equalBytes(tag, t)) {
      throw new Error('cose-ts: Mac0Message.fromBytes: tag mismatch')
    }

    return new Mac0Message(payload, protectedHeader, unprotectedHeader)
  }

  static withTag(coseData: Uint8Array): Uint8Array {
    return withTag(Mac0MessagePrefix, coseData)
  }

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

  toBytes(key: Key & MACer, externalData?: Uint8Array): Uint8Array {
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
          `cose-ts: Mac0Message.toBytes: alg mismatch, expected ${alg}, got ${key.alg}`
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

    const protectedBytes = this.protected.toBytes()
    const tag = key.mac(
      Mac0Message.macBytes(this.payload, protectedBytes, externalData)
    )

    return encodeCBOR([
      protectedBytes,
      this.unprotected.toRaw(),
      this.payload,
      tag
    ])
  }
}
