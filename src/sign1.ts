// (c) 2023-present, LDC Labs. All rights reserved.
// See the file LICENSE for licensing terms.

import { Header } from './header'
import { RawMap } from './map'
import { Key, type Verifier, Signer } from './key'
import * as iana from './iana'
import { decodeCBOR, encodeCBOR } from './utils'
import {
  skipTag,
  withTag,
  CwtPrefix,
  Sign1MessagePrefix,
  CBORSelfPrefix,
} from './tag'

// Sign1Message represents a COSE_Sign1 object.
//
// Reference https://datatracker.ietf.org/doc/html/rfc9052#name-signing-with-one-signer
export class Sign1Message {
  payload: Uint8Array
  protected: Header | null = null
  unprotected: Header | null = null

  private static signBytes(
    payload: Uint8Array,
    protectedHeader: Uint8Array,
    externalData?: Uint8Array
  ): Uint8Array {
    return encodeCBOR([
      'Signature1',
      protectedHeader,
      externalData ?? new Uint8Array(),
      payload,
    ])
  }

  static fromBytes(
    key: Key & Verifier,
    coseData: Uint8Array,
    externalData?: Uint8Array
  ): Sign1Message {
    const data = skipTag(
      Sign1MessagePrefix,
      skipTag(CwtPrefix, skipTag(CBORSelfPrefix, coseData))
    )

    const [protectedBytes, unprotected, payload, signature] = decodeCBOR(
      data
    ) as [Uint8Array, RawMap, Uint8Array, Uint8Array]
    const protectedHeader = Header.fromBytes(protectedBytes)
    const unprotectedHeader = new Header(unprotected)
    if (protectedHeader.has(iana.HeaderParameterAlg)) {
      const alg = protectedHeader.getInt(iana.HeaderParameterAlg)
      if (alg !== key.alg) {
        throw new Error(
          `cose-ts: Sign1Message.fromBytes: alg mismatch, expected ${alg}, got ${key.alg}`
        )
      }
    }

    if (
      !key.verify(
        Sign1Message.signBytes(payload, protectedBytes, externalData),
        signature
      )
    ) {
      throw new Error('cose-ts: Sign1Message.fromBytes: signature mismatch')
    }

    return new Sign1Message(payload, protectedHeader, unprotectedHeader)
  }

  static withTag(coseData: Uint8Array): Uint8Array {
    return withTag(Sign1MessagePrefix, coseData)
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

  toBytes(key: Key & Signer, externalData?: Uint8Array): Uint8Array {
    if (this.protected == null) {
      this.protected = new Header()
      if (key.has(iana.KeyParameterAlg)) {
        this.protected.setParam(iana.HeaderParameterAlg, key.alg)
      }
    } else if (this.protected.has(iana.HeaderParameterAlg)) {
      const alg = this.protected.getInt(iana.HeaderParameterAlg)
      if (alg !== key.alg) {
        throw new Error(
          `cose-ts: Sign1Message.toBytes: alg mismatch, expected ${alg}, got ${key.alg}`
        )
      }
    }

    if (this.unprotected == null) {
      this.unprotected = new Header()
      if (key.has(iana.KeyParameterKid)) {
        this.unprotected.setParam(iana.HeaderParameterKid, key.kid)
      }
    }

    const protectedBytes = this.protected.toBytes()
    const sig = key.sign(
      Sign1Message.signBytes(this.payload, protectedBytes, externalData)
    )

    return encodeCBOR([
      protectedBytes,
      this.unprotected.toRaw(),
      this.payload,
      sig,
    ])
  }
}
