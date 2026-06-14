// (c) 2023-present, LDC Labs. All rights reserved.
// See the file LICENSE for licensing terms.

import { Header, verifyHeaders } from './header'
import { RawMap, Value, assertIntOrText } from './map'
import { Key, type KeyWrapper } from './key'
import * as iana from './iana'

// Recipient represents a COSE_recipient structure used by COSE_Encrypt and
// COSE_Mac to carry the (optionally encrypted) content encryption key for a
// recipient.
//
// Reference https://datatracker.ietf.org/doc/html/rfc9052#name-enveloped-cose-structure.
export class Recipient {
  protected: Header | null
  unprotected: Header | null
  ciphertext: Uint8Array
  recipients: Recipient[]
  // key is the key encryption key (KEK) used to wrap the content encryption key
  // for this recipient. It is not part of the serialized structure.
  key: (Key & KeyWrapper) | null

  // direct creates a recipient for the direct content key distribution method
  // (RFC 9052 §8.5.1): the content encryption key is the preshared secret and
  // no key is transported.
  static direct(kid?: Uint8Array): Recipient {
    const unprotected = new Header().setParam(
      iana.HeaderParameterAlg,
      iana.AlgorithmDirect
    )
    if (kid) {
      unprotected.setParam(iana.HeaderParameterKid, kid)
    }
    return new Recipient(undefined, unprotected)
  }

  // keyWrap creates a recipient for the AES Key Wrap content key distribution
  // method (RFC 9052 §8.5.2). The "alg" header parameter is taken from the KEK.
  static keyWrap(kek: Key & KeyWrapper, kid?: Uint8Array): Recipient {
    const unprotected = new Header().setParam(iana.HeaderParameterAlg, kek.alg)
    if (kid) {
      unprotected.setParam(iana.HeaderParameterKid, kid)
    } else if (kek.has(iana.KeyParameterKid)) {
      unprotected.setParam(iana.HeaderParameterKid, kek.kid)
    }
    const r = new Recipient(undefined, unprotected)
    r.key = kek
    return r
  }

  static fromCBORValue(value: unknown): Recipient {
    const v = value as Value[]
    if (!Array.isArray(v) || (v.length !== 3 && v.length !== 4)) {
      throw new Error('cose-ts: Recipient.fromCBORValue: invalid recipient')
    }

    const protectedHeader = Header.fromBytes(v[0] as Uint8Array)
    const unprotectedHeader = new Header(v[1] as RawMap)
    verifyHeaders(protectedHeader, unprotectedHeader)

    const r = new Recipient(protectedHeader, unprotectedHeader)
    r.ciphertext = v[2] as Uint8Array
    if (v.length === 4) {
      const nested = v[3] as unknown[]
      if (!Array.isArray(nested) || nested.length === 0) {
        throw new Error(
          'cose-ts: Recipient.fromCBORValue: invalid nested recipients'
        )
      }
      r.recipients = nested.map((n) => Recipient.fromCBORValue(n))
    }
    return r
  }

  constructor(protectedHeader?: Header, unprotected?: Header) {
    this.protected = protectedHeader
      ? new Header(protectedHeader.toRaw())
      : null
    this.unprotected = unprotected ? new Header(unprotected.toRaw()) : null
    this.ciphertext = new Uint8Array()
    this.recipients = []
    this.key = null
  }

  // alg returns the recipient algorithm, preferring the protected bucket.
  alg(): number | string | undefined {
    if (this.protected?.has(iana.HeaderParameterAlg)) {
      return this.protected.getType(
        iana.HeaderParameterAlg,
        assertIntOrText,
        'alg'
      )
    }
    if (this.unprotected?.has(iana.HeaderParameterAlg)) {
      return this.unprotected.getType(
        iana.HeaderParameterAlg,
        assertIntOrText,
        'alg'
      )
    }
    return undefined
  }

  // encode wraps the content encryption key as required by the recipient
  // algorithm and returns the CBOR array form of the COSE_recipient.
  encode(cek: Uint8Array): Value[] {
    const alg = this.alg()
    if (alg === iana.AlgorithmDirect) {
      this.ciphertext = new Uint8Array()
    } else if (this.key) {
      this.ciphertext = this.key.wrapKey(cek)
    }

    const protectedBytes = this.protected
      ? this.protected.toBytes()
      : new Uint8Array()
    const unprotected = (this.unprotected ?? new Header()).toRaw()
    const arr: Value[] = [protectedBytes, unprotected, this.ciphertext]
    if (this.recipients.length > 0) {
      arr.push(this.recipients.map((r) => r.encode(cek)))
    }
    return arr
  }

  // recoverCEK recovers the content encryption key for this recipient using the
  // provided KEK. For the direct method the KEK's own secret is returned.
  recoverCEK(kek: Key & Partial<KeyWrapper>): Uint8Array {
    const alg = this.alg()
    if (alg === iana.AlgorithmDirect) {
      return kek.getSecret()
    }
    if (typeof kek.unwrapKey !== 'function') {
      throw new Error(
        'cose-ts: Recipient.recoverCEK: key cannot unwrap the content key'
      )
    }
    return kek.unwrapKey(this.ciphertext)
  }
}
