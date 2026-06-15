// (c) 2023-present, LDC Labs. All rights reserved.
// See the file LICENSE for licensing terms.

import { Header, verifyHeaders } from './header'
import { RawMap, Value, assertBytes, assertIntOrText } from './map'
import { Key, type KeyWrapper } from './key'
import * as iana from './iana'

// Recipient represents a COSE_recipient structure used by COSE_Encrypt and
// COSE_Mac to carry the content encryption/MAC key for a recipient.
//
// This class currently provides construction and recovery helpers for the two
// modes used by the message helpers:
//   - direct: the caller-provided key is the content key; no key bytes are
//     transported in the recipient.
//   - AES-KW: the content key is wrapped by a recipient key-encryption key.
//
// Unsupported recipient algorithms can be parsed and kept in the object graph,
// but recoverCEK() only works for the supported helper modes.
//
// Reference https://datatracker.ietf.org/doc/html/rfc9052#name-enveloped-cose-structure.
export class Recipient {
  protected: Header | null
  unprotected: Header | null
  ciphertext: Uint8Array | null
  recipients: Recipient[]
  // key is the key-encryption key (KEK) used to wrap the content key for this
  // recipient. It is local-only state and is never serialized.
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
  // If the KEK has a kid, it is copied as an unprotected key-selection hint.
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
    r.ciphertext =
      v[2] === null ? null : assertBytes(v[2], 'recipient ciphertext')
    if (v.length === 4) {
      const nested = v[3] as unknown[]
      if (!Array.isArray(nested) || nested.length === 0) {
        throw new Error(
          'cose-ts: Recipient.fromCBORValue: invalid nested recipients'
        )
      }
      r.recipients = nested.map((n) => Recipient.fromCBORValue(n))
    }
    validateRecipientForAlg(r, 'fromCBORValue')
    return r
  }

  constructor(protectedHeader?: Header, unprotected?: Header) {
    this.protected = protectedHeader
      ? new Header(protectedHeader.clone())
      : null
    this.unprotected = unprotected ? new Header(unprotected.clone()) : null
    this.ciphertext = new Uint8Array()
    this.recipients = []
    this.key = null
  }

  // alg returns the recipient algorithm, preferring the protected bucket as
  // required by RFC 9052 header processing.
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

  // encode wraps the content key as required by this recipient algorithm and
  // returns the CBOR array form of COSE_recipient.
  //
  // The input is the CEK/MAC key from the next layer down. Direct recipients
  // leave it untransported; AES-KW recipients wrap it with this.key.
  encode(cek: Uint8Array): Value[] {
    const protectedHeader = this.protected ?? new Header()
    const unprotectedHeader = this.unprotected ?? new Header()
    verifyHeaders(protectedHeader, unprotectedHeader)

    const alg = this.alg()
    if (alg == null) {
      throw new Error('cose-ts: Recipient.encode: alg header parameter missing')
    }
    if (alg === iana.AlgorithmDirect) {
      this.ciphertext = new Uint8Array()
    } else if (this.key) {
      if (this.key.has(iana.KeyParameterAlg) && alg !== this.key.alg) {
        throw new Error(
          `cose-ts: Recipient.encode: alg mismatch, expected ${alg}, got ${this.key.alg}`
        )
      }
      this.ciphertext = this.key.wrapKey(cek)
    } else {
      throw new Error('cose-ts: Recipient.encode: key wrapper missing')
    }
    validateRecipientForAlg(this, 'encode')

    const protectedBytes = protectedHeader.toBytes()
    const unprotected = unprotectedHeader.toRaw()
    const arr: Value[] = [protectedBytes, unprotected, this.ciphertext]
    if (this.recipients.length > 0) {
      arr.push(this.recipients.map((r) => r.encode(cek)))
    }
    return arr
  }

  // recoverCEK recovers the content encryption/MAC key for this recipient using
  // the provided KEK. For the direct method the KEK's own secret is returned.
  recoverCEK(kek: Key & Partial<KeyWrapper>): Uint8Array {
    const alg = this.alg()
    if (alg === iana.AlgorithmDirect) {
      return kek.getSecret()
    }
    if (alg == null) {
      throw new Error(
        'cose-ts: Recipient.recoverCEK: alg header parameter missing'
      )
    }
    if (kek.has(iana.KeyParameterAlg) && alg !== kek.alg) {
      throw new Error(
        `cose-ts: Recipient.recoverCEK: alg mismatch, expected ${alg}, got ${kek.alg}`
      )
    }
    if (typeof kek.unwrapKey !== 'function') {
      throw new Error(
        'cose-ts: Recipient.recoverCEK: key cannot unwrap the content key'
      )
    }
    if (!(this.ciphertext instanceof Uint8Array)) {
      throw new Error(
        'cose-ts: Recipient.recoverCEK: encrypted content key is missing'
      )
    }
    return kek.unwrapKey(this.ciphertext)
  }
}

function validateRecipientForAlg(r: Recipient, fn: string): void {
  const alg = r.alg()
  if (alg === iana.AlgorithmDirect) {
    if (r.protected && r.protected.toRaw().size !== 0) {
      throw new Error(
        `cose-ts: Recipient.${fn}: direct recipient protected bucket must be empty`
      )
    }
    if (!(r.ciphertext instanceof Uint8Array) || r.ciphertext.length !== 0) {
      throw new Error(
        `cose-ts: Recipient.${fn}: direct recipient ciphertext must be empty`
      )
    }
    if (r.recipients.length !== 0) {
      throw new Error(
        `cose-ts: Recipient.${fn}: direct recipient must not contain nested recipients`
      )
    }
  } else if (isAesKeyWrapAlg(alg)) {
    if (!(r.ciphertext instanceof Uint8Array)) {
      throw new Error(
        `cose-ts: Recipient.${fn}: AES-KW recipient ciphertext must be a byte string`
      )
    }
    if (r.protected && r.protected.toRaw().size !== 0) {
      throw new Error(
        `cose-ts: Recipient.${fn}: AES-KW recipient protected bucket must be empty`
      )
    }
  }
}

function isAesKeyWrapAlg(alg: number | string | undefined): boolean {
  return (
    alg === iana.AlgorithmA128KW ||
    alg === iana.AlgorithmA192KW ||
    alg === iana.AlgorithmA256KW
  )
}
