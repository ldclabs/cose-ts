// (c) 2023-present, LDC Labs. All rights reserved.
// See the file LICENSE for licensing terms.

import { Header, verifyHeaders } from './header'
import { RawMap, Value, assertIntOrText } from './map'
import { Key, type MACer } from './key'
import { HMACKey } from './hmac'
import { Recipient } from './recipient'
import * as iana from './iana'
import { decodeCBOR, encodeCBOR, equalBytes } from './utils'
import {
  skipTag,
  withTag,
  CwtPrefix,
  MacMessagePrefix,
  CBORSelfPrefix
} from './tag'

// MacMessage represents a COSE_Mac object.
//
// The payload is MACed with a caller-provided content MAC key. Each Recipient
// then carries or derives that MAC key for a recipient. Use Mac0Message when
// the MAC key is known implicitly and no recipient structure is needed.
//
// Reference https://datatracker.ietf.org/doc/html/rfc9052#name-maced-message-with-recipien.
export class MacMessage {
  payload: Uint8Array
  protected: Header | null = null
  unprotected: Header | null = null
  tag: Uint8Array
  recipients: Recipient[]

  private static macBytes(
    payload: Uint8Array,
    protectedHeader: Uint8Array,
    externalData?: Uint8Array
  ): Uint8Array {
    return encodeCBOR([
      'MAC',
      protectedHeader,
      externalData ?? new Uint8Array(),
      payload
    ])
  }

  static withTag(coseData: Uint8Array): Uint8Array {
    return withTag(MacMessagePrefix, coseData)
  }

  static fromBytes(
    keks: Key[],
    coseData: Uint8Array,
    externalData?: Uint8Array
  ): MacMessage {
    const data = skipTag(
      MacMessagePrefix,
      skipTag(CwtPrefix, skipTag(CBORSelfPrefix, coseData))
    )

    const [protectedBytes, unprotected, payload, tag, recipients] = decodeCBOR(
      data
    ) as [Uint8Array, RawMap, Uint8Array, Uint8Array, Value[]]

    if (!Array.isArray(recipients) || recipients.length === 0) {
      throw new Error('cose-ts: MacMessage.fromBytes: no recipients')
    }

    const protectedHeader = Header.fromBytes(protectedBytes)
    const unprotectedHeader = new Header(unprotected)
    verifyHeaders(protectedHeader, unprotectedHeader)

    const alg = protectedHeader.getType(
      iana.HeaderParameterAlg,
      assertIntOrText,
      'alg'
    )

    const recps = recipients.map((r) => Recipient.fromCBORValue(r))
    const toBeMaced = MacMessage.macBytes(payload, protectedBytes, externalData)

    // Recover the content MAC key from a recipient using one of the provided
    // KEKs, then verify the tag. A candidate is accepted only if it reproduces
    // the tag, so a wrong key is rejected.
    for (const kek of keks) {
      for (const r of recps) {
        let contentKey: Key & MACer
        try {
          contentKey = makeMACer(alg, r.recoverCEK(kek))
        } catch (_e) {
          continue
        }
        if (equalBytes(tag, contentKey.mac(toBeMaced))) {
          return new MacMessage(
            payload,
            protectedHeader,
            unprotectedHeader,
            tag,
            recps
          )
        }
      }
    }

    throw new Error('cose-ts: MacMessage.fromBytes: tag mismatch')
  }

  constructor(
    payload: Uint8Array,
    protectedHeader?: Header,
    unprotected?: Header,
    tag: Uint8Array = new Uint8Array(),
    recipients: Recipient[] = []
  ) {
    this.payload = payload
    this.protected = protectedHeader
      ? new Header(protectedHeader.clone())
      : null
    this.unprotected = unprotected ? new Header(unprotected.clone()) : null
    this.tag = tag
    this.recipients = recipients
  }

  // toBytes computes the MAC over the payload with the content MAC key and
  // serializes the COSE_Mac, wrapping the MAC key for each recipient.
  toBytes(contentKey: Key & MACer, externalData?: Uint8Array): Uint8Array {
    if (this.recipients.length === 0) {
      throw new Error('cose-ts: MacMessage.toBytes: no recipients')
    }

    if (this.protected == null) {
      this.protected = new Header()
      if (contentKey.has(iana.KeyParameterAlg)) {
        this.protected.setParam(iana.HeaderParameterAlg, contentKey.alg)
      }
    } else if (this.protected.has(iana.HeaderParameterAlg)) {
      const alg = this.protected.getType(
        iana.HeaderParameterAlg,
        assertIntOrText,
        'alg'
      )
      if (alg !== contentKey.alg) {
        throw new Error(
          `cose-ts: MacMessage.toBytes: alg mismatch, expected ${alg}, got ${contentKey.alg}`
        )
      }
    }

    if (this.unprotected == null) {
      this.unprotected = new Header()
    }

    verifyHeaders(this.protected, this.unprotected)
    assertRecipientMode(this.recipients, 'MacMessage.toBytes')

    const protectedBytes = this.protected.toBytes()
    this.tag = contentKey.mac(
      MacMessage.macBytes(this.payload, protectedBytes, externalData)
    )

    const cek = contentKey.getSecret()
    const recipients = this.recipients.map((r) => r.encode(cek))

    return encodeCBOR([
      protectedBytes,
      this.unprotected.toRaw(),
      this.payload,
      this.tag,
      recipients
    ])
  }
}

// makeMACer builds the content MAC key from the body algorithm and the recovered
// content MAC key bytes. Only HMAC algorithms are supported.
function makeMACer(alg: number | string, cek: Uint8Array): Key & MACer {
  switch (alg) {
    case iana.AlgorithmHMAC_256_64:
    case iana.AlgorithmHMAC_256_256:
    case iana.AlgorithmHMAC_384_384:
    case iana.AlgorithmHMAC_512_512:
      return HMACKey.fromSecret(cek, alg as number)
    default:
      throw new Error(`cose-ts: MacMessage: unsupported MAC alg ${alg}`)
  }
}

function assertRecipientMode(recipients: Recipient[], fn: string): void {
  const directCount = recipients.filter(
    (r) => r.alg() === iana.AlgorithmDirect
  ).length
  if (directCount > 0 && recipients.length !== 1) {
    throw new Error(
      `cose-ts: ${fn}: direct recipient mode must be the only recipient mode`
    )
  }
}
