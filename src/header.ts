// (c) 2023-present, LDC Labs. All rights reserved.
// See the file LICENSE for licensing terms.

import { KVMap, Label, RawMap, assertBytes, assertIntOrText } from './map'
import { decodeCBOR } from './utils'
import * as iana from './iana'

// Header represents a COSE Generic_Headers map.
//
// COSE carries protected headers as a bstr containing the encoded map, while
// unprotected headers are carried directly as a map. Header.toBytes() returns a
// zero-length bstr for an empty protected map, matching the preferred RFC 9052
// encoding used in Sig_structure, Enc_structure, and MAC_structure.
export class Header extends KVMap {
  static fromBytes(data: Uint8Array): Header {
    if (data.length === 0) {
      return new Header()
    }
    return new Header(decodeCBOR(data))
  }

  constructor(kv: RawMap = new Map()) {
    super(kv)
  }

  toBytes(): Uint8Array {
    if (this.toRaw().size === 0) {
      return new Uint8Array()
    }

    return super.toBytes()
  }
}

// verifyHeaders validates the protected and unprotected header buckets for one
// COSE security layer and returns the list of critical labels.
//
// It enforces:
//   - RFC 9052 §3: the same label MUST NOT occur in both the protected and
//     unprotected buckets.
//   - RFC 9052 §3.1: when present, "crit" MUST be in the protected bucket, the
//     array MUST have at least one value, and every label it lists MUST be
//     present in the protected bucket (otherwise this is a fatal error).
//   - RFC 9052 §3.1 common header value types for alg, content type, kid, IV,
//     and Partial IV.
//   - RFC 9052 §3.1: IV and Partial IV MUST NOT both be present in the same
//     security layer.
//
// The returned labels allow the caller to verify that each critical header
// parameter is actually understood by the application.
export function verifyHeaders(
  protectedHeader: Header,
  unprotectedHeader: Header
): Label[] {
  // RFC 9052 §1.5: a label that is neither a text string nor an integer is an
  // error.
  for (const label of unprotectedHeader.toRaw().keys()) {
    assertIntOrText(label, 'unprotected header label')
  }

  for (const label of protectedHeader.toRaw().keys()) {
    assertIntOrText(label, 'protected header label')
    if (unprotectedHeader.has(label)) {
      throw new Error(
        `cose-ts: header parameter ${String(
          label
        )} occurs in both the protected and unprotected buckets`
      )
    }
  }

  verifyCommonHeaderParameters(protectedHeader, 'protected')
  verifyCommonHeaderParameters(unprotectedHeader, 'unprotected')

  const hasIV =
    protectedHeader.has(iana.HeaderParameterIV) ||
    unprotectedHeader.has(iana.HeaderParameterIV)
  const hasPartialIV =
    protectedHeader.has(iana.HeaderParameterPartialIV) ||
    unprotectedHeader.has(iana.HeaderParameterPartialIV)
  if (hasIV && hasPartialIV) {
    throw new Error(
      'cose-ts: IV and Partial IV must not both be present in the same header layer'
    )
  }

  if (unprotectedHeader.has(iana.HeaderParameterCrit)) {
    throw new Error(
      'cose-ts: crit header parameter must be in the protected bucket'
    )
  }

  if (!protectedHeader.has(iana.HeaderParameterCrit)) {
    return []
  }

  const crit = protectedHeader.getArray(
    iana.HeaderParameterCrit,
    assertIntOrText,
    'crit'
  )
  if (crit.length === 0) {
    throw new Error(
      'cose-ts: crit header parameter must have at least one value'
    )
  }

  for (const label of crit) {
    if (!protectedHeader.has(label)) {
      throw new Error(
        `cose-ts: critical header parameter ${String(
          label
        )} is not present in the protected bucket`
      )
    }
  }

  return crit
}

function verifyCommonHeaderParameters(header: Header, bucket: string): void {
  if (header.has(iana.HeaderParameterAlg)) {
    header.getType(iana.HeaderParameterAlg, assertIntOrText, `${bucket} alg`)
  }
  if (header.has(iana.HeaderParameterContentType)) {
    header.getType(
      iana.HeaderParameterContentType,
      assertContentType,
      `${bucket} content type`
    )
  }
  if (header.has(iana.HeaderParameterKid)) {
    header.getType(iana.HeaderParameterKid, assertBytes, `${bucket} kid`)
  }
  if (header.has(iana.HeaderParameterIV)) {
    header.getType(iana.HeaderParameterIV, assertBytes, `${bucket} IV`)
  }
  if (header.has(iana.HeaderParameterPartialIV)) {
    header.getType(
      iana.HeaderParameterPartialIV,
      assertBytes,
      `${bucket} Partial IV`
    )
  }
}

function assertContentType(value: unknown, name: string): number | string {
  if (typeof value === 'string') {
    return value
  }
  if (typeof value === 'number' && Number.isSafeInteger(value) && value >= 0) {
    return value
  }
  throw new TypeError(
    `${name} must be a non-negative integer or string, but got ${String(value)}`
  )
}
