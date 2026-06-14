// (c) 2023-present, LDC Labs. All rights reserved.
// See the file LICENSE for licensing terms.

import { KVMap, Label, RawMap, assertIntOrText } from './map'
import { decodeCBOR } from './utils'
import * as iana from './iana'

// Header represents a COSE Generic_Headers structure.
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

// verifyHeaders validates the protected and unprotected header buckets of a
// COSE message and returns the list of critical labels.
//
// It enforces:
//   - RFC 9052 §3: the same label MUST NOT occur in both the protected and
//     unprotected buckets.
//   - RFC 9052 §3.1: when present, "crit" MUST be in the protected bucket, the
//     array MUST have at least one value, and every label it lists MUST be
//     present in the protected bucket (otherwise this is a fatal error).
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
