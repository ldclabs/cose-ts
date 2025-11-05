// (c) 2023-present, LDC Labs. All rights reserved.
// See the file LICENSE for licensing terms.

import { decode, encode, Token } from 'cborg'

export {
  bytesToHex,
  concatBytes,
  hexToBytes,
  randomBytes,
  toBytes,
  utf8ToBytes
} from '@noble/hashes/utils'

export function bytesToBase64(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes))
}

export function bytesToBase64Url(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes))
    .replaceAll('+', '-')
    .replaceAll('/', '_')
    .replaceAll('=', '')
}

export function base64ToBytes(str: string): Uint8Array {
  return Uint8Array.from(
    atob(str.replaceAll('-', '+').replaceAll('_', '/')),
    (m) => m.charCodeAt(0)
  )
}

// compareBytes compares two Uint8Array and returns: -1 if a < b, 0 if a == b, 1 if a > b
export function compareBytes(a: Uint8Array, b: Uint8Array): number {
  if (a instanceof Uint8Array && b instanceof Uint8Array) {
    if (a === b) {
      return 0
    }

    for (let i = 0; i < a.length; i++) {
      if (a[i] === b[i]) {
        continue
      }
      return a[i] < b[i] ? -1 : 1
    }

    if (b.length > a.length) {
      return -1
    }

    return 0
  }

  throw new Error('cose-ts: compareBytes: invalid arguments')
}

export function assertEqual(
  actual: unknown,
  expected: unknown,
  message: string = 'not equal'
): void {
  if (actual !== expected) {
    throw new Error(`cose-ts: ${message}, expected ${expected}, got ${actual}`)
  }
}

type TokenEx = Token & { _keyBytes?: Uint8Array }

function rfc8949MapSorter(
  e1: (Token | Token[])[],
  e2: (Token | Token[])[]
): number {
  if (e1[0] instanceof Token && e2[0] instanceof Token) {
    const t1 = e1[0] as TokenEx
    const t2 = e2[0] as TokenEx

    // different key types
    if (!t1._keyBytes) {
      t1._keyBytes = encodeCBOR(t1.value)
    }

    if (!t2._keyBytes) {
      t2._keyBytes = encodeCBOR(t2.value)
    }

    return compareBytes(t1._keyBytes, t2._keyBytes)
  }
  throw new Error('rfc8949MapSorter: complex key types are not supported yet')
}

const rfc8949EncodeOptions = Object.freeze({
  float64: true,
  mapSorter: rfc8949MapSorter
})

export function decodeCBOR<T>(data: Uint8Array): T {
  return decode(data, {
    useMaps: true,
    rejectDuplicateMapKeys: true
  }) as T
}

// RFC 8949 Deterministic Encoding: The keys in every map MUST be sorted in the bytewise lexicographic order of their deterministic encodings.
export function encodeCBOR(data: unknown): Uint8Array {
  return encode(data, rfc8949EncodeOptions)
}
