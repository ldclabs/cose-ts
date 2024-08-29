// (c) 2023-present, LDC Labs. All rights reserved.
// See the file LICENSE for licensing terms.

import { decode, encode } from 'cborg'

export {
  bytesToHex,
  hexToBytes,
  utf8ToBytes,
  randomBytes,
  toBytes,
  concatBytes,
} from '@noble/hashes/utils'

export function decodeCBOR<T>(data: Uint8Array): T {
  return decode(data, {
    useMaps: true,
    rejectDuplicateMapKeys: true,
  }) as T
}

export function encodeCBOR(data: unknown): Uint8Array {
  return encode(data, {})
}

export function bytesToBase64Url(bytes: Uint8Array): string {
  return btoa(String.fromCodePoint(...bytes))
    .replaceAll('+', '-')
    .replaceAll('/', '_')
    .replaceAll('=', '')
}

export function base64ToBytes(str: string): Uint8Array {
  return Uint8Array.from(
    atob(str.replaceAll('-', '+').replaceAll('_', '/')),
    (m) => m.codePointAt(0)!
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

export function assertEqual(actual: unknown, expected: unknown, message: string = 'not equal'): void {
  if (actual !== expected) {
    throw new Error(`cose-ts: ${message}, expected ${expected}, got ${actual}`)
  }
}