// (c) 2023-present, LDC Labs. All rights reserved.
// See the file LICENSE for licensing terms.

import {
  concatBytes as nobleConcatBytes,
  utf8ToBytes as nobleUtf8ToBytes
} from '@noble/hashes/utils.js'
import { decode, encode, Token } from 'cborg'

export {
  bytesToHex,
  concatBytes,
  hexToBytes,
  randomBytes,
  utf8ToBytes
} from '@noble/hashes/utils.js'

export function bytesToBase64(bytes: Uint8Array): string {
  // Build the binary string in chunks to avoid "Maximum call stack size
  // exceeded" that `String.fromCharCode(...bytes)` triggers on large inputs.
  let binary = ''
  const chunkSize = 0x8000 // 32 KiB, well under the argument-count limit
  for (let i = 0; i < bytes.length; i += chunkSize) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunkSize))
  }
  return btoa(binary)
}

export function bytesToBase64Url(bytes: Uint8Array): string {
  return bytesToBase64(bytes)
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

// equalBytes reports whether two Uint8Array have the same contents, comparing
// in constant time with respect to the byte values (timing still depends on
// the length). Use this instead of compareBytes when comparing secret-derived
// values such as MAC tags to avoid leaking information through early exits.
export function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (!(a instanceof Uint8Array) || !(b instanceof Uint8Array)) {
    throw new Error('cose-ts: equalBytes: invalid arguments')
  }

  if (a.length !== b.length) {
    return false
  }

  let diff = 0
  for (let i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i]
  }
  return diff === 0
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

// cborHead encodes a CBOR head (major type + minimal-length argument).
function cborHead(major: number, n: number): Uint8Array {
  const mt = major << 5
  if (n < 24) {
    return new Uint8Array([mt | n])
  }
  if (n < 0x100) {
    return new Uint8Array([mt | 24, n])
  }
  if (n < 0x10000) {
    return new Uint8Array([mt | 25, n >> 8, n & 0xff])
  }
  if (n < 0x100000000) {
    return new Uint8Array([
      mt | 26,
      (n >>> 24) & 0xff,
      (n >>> 16) & 0xff,
      (n >>> 8) & 0xff,
      n & 0xff
    ])
  }
  // 64-bit argument; map labels never reach this range in practice.
  const hi = Math.floor(n / 0x100000000)
  const lo = n >>> 0
  return new Uint8Array([
    mt | 27,
    (hi >>> 24) & 0xff,
    (hi >>> 16) & 0xff,
    (hi >>> 8) & 0xff,
    hi & 0xff,
    (lo >>> 24) & 0xff,
    (lo >>> 16) & 0xff,
    (lo >>> 8) & 0xff,
    lo & 0xff
  ])
}

// cborKeyBytes returns the deterministic CBOR encoding of a map key (an integer
// or text-string label). It deliberately does NOT call encodeCBOR(): the map
// sorter runs inside cborg's own encode(), and re-entering encode() there
// corrupts cborg's shared encoding state (dropping the enclosing array header
// for maps with 4 or more entries). The head bytes are produced directly here.
function cborKeyBytes(value: unknown): Uint8Array {
  if (typeof value === 'number' && Number.isInteger(value)) {
    return value >= 0 ? cborHead(0, value) : cborHead(1, -value - 1)
  }
  if (typeof value === 'string') {
    const b = nobleUtf8ToBytes(value)
    return nobleConcatBytes(cborHead(3, b.length), b)
  }
  throw new Error('rfc8949MapSorter: complex key types are not supported yet')
}

function rfc8949MapSorter(
  e1: (Token | Token[])[],
  e2: (Token | Token[])[]
): number {
  if (e1[0] instanceof Token && e2[0] instanceof Token) {
    const t1 = e1[0] as TokenEx
    const t2 = e2[0] as TokenEx

    // different key types
    if (!t1._keyBytes) {
      t1._keyBytes = cborKeyBytes(t1.value)
    }

    if (!t2._keyBytes) {
      t2._keyBytes = cborKeyBytes(t2.value)
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

// encodeCBOR uses the RFC 8949 deterministic map-key order required by RFC
// 9052 for Sig_structure, Enc_structure, and MAC_structure. Map keys are
// limited to COSE label types supported by this library: integers and text
// strings.
export function encodeCBOR(data: unknown): Uint8Array {
  return encode(data, rfc8949EncodeOptions)
}
