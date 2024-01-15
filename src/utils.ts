// (c) 2023-present, LDC Labs. All rights reserved.
// See the file LICENSE for licensing terms.

import { decode as _decode, encode as _encode } from 'cborg'

// re-export with the right types
export function decode<T>(data: Uint8Array): T {
  return _decode(data, {
    useMaps: true,
    rejectDuplicateMapKeys: true,
  }) as T
}

export function encode(data: unknown) {
  return _encode(data, {})
}

export function bytesToBase64Url(bytes: Uint8Array) {
  return btoa(String.fromCodePoint(...bytes))
    .replaceAll('+', '-')
    .replaceAll('/', '_')
    .replaceAll('=', '')
}

export function base64ToBytes(str: string) {
  return Uint8Array.from(atob(str), (m) => m.codePointAt(0)!)
}
