// (c) 2023-present, LDC Labs. All rights reserved.
// See the file LICENSE for licensing terms.

import { hkdf } from '@noble/hashes/hkdf'
import { sha256, sha512 } from '@noble/hashes/sha2'

// hkdf256 derives a key from the given secret, salt, info and key size, using HKDF-SHA-256.
export function hkdf256(
  secret: Uint8Array,
  salt: Uint8Array | undefined,
  info: Uint8Array,
  keySize: number
): Uint8Array {
  return hkdf(sha256, secret, salt, info, keySize)
}

// hkdf512 derives a key from the given secret, salt, info and key size, using HKDF-SHA-512.
export function hkdf512(
  secret: Uint8Array,
  salt: Uint8Array | undefined,
  info: Uint8Array,
  keySize: number
): Uint8Array {
  return hkdf(sha512, secret, salt, info, keySize)
}
