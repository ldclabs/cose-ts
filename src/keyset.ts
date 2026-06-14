// (c) 2023-present, LDC Labs. All rights reserved.
// See the file LICENSE for licensing terms.

import { Key } from './key'
import { RawMap } from './map'
import { decodeCBOR, encodeCBOR, equalBytes } from './utils'
import * as iana from './iana'

// KeySet represents a COSE_KeySet object: a CBOR array whose elements are
// COSE_Key maps.
//
// Reference https://datatracker.ietf.org/doc/html/rfc9052#name-key-objects.
// A COSE Key Set MUST have at least one element in the array.
export class KeySet {
  keys: Key[]

  static fromBytes(data: Uint8Array): KeySet {
    const arr = decodeCBOR<RawMap[]>(data)
    if (!Array.isArray(arr)) {
      throw new Error('cose-ts: KeySet.fromBytes: data is not an array')
    }
    if (arr.length === 0) {
      throw new Error('cose-ts: KeySet.fromBytes: key set must not be empty')
    }

    return new KeySet(arr.map((kv) => new Key(kv)))
  }

  constructor(keys: Key[] = []) {
    if (!Array.isArray(keys)) {
      throw new TypeError('cose-ts: KeySet: keys must be an array')
    }
    this.keys = keys
  }

  // getByKid returns all keys whose "kid" matches the given identifier. Per
  // RFC 9052, "kid" values are not guaranteed to be unique, so a list is
  // returned; keys without a "kid" are skipped.
  getByKid(kid: Uint8Array): Key[] {
    return this.keys.filter((key) => {
      if (!key.has(iana.KeyParameterKid)) {
        return false
      }
      return equalBytes(key.kid, kid)
    })
  }

  toBytes(): Uint8Array {
    if (this.keys.length === 0) {
      throw new Error('cose-ts: KeySet.toBytes: key set must not be empty')
    }
    return encodeCBOR(this.keys.map((key) => key.toRaw()))
  }
}
