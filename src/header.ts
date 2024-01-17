// (c) 2023-present, LDC Labs. All rights reserved.
// See the file LICENSE for licensing terms.

import { KVMap, RawMap } from './map'
import { decodeCBOR } from './utils'

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
