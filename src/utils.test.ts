// (c) 2023-present, LDC Labs. All rights reserved.
// See the file LICENSE for licensing terms.

import { assert, describe, it } from 'vitest'
import {
  compareBytes,
  bytesToBase64Url,
  base64ToBytes,
  randomBytes
} from './utils'

describe('utils', () => {
  it('compareBytes', () => {
    assert.equal(compareBytes(new Uint8Array(), new Uint8Array([1, 2, 3])), -1)
    assert.equal(compareBytes(new Uint8Array([1, 2, 3]), new Uint8Array()), 1)
    assert.equal(
      compareBytes(new Uint8Array([1, 2, 3]), new Uint8Array([1, 2, 3])),
      0
    )
    assert.equal(
      compareBytes(new Uint8Array([1, 2, 3]), new Uint8Array([1, 2, 4])),
      -1
    )
    assert.equal(
      compareBytes(new Uint8Array([1, 2, 4]), new Uint8Array([1, 2, 3])),
      1
    )
    assert.equal(
      compareBytes(new Uint8Array([1, 2]), new Uint8Array([1, 2, 3])),
      -1
    )
    assert.equal(
      compareBytes(new Uint8Array([1, 2]), new Uint8Array([1, 1, 3])),
      1
    )
    assert.equal(
      compareBytes(new Uint8Array([1, 2, 3]), new Uint8Array([1, 2])),
      1
    )
    assert.equal(
      compareBytes(new Uint8Array([1, 1, 3]), new Uint8Array([1, 2])),
      -1
    )
  })

  it('bytesToBase64Url and base64ToBytes', () => {
    for (let i = 0; i < 64; i++) {
      const b = randomBytes(i)
      const s = bytesToBase64Url(b)
      assert.equal(compareBytes(base64ToBytes(s), b), 0)
    }
  })
})
