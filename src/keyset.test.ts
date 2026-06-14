// (c) 2023-present, LDC Labs. All rights reserved.
// See the file LICENSE for licensing terms.

import { assert, describe, it } from 'vitest'
import * as iana from './iana'
import { utf8ToBytes, compareBytes } from './utils'
import { Ed25519Key } from './ed25519'
import { ECDSAKey } from './ecdsa'
import { KeySet } from './keyset'

describe('KeySet', () => {
  it('round-trips a set of public keys and looks them up by kid', () => {
    const k1 = Ed25519Key.generate().public()
    k1.kid = utf8ToBytes('a')
    const k2 = ECDSAKey.generate(iana.AlgorithmES256).public()
    k2.kid = utf8ToBytes('b')

    const set = new KeySet([k1, k2])
    const data = set.toBytes()

    const set2 = KeySet.fromBytes(data)
    assert.equal(set2.keys.length, 2)

    const found = set2.getByKid(utf8ToBytes('b'))
    assert.equal(found.length, 1)
    assert.equal(compareBytes(found[0].kid, utf8ToBytes('b')), 0)

    assert.equal(set2.getByKid(utf8ToBytes('missing')).length, 0)
  })

  it('rejects an empty key set', () => {
    assert.throw(() => new KeySet().toBytes(), /must not be empty/)
  })
})
