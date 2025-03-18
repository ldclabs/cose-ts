// (c) 2023-present, LDC Labs. All rights reserved.
// See the file LICENSE for licensing terms.

import { assert, describe, it } from 'vitest'
import { bytesToHex, utf8ToBytes } from './utils'
import * as iana from './iana'
import { ECDSAKey, getCrv } from './ecdsa'

describe('ECDSAKey Examples', () => {
  it('Signer and Verifier', () => {
    for (const alg of [
      iana.AlgorithmES256,
      iana.AlgorithmES384,
      iana.AlgorithmES512,
      iana.AlgorithmES256K
    ]) {
      let key = ECDSAKey.generate(alg)
      assert.equal(key.kty, iana.KeyTypeEC2)
      assert.equal(key.alg, alg)
      assert.equal(key.getInt(iana.EC2KeyParameterCrv), getCrv(alg))

      const keyBytes = key.toBytes()
      key = ECDSAKey.fromBytes(keyBytes)

      const sig = key.sign(utf8ToBytes('This is the content.'))
      assert.equal(key.verify(utf8ToBytes('This is the content.'), sig), true)
      assert.equal(key.verify(utf8ToBytes('This is the content'), sig), false)
      const key2 = ECDSAKey.fromSecret(key.getSecretKey())
      assert.equal(key2.verify(utf8ToBytes('This is the content.'), sig), true)

      const pk = key.public()
      assert.equal(pk.verify(utf8ToBytes('This is the content.'), sig), true)
      assert.throw(() => pk.sign(utf8ToBytes('This is the content.')))

      const sig2 = key2.sign(utf8ToBytes('This is the content.'))
      assert.equal(bytesToHex(sig2), bytesToHex(sig))

      const pk2 = ECDSAKey.fromPublic(pk.getPublicKey())
      assert.equal(pk2.verify(utf8ToBytes('This is the content.'), sig2), true)
    }
  })
})
