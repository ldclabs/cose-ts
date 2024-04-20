// (c) 2023-present, LDC Labs. All rights reserved.
// See the file LICENSE for licensing terms.

import { assert, describe, it } from 'vitest'
import { utf8ToBytes, bytesToHex } from './utils'
import * as iana from './iana'
import { Ed25519Key } from './ed25519'

describe('Ed25519Key Examples', () => {
  it('Signer and Verifier', () => {
    let key = Ed25519Key.generate()
    assert.equal(key.kty, iana.KeyTypeOKP)
    assert.equal(key.alg, iana.AlgorithmEdDSA)
    assert.equal(key.getInt(iana.OKPKeyParameterCrv), iana.EllipticCurveEd25519)

    const keyBytes = key.toBytes()
    key = Ed25519Key.fromBytes(keyBytes)

    const sig = key.sign(utf8ToBytes('This is the content.'))
    assert.equal(key.verify(utf8ToBytes('This is the content.'), sig), true)
    assert.equal(key.verify(utf8ToBytes('This is the content'), sig), false)
    const key2 = Ed25519Key.fromSecret(key.getSecretKey())
    assert.equal(key2.verify(utf8ToBytes('This is the content.'), sig), true)

    const pk = key.public()
    assert.equal(pk.verify(utf8ToBytes('This is the content.'), sig), true)
    assert.throw(() => pk.sign(utf8ToBytes('This is the content.')))

    const sig2 = key2.sign(utf8ToBytes('This is the content.'))
    assert.equal(bytesToHex(sig2), bytesToHex(sig))

    const pk2 = Ed25519Key.fromPublic(pk.getPublicKey())
    assert.equal(pk2.verify(utf8ToBytes('This is the content.'), sig2), true)
  })
})
