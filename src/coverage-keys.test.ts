// (c) 2023-present, LDC Labs. All rights reserved.
// See the file LICENSE for licensing terms.

// Coverage tests for the asymmetric key classes: ecdh, ecdsa, ed25519.
import { assert, describe, it } from 'vitest'
import * as iana from './iana'
import { hexToBytes, concatBytes } from './utils'
import { ECDHKey, getCurve as ecdhCurve, getKeySize } from './ecdh'
import { ECDSAKey, getCrv, getCurve as ecdsaCurve } from './ecdsa'
import { Ed25519Key } from './ed25519'

// RFC 9052 C.7 "meriadoc" P-256 key.
const mx = hexToBytes(
  '65eda5a12577c2bae829437fe338701a10aaa375e1bb5b5de108de439c08551d'
)
const my = hexToBytes(
  '1e52ed75701163f7f9e40ddf9f341b3dc9ba860af7e0ca7ca7e9eecd0084d19c'
)
const md = hexToBytes(
  'aff907c99f9ad3aae6c4cdf21122bce2bd68b5283e6907154ad911840fa208cf'
)

describe('ecdh coverage', () => {
  it('fromBytes round-trips', () => {
    const k = ECDHKey.generate(iana.EllipticCurveP_256)
    const k2 = ECDHKey.fromBytes(k.toBytes())
    assert.equal(k2.crv, iana.EllipticCurveP_256)
  })

  it('fromSecret validates key material', () => {
    assert.throws(() =>
      ECDHKey.fromSecret(iana.EllipticCurveX25519, new Uint8Array(31))
    )
    assert.throws(() =>
      ECDHKey.fromSecret(iana.EllipticCurveP_256, new Uint8Array(32))
    )
  })

  it('fromPublic handles compressed, uncompressed and x25519 keys', () => {
    const ec = ECDHKey.generate(iana.EllipticCurveP_256)
    // compressed public key (0x02/0x03 prefix)
    ECDHKey.fromPublic(iana.EllipticCurveP_256, ec.getPublicKey())
    // uncompressed public key (0x04 prefix)
    const uncompressed = concatBytes(new Uint8Array([0x04]), mx, my)
    const pk = ECDHKey.fromPublic(
      iana.EllipticCurveP_256,
      uncompressed,
      hexToBytes('01')
    )
    assert.equal(pk.crv, iana.EllipticCurveP_256)

    const x = ECDHKey.generate(iana.EllipticCurveX25519)
    ECDHKey.fromPublic(iana.EllipticCurveX25519, x.getPublicKey())
  })

  it('public() derives x/y for stored uncompressed and x25519 keys', () => {
    const kr = new ECDHKey(
      new Map<number, unknown>([
        [iana.KeyParameterKty, iana.KeyTypeEC2],
        [iana.EC2KeyParameterCrv, iana.EllipticCurveP_256],
        [iana.EC2KeyParameterX, mx],
        [iana.EC2KeyParameterY, my],
        [iana.EC2KeyParameterD, md],
        [iana.KeyParameterKeyOps, [iana.KeyOperationDeriveKey]]
      ]) as never
    )
    const pub = kr.public()
    assert.equal(pub.has(iana.EC2KeyParameterD), false)

    const x = ECDHKey.generate(iana.EllipticCurveX25519)
    assert.equal(x.public().has(iana.EC2KeyParameterD), false)
  })

  it('ecdh rejects mismatched curves', () => {
    const a = ECDHKey.generate(iana.EllipticCurveP_256)
    const b = ECDHKey.generate(iana.EllipticCurveP_384)
    assert.throws(() => a.ecdh(b.public()))
  })

  it('getCurve / getKeySize reject unknown curves', () => {
    assert.throws(() => ecdhCurve(99999))
    assert.throws(() => getKeySize(99999))
  })
})

describe('ecdsa coverage', () => {
  it('fromSecret rejects an invalid private key', () => {
    assert.throws(() => ECDSAKey.fromSecret(new Uint8Array(32)))
  })

  it('fromPublic rejects a too-short key and handles uncompressed keys', () => {
    assert.throws(() => ECDSAKey.fromPublic(new Uint8Array(10)))

    const x = hexToBytes(
      '143329cce7868e416927599cf65a34f3ce2ffda55a7eca69ed8919a394d42f0f'
    )
    const y = hexToBytes(
      '60f7f1a780d8a783bfb7a2dd6b2796e8128dbbcef9d3d168db9529971a36e7b9'
    )
    const uncompressed = concatBytes(new Uint8Array([0x04]), x, y)
    const pk = ECDSAKey.fromPublic(uncompressed, hexToBytes('01'))
    assert.equal(pk.alg, iana.AlgorithmES256)
  })

  it('public() derives x/y from a stored uncompressed key', () => {
    const key = new ECDSAKey(
      new Map<number, unknown>([
        [iana.KeyParameterKty, iana.KeyTypeEC2],
        [iana.KeyParameterAlg, iana.AlgorithmES256],
        [iana.EC2KeyParameterCrv, iana.EllipticCurveP_256],
        [
          iana.EC2KeyParameterX,
          hexToBytes(
            '143329cce7868e416927599cf65a34f3ce2ffda55a7eca69ed8919a394d42f0f'
          )
        ],
        [
          iana.EC2KeyParameterY,
          hexToBytes(
            '60f7f1a780d8a783bfb7a2dd6b2796e8128dbbcef9d3d168db9529971a36e7b9'
          )
        ],
        [
          iana.EC2KeyParameterD,
          hexToBytes(
            '6c1382765aec5358f117733d281c1c7bdc39884d04a45a1e6c67c858bc206c19'
          )
        ],
        [iana.KeyParameterKeyOps, [iana.KeyOperationSign]]
      ]) as never
    )
    const pub = key.public()
    assert.equal(pub.has(iana.EC2KeyParameterD), false)
  })

  it('getCrv / getCurve reject unknown algorithms', () => {
    assert.throws(() => getCrv(99999))
    assert.throws(() => ecdsaCurve(99999))
  })
})

describe('ed25519 coverage', () => {
  it('rejects wrong-sized key material', () => {
    assert.throws(() => Ed25519Key.fromSecret(new Uint8Array(31)))
    assert.throws(() => Ed25519Key.fromPublic(new Uint8Array(31)))
  })

  it('fromPublic accepts a kid; public() narrows key_ops', () => {
    const pub = Ed25519Key.fromPublic(new Uint8Array(32), '11')
    assert.equal(pub.kty, iana.KeyTypeOKP)

    const k = Ed25519Key.generate()
    k.ops = [iana.KeyOperationSign, iana.KeyOperationVerify]
    assert.deepEqual(k.public().ops, [iana.KeyOperationVerify])
  })
})
