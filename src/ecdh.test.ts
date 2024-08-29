// (c) 2023-present, LDC Labs. All rights reserved.
// See the file LICENSE for licensing terms.

import { assert, describe, it } from 'vitest'
import { ECDHKey } from './ecdh'
import * as iana from './iana'
import { base64ToBytes, bytesToHex, utf8ToBytes } from './utils'

describe('ECDH Examples', () => {
  it('ECDHer', () => {
    for (const crv of [
      iana.EllipticCurveP_256,
      iana.EllipticCurveP_384,
      iana.EllipticCurveP_521,
      iana.EllipticCurveX25519
    ]) {
      const a = ECDHKey.generate(crv)
      const b = ECDHKey.generate(crv)
      const secretA = a.ecdh(b.public())
      const secretB = b.ecdh(a.public())
      assert.deepEqual(secretA, secretB)
    }
  })

  it('Examples', () => {
    const keyR = new Map()
    keyR.set(iana.KeyParameterKty, iana.KeyTypeEC2)
    keyR.set(
      iana.KeyParameterKid,
      utf8ToBytes('meriadoc.brandybuck@buckland.example')
    )
    keyR.set(iana.EC2KeyParameterCrv, iana.EllipticCurveP_256)
    keyR.set(
      iana.EC2KeyParameterX,
      base64ToBytes('Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0')
    )
    keyR.set(
      iana.EC2KeyParameterY,
      base64ToBytes('HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw')
    )
    keyR.set(
      iana.EC2KeyParameterD,
      base64ToBytes('r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8')
    )
    const kr = new ECDHKey(keyR)

    const keyS = new Map()
    keyS.set(iana.KeyParameterKty, iana.KeyTypeEC2)
    keyS.set(
      iana.KeyParameterKid,
      utf8ToBytes('meriadoc.brandybuck@buckland.example')
    )
    keyS.set(iana.EC2KeyParameterCrv, iana.EllipticCurveP_256)
    keyS.set(
      iana.EC2KeyParameterX,
      base64ToBytes('mPUKT_bAWGHIhg0TpjjqVsP1rXWQu_vwVOHHtNkdYoA')
    )
    keyS.set(
      iana.EC2KeyParameterY,
      base64ToBytes('8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs')
    )
    const ks = new ECDHKey(keyS)

    const secret = kr.ecdh(ks)
    assert.equal(
      bytesToHex(secret).toLocaleUpperCase(),
      '4B31712E096E5F20B4ECF9790FD8CC7C8B7E2C8AD90BDA81CB224F62C0E7B9A6'
    )
  })
})
