// (c) 2023-present, LDC Labs. All rights reserved.
// See the file LICENSE for licensing terms.

import { assert, describe, it } from 'vitest'
import { Header } from './header'
import * as iana from './iana'
import { KDFContext, PartyInfo, SuppPubInfo } from './kdfcontext'
import { bytesToHex, hexToBytes } from './utils'

describe('KDFContext Examples', () => {
  it('works', () => {
    const ctx0 = KDFContext.fromBytes(hexToBytes('840083F6F6F683F6F6F6820040'))
    assert.equal(ctx0.algorithmID, 0)
    assert.deepEqual(ctx0.partyUInfo, new PartyInfo())
    assert.deepEqual(ctx0.partyVInfo, new PartyInfo())
    assert.deepEqual(ctx0.suppPubInfo, new SuppPubInfo(0, new Header()))
    assert.equal(ctx0.suppPrivInfo, null)
    assert.equal(bytesToHex(ctx0.toBytes()).toUpperCase(), '840083F6F6F683F6F6F6820040')

    const ctx = KDFContext.fromBytes(hexToBytes('840183F6F6F683F6F6F682188044A1013818'))
    assert.equal(ctx.algorithmID, iana.AlgorithmA128GCM)
    assert.deepEqual(ctx.partyUInfo, new PartyInfo())
    assert.deepEqual(ctx.partyVInfo, new PartyInfo())
    const kv = new Map([[iana.HeaderParameterAlg, iana.AlgorithmECDH_ES_HKDF_256]])
    assert.deepEqual(ctx.suppPubInfo, new SuppPubInfo(128, new Header(kv)))
    assert.equal(ctx.suppPrivInfo, null)
    assert.equal(bytesToHex(ctx.toBytes()).toUpperCase(), '840183F6F6F683F6F6F682188044A1013818')
  })
})