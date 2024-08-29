// (c) 2023-present, LDC Labs. All rights reserved.
// See the file LICENSE for licensing terms.

import { assert, describe, it } from 'vitest'
import { Header } from './header'
import { hkdf256, hkdf512 } from './hkdf'
import * as iana from './iana'
import { KDFContext, PartyInfo, SuppPubInfo } from './kdfcontext'
import { bytesToHex, hexToBytes } from './utils'

describe('HKDF Examples', () => {
  // https://github.com/cose-wg/Examples/tree/master/hkdf-hmac-sha-examples
  it('hkdf256', () => {
    // [secret, salt, info, keySize, key]
    const cases: [string, string, string, number, string][] = [
      [
        '4B31712E096E5F20B4ECF9790FD8CC7C8B7E2C8AD90BDA81CB224F62C0E7B9A6',
        '',
        '840183F6F6F683F6F6F682188044A1013818',
        16,
        '56074D506729CA40C4B4FE50C6439893',
      ],
      [
        '4B31712E096E5F20B4ECF9790FD8CC7C8B7E2C8AD90BDA81CB224F62C0E7B9A6',
        '',
        '840383F6F6F683F6F6F68219010044A1013818',
        32,
        '29CAA7326B683A73C98777707866D8838A3ADC3E3F46C180C54C5AAF01F1CC0C',
      ],
      [
        '4B31712E096E5F20B4ECF9790FD8CC7C8B7E2C8AD90BDA81CB224F62C0E7B9A6',
        '',
        '840783F6F6F683F6F6F68219020044A1013818',
        64,
        '69220077533E89BDA8DA04814ACCB4703E8C9B009033C8F6A7E65DBB3BCA621B2CF279C6842998CB2B4D2BBAD2E6652824F424D7B7004CC2D6A7384086CF5FF8',
      ],
      [
        '4B31712E096E5F20B4ECF9790FD8CC7C8B7E2C8AD90BDA81CB224F62C0E7B9A6',
        '',
        '',
        16,
        '0A9E2D1F080FDF6686C7DDE0DA3F113C',
      ],
    ]

    for (const [secret, salt, info, keySize, key] of cases) {
      let k = hkdf256(hexToBytes(secret), hexToBytes(salt), hexToBytes(info), keySize)
      assert.equal(bytesToHex(k).toUpperCase(), key)
    }
  })

  // https://github.com/cose-wg/Examples/tree/master/hkdf-hmac-sha-examples
  it('hkdf512', () => {
    // [secret, salt, info, keySize, key]
    const cases: [string, string, string, number, string][] = [
      [
        '4B31712E096E5F20B4ECF9790FD8CC7C8B7E2C8AD90BDA81CB224F62C0E7B9A6',
        '',
        '840183F6F6F683F6F6F682188044A1013819',
        16,
        '7EC6DB8FF17E392A6CB51579F8443976',
      ],
      [
        '4B31712E096E5F20B4ECF9790FD8CC7C8B7E2C8AD90BDA81CB224F62C0E7B9A6',
        '',
        '840383F6F6F683F6F6F68219010044A1013819',
        32,
        '4684AD00BE06914F7B74EE11F70E448D9192EE740182A674A665D7B4692A3EEB',
      ],
      [
        '4B31712E096E5F20B4ECF9790FD8CC7C8B7E2C8AD90BDA81CB224F62C0E7B9A6',
        '',
        '840783F6F6F683F6F6F68219020044A1013819',
        64,
        'ECEAACB6A84FC9FAD2BB2E2C9520A036675BD6894CE41E826E0A5BB98D22403163739A28A2FDFED93675BCC8E46F40EDBEA98D15834F01418A43382D54510DCB',
      ],
      [
        '4B31712E096E5F20B4ECF9790FD8CC7C8B7E2C8AD90BDA81CB224F62C0E7B9A6',
        '',
        '',
        16,
        'C42FFE41AA6D378EB0BEFE47841D2E28',
      ],
    ]

    for (const [secret, salt, info, keySize, key] of cases) {
      let k = hkdf512(hexToBytes(secret), hexToBytes(salt), hexToBytes(info), keySize)
      assert.equal(bytesToHex(k).toUpperCase(), key)
    }
  })

  // https://github.com/cose-wg/Examples/blob/master/ecdh-direct-examples/p256-hkdf-256-01.json
  it('hkdf with KDFContext', () => {})
    const ctx = new KDFContext(iana.AlgorithmA128GCM, new PartyInfo(), new PartyInfo(), new SuppPubInfo(128, new Header(new Map([[iana.HeaderParameterAlg, iana.AlgorithmECDH_ES_HKDF_256]]))))

    assert.equal(bytesToHex(ctx.toBytes()).toUpperCase(), '840183F6F6F683F6F6F682188044A1013818')
    const secret = hexToBytes('4B31712E096E5F20B4ECF9790FD8CC7C8B7E2C8AD90BDA81CB224F62C0E7B9A6')
    const k = hkdf256(secret, undefined, ctx.toBytes(), 16)
    assert.equal(bytesToHex(k).toUpperCase(), '56074D506729CA40C4B4FE50C6439893')
})