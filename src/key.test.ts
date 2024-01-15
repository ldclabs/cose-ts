// (c) 2023-present, LDC Labs. All rights reserved.
// See the file LICENSE for licensing terms.

import { assert, describe, it } from 'vitest'
import { bytesToHex, hexToBytes, utf8ToBytes } from '@noble/ciphers/utils'
import * as iana from './iana'
import { Key } from './key'

describe('Key Examples', () => {
  it('128-Bit Symmetric COSE_Key', () => {
    const key = new Key()
    key.kty = iana.KeyTypeSymmetric
    key.kid = utf8ToBytes('Symmetric128')
    key.alg = iana.AlgorithmAES_CCM_16_64_128
    key.setParam(
      iana.SymmetricKeyParameterK,
      hexToBytes('231f4c4d4d3051fdc2ec0a3851d5b383')
    )
    const expected =
      'a40104024c53796d6d6574726963313238030a2050231f4c4d4d3051fdc2ec0a3851d5b383'
    assert.equal(bytesToHex(key.toBytes()), expected)

    const key2 = Key.fromBytes(hexToBytes(expected))
    assert.equal(bytesToHex(key2.toBytes()), expected)
  })

  it('256-Bit Symmetric COSE_Key', () => {
    const key = new Key()
    key.kty = iana.KeyTypeSymmetric
    key.kid = utf8ToBytes('Symmetric256')
    key.alg = iana.AlgorithmHMAC_256_64
    key.setParam(
      iana.SymmetricKeyParameterK,
      hexToBytes(
        '403697de87af64611c1d32a05dab0fe1fcb715a86ab435f1ec99192d79569388'
      )
    )
    const expected =
      'a40104024c53796d6d65747269633235360304205820403697de87af64611c1d32a05dab0fe1fcb715a86ab435f1ec99192d79569388'
    assert.equal(bytesToHex(key.toBytes()), expected)

    const key2 = Key.fromBytes(hexToBytes(expected))
    assert.equal(bytesToHex(key2.toBytes()), expected)
  })

  it('ECDSA 256-Bit COSE Key', () => {
    const key = new Key()
    key.kty = iana.KeyTypeEC2
    key.kid = utf8ToBytes('AsymmetricECDSA256')
    key.alg = iana.AlgorithmES256
    key.setParam(iana.EC2KeyParameterCrv, iana.EllipticCurveP_256)
    key.setParam(
      iana.EC2KeyParameterX,
      hexToBytes(
        '143329cce7868e416927599cf65a34f3ce2ffda55a7eca69ed8919a394d42f0f'
      )
    )
    key.setParam(
      iana.EC2KeyParameterY,
      hexToBytes(
        '60f7f1a780d8a783bfb7a2dd6b2796e8128dbbcef9d3d168db9529971a36e7b9'
      )
    )
    key.setParam(
      iana.EC2KeyParameterD,
      hexToBytes(
        '6c1382765aec5358f117733d281c1c7bdc39884d04a45a1e6c67c858bc206c19'
      )
    )
    const expected =
      'a7010202524173796d6d6574726963454344534132353603262001215820143329cce7868e416927599cf65a34f3ce2ffda55a7eca69ed8919a394d42f0f22582060f7f1a780d8a783bfb7a2dd6b2796e8128dbbcef9d3d168db9529971a36e7b92358206c1382765aec5358f117733d281c1c7bdc39884d04a45a1e6c67c858bc206c19'
    assert.equal(bytesToHex(key.toBytes()), expected)

    const key2 = Key.fromBytes(hexToBytes(expected))
    assert.equal(bytesToHex(key2.toBytes()), expected)
  })
})
