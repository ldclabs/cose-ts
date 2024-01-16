// (c) 2023-present, LDC Labs. All rights reserved.
// See the file LICENSE for licensing terms.

import { assert, describe, it } from 'vitest'
import * as iana from './iana'
import {
  bytesToHex,
  hexToBytes,
  utf8ToBytes,
  base64ToBytes,
  bytesToBase64Url,
} from './utils'
import { Header } from './header'
import { ECDSAKey } from './ecdsa'
import { Sign1Message } from './sign1'

describe('Sign1Message Examples', () => {
  // https://github.com/cose-wg/Examples/tree/master/sign1-tests
  it('sign-pass-02: External', async () => {
    const key = ECDSAKey.fromSecret(
      base64ToBytes('V8kgd2ZBRuh2dgyVINBUqpPDr7BOMGcF22CQMIUHtNM'),
      '11'
    )
    assert.equal(key.kty, iana.KeyTypeEC2)
    assert.equal(key.alg, iana.AlgorithmES256)
    assert.equal(key.getInt(iana.EC2KeyParameterCrv), iana.EllipticCurveP_256)

    const msg = new Sign1Message(
      utf8ToBytes('This is the content.'),
      new Header().setParam(iana.HeaderParameterAlg, iana.AlgorithmES256),
      new Header().setParam(iana.HeaderParameterKid, utf8ToBytes('11'))
    )

    const output = Sign1Message.withTag(
      msg.toBytes(key, hexToBytes('11aa22bb33cc44dd55006699'))
    )
    assert.equal(
      bytesToHex(output).toUpperCase(),
      'D28443A10126A10442313154546869732069732074686520636F6E74656E742E584010729CD711CB3813D8D8E944A8DA7111E7B258C9BDCA6135F7AE1ADBEE9509891267837E1E33BD36C150326AE62755C6BD8E540C3E8F92D7D225E8DB72B8820B'
    )

    const msg2 = Sign1Message.fromBytes(
      key,
      output,
      hexToBytes('11aa22bb33cc44dd55006699')
    )
    assert.equal(bytesToHex(msg2.payload), bytesToHex(msg.payload))
    assert.throw(() => Sign1Message.fromBytes(key, output))

    const pk = key.public()
    assert.equal(
      bytesToBase64Url(pk.getBytes(iana.EC2KeyParameterX)),
      'usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8'
    )
    assert.equal(pk.getBool(iana.EC2KeyParameterY), false)
    const msg3 = Sign1Message.fromBytes(
      pk,
      output,
      hexToBytes('11aa22bb33cc44dd55006699')
    )
    assert.equal(bytesToHex(msg3.payload), bytesToHex(msg.payload))

    const pk2 = new ECDSAKey()
    pk2.alg = iana.AlgorithmES256
    pk2.setParam(
      iana.EC2KeyParameterX,
      base64ToBytes('usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8')
    )
    pk2.setParam(
      iana.EC2KeyParameterY,
      base64ToBytes('IBOL-C3BttVivg-lSreASjpkttcsz-1rb7btKLv8EX4')
    )
    const msg4 = Sign1Message.fromBytes(
      pk2,
      output,
      hexToBytes('11aa22bb33cc44dd55006699')
    )
    assert.equal(bytesToHex(msg4.payload), bytesToHex(msg.payload))
  })
})
