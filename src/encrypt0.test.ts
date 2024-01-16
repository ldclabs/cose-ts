// (c) 2023-present, LDC Labs. All rights reserved.
// See the file LICENSE for licensing terms.

import { assert, describe, it } from 'vitest'
import * as iana from './iana'
import { bytesToHex, hexToBytes, utf8ToBytes, base64ToBytes } from './utils'
import { Header } from './header'
import { AesGcmKey } from './aesgcm'
import { Encrypt0Message } from './encrypt0'

// https://github.com/cose-wg/Examples/tree/master/encrypted-tests
// https://github.com/cose-wg/Examples/tree/master/RFC8152
describe('Encrypt0Message Examples', () => {
  it('env-pass-02: Add external data', async () => {
    const key = AesGcmKey.fromSecret(
      base64ToBytes('hJtXIZ2uSN5kbQfbtTNWbg'),
      'our-secret'
    )
    assert.equal(key.alg, iana.AlgorithmA128GCM)

    const msg = new Encrypt0Message(
      utf8ToBytes('This is the content.'),
      new Header().setParam(iana.HeaderParameterAlg, iana.AlgorithmA128GCM),
      new Header().setParam(
        iana.HeaderParameterIV,
        hexToBytes('02D1F7E6F26C43D4868D87CE')
      )
    )

    let data = await msg.toBytes(key, hexToBytes('0011bbcc22dd4455dd220099'))
    data = Encrypt0Message.withTag(data)
    assert.equal(
      bytesToHex(data).toUpperCase(),
      'D08343A10101A1054C02D1F7E6F26C43D4868D87CE582460973A94BB2898009EE52ECFD9AB1DD25867374B1DC3A143880CA2883A5630DA08AE1E6E'
    )

    const msg2 = await Encrypt0Message.fromBytes(
      key,
      data,
      hexToBytes('0011bbcc22dd4455dd220099')
    )
    data = await msg2.toBytes(key, hexToBytes('0011bbcc22dd4455dd220099'))
    assert.equal(
      bytesToHex(data).toUpperCase(),
      '8343A10101A1054C02D1F7E6F26C43D4868D87CE582460973A94BB2898009EE52ECFD9AB1DD25867374B1DC3A143880CA2883A5630DA08AE1E6E'
    )
  })
})
