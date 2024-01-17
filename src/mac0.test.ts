// (c) 2023-present, LDC Labs. All rights reserved.
// See the file LICENSE for licensing terms.

import { assert, describe, it } from 'vitest'
import { base64ToBytes, bytesToHex, hexToBytes, utf8ToBytes } from './utils'
import * as iana from './iana'
import { HMACKey } from './hmac'
import { Mac0Message } from './mac0'
import { Header } from './header'

describe('Mac0Message Examples', () => {
  it('mac-pass-02: External Data', () => {
    const key = HMACKey.fromSecret(
      base64ToBytes('hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYg'),
      iana.AlgorithmHMAC_256_256,
      'our-secret'
    )
    const msg = new Mac0Message(
      utf8ToBytes('This is the content.'),
      new Header(),
      new Header().setParam(iana.HeaderParameterAlg, iana.AlgorithmHMAC_256_256)
    )
    const output = Mac0Message.withTag(
      msg.toBytes(key, hexToBytes('ff00ee11dd22cc33bb44aa559966'))
    )
    assert.equal(
      bytesToHex(output).toUpperCase(),
      'D18440A1010554546869732069732074686520636F6E74656E742E58200FECAEC59BB46CC8A488AACA4B205E322DD52696B75A45768D3C302DD4BAE2F7'
    )

    const msg2 = Mac0Message.fromBytes(
      key,
      output,
      hexToBytes('ff00ee11dd22cc33bb44aa559966')
    )
    assert.equal(bytesToHex(msg2.payload), bytesToHex(msg.payload))
    assert.throw(() =>
      Mac0Message.fromBytes(
        key,
        output,
        hexToBytes('ff00ee11dd22cc33bb44aa559965')
      )
    )
  })
})
