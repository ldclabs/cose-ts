// (c) 2023-present, LDC Labs. All rights reserved.
// See the file LICENSE for licensing terms.

import { assert, describe, it } from 'vitest'
import * as iana from './iana'
import { base64ToBytes, utf8ToBytes, decodeCBOR } from './utils'
import { Header } from './header'
import { HMACKey } from './hmac'
import { AesKwKey } from './aeskw'
import { Recipient } from './recipient'
import { MacMessage } from './mac'

const payload = utf8ToBytes('This is the content.')

describe('MacMessage (COSE_Mac)', () => {
  it('round-trips with a direct recipient', () => {
    const macKey = HMACKey.fromSecret(
      base64ToBytes('hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYg'),
      iana.AlgorithmHMAC_256_256
    )

    const msg = new MacMessage(
      payload,
      new Header().setParam(
        iana.HeaderParameterAlg,
        iana.AlgorithmHMAC_256_256
      ),
      undefined,
      undefined,
      [Recipient.direct(utf8ToBytes('our-secret'))]
    )
    const output = MacMessage.withTag(msg.toBytes(macKey))

    // The COSE_Mac structure is a 5-element array.
    const decoded = decodeCBOR<unknown[]>(output.subarray(2))
    assert.equal(decoded.length, 5)

    const msg2 = MacMessage.fromBytes([macKey], output)
    assert.deepEqual(msg2.payload, payload)
    assert.equal(msg2.recipients.length, 1)
  })

  it('round-trips with an AES key-wrap recipient', () => {
    const macKey = HMACKey.generate(iana.AlgorithmHMAC_256_256)
    const kek = AesKwKey.generate(iana.AlgorithmA256KW, utf8ToBytes('018c0ae5'))

    const msg = new MacMessage(
      payload,
      new Header().setParam(
        iana.HeaderParameterAlg,
        iana.AlgorithmHMAC_256_256
      ),
      undefined,
      undefined,
      [Recipient.keyWrap(kek)]
    )
    const output = msg.toBytes(macKey, utf8ToBytes('aad'))

    const msg2 = MacMessage.fromBytes([kek], output, utf8ToBytes('aad'))
    assert.deepEqual(msg2.payload, payload)

    // Wrong external data fails.
    assert.throw(
      () => MacMessage.fromBytes([kek], output, utf8ToBytes('bad')),
      /tag mismatch/
    )

    // Wrong KEK fails.
    const otherKek = AesKwKey.generate(iana.AlgorithmA256KW)
    assert.throw(
      () => MacMessage.fromBytes([otherKek], output, utf8ToBytes('aad')),
      /tag mismatch/
    )
  })
})
