// (c) 2023-present, LDC Labs. All rights reserved.
// See the file LICENSE for licensing terms.

import { assert, describe, expect, it } from 'vitest'
import * as iana from './iana'
import { base64ToBytes, utf8ToBytes, decodeCBOR } from './utils'
import { Header } from './header'
import { AesGcmKey } from './aesgcm'
import { ChaCha20Poly1305Key } from './chacha20poly1305'
import { AesKwKey } from './aeskw'
import { Recipient } from './recipient'
import { EncryptMessage } from './encrypt'

const payload = utf8ToBytes('This is the content.')

describe('EncryptMessage (COSE_Encrypt)', () => {
  it('round-trips with a direct recipient (AES-GCM)', async () => {
    const cek = AesGcmKey.fromSecret(base64ToBytes('hJtXIZ2uSN5kbQfbtTNWbg'))

    const msg = new EncryptMessage(
      payload,
      new Header().setParam(iana.HeaderParameterAlg, iana.AlgorithmA128GCM),
      undefined,
      [Recipient.direct(utf8ToBytes('our-secret'))]
    )
    const output = EncryptMessage.withTag(await msg.toBytes(cek))

    // The COSE_Encrypt structure is a 4-element array.
    const decoded = decodeCBOR<unknown[]>(output.subarray(2))
    assert.equal(decoded.length, 4)

    const msg2 = await EncryptMessage.fromBytes([cek], output)
    assert.deepEqual(msg2.payload, payload)
    assert.equal(msg2.recipients.length, 1)
  })

  it('round-trips with an AES key-wrap recipient (ChaCha20/Poly1305)', async () => {
    const cek = ChaCha20Poly1305Key.generate()
    const kek = AesKwKey.generate(iana.AlgorithmA256KW, utf8ToBytes('kek-1'))

    const msg = new EncryptMessage(payload, undefined, undefined, [
      Recipient.keyWrap(kek)
    ])
    const output = await msg.toBytes(cek, utf8ToBytes('aad'))

    const msg2 = await EncryptMessage.fromBytes(
      [kek],
      output,
      utf8ToBytes('aad')
    )
    assert.deepEqual(msg2.payload, payload)

    // Wrong external data fails.
    await expect(
      EncryptMessage.fromBytes([kek], output, utf8ToBytes('bad'))
    ).rejects.toThrow(/decryption failed/)

    // Wrong KEK fails.
    const otherKek = AesKwKey.generate(iana.AlgorithmA256KW)
    await expect(
      EncryptMessage.fromBytes([otherKek], output, utf8ToBytes('aad'))
    ).rejects.toThrow(/decryption failed/)
  })

  it('rejects tampered ciphertext', async () => {
    const cek = AesGcmKey.generate(iana.AlgorithmA256GCM)
    const kek = AesKwKey.generate(iana.AlgorithmA128KW)
    const msg = new EncryptMessage(payload, undefined, undefined, [
      Recipient.keyWrap(kek)
    ])
    const output = await msg.toBytes(cek)

    // Flip a byte in the middle of the serialized message (within ciphertext).
    output[Math.floor(output.length / 2)] ^= 0xff
    await expect(EncryptMessage.fromBytes([kek], output)).rejects.toThrow()
  })
})
