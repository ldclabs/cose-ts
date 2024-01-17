// (c) 2023-present, LDC Labs. All rights reserved.
// See the file LICENSE for licensing terms.

import { assert, describe, it } from 'vitest'
import { bytesToHex, hexToBytes, utf8ToBytes } from './utils'
import * as iana from './iana'
import { ChaCha20Poly1305Key } from './chacha20poly1305'

describe('ChaCha20Poly1305Key Examples', () => {
  // https://github.com/cose-wg/Examples/tree/master/chacha-poly-examples
  // https://github.com/cose-wg/Examples/pull/104
  it('Examples', async () => {
    const key = ChaCha20Poly1305Key.fromSecret(
      hexToBytes(
        '0F1E2D3C4B5A69788796A5B4C3D2E1F01F2E3D4C5B6A798897A6B5C4D3E2F100'
      )
    )
    assert.equal(key.alg, iana.AlgorithmChaCha20Poly1305)

    const ciphertext = await key.encrypt(
      utf8ToBytes('This is the content.'),
      hexToBytes('26682306D4FB28CA01B43B80'),
      hexToBytes('8367456E637279707444A101181840')
    )

    assert.equal(
      bytesToHex(ciphertext).toUpperCase(),
      '1CD5D49DAA014CCAFFB30E765DC5CD410689AAE1C60B45648853298FF6808DB3FA8235DB'
    )

    const plaintext = await key.decrypt(
      ciphertext,
      hexToBytes('26682306D4FB28CA01B43B80'),
      hexToBytes('8367456E637279707444A101181840')
    )
    assert.equal(
      bytesToHex(plaintext),
      bytesToHex(utf8ToBytes('This is the content.'))
    )

    let err = null
    try {
      await key.decrypt(
        ciphertext,
        hexToBytes('26682306D4FB28CA01B43B80'),
        hexToBytes('8367456E637279707444A101181841')
      )
    } catch (_err) {
      err = _err
    }
    assert.exists(err)
  })
})
