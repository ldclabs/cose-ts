// (c) 2023-present, LDC Labs. All rights reserved.
// See the file LICENSE for licensing terms.

import { assert, describe, it } from 'vitest'
import { bytesToHex, hexToBytes, utf8ToBytes } from './utils'
import * as iana from './iana'
import { AesGcmKey } from './aesgcm'

describe('AesGcmKey Examples', () => {
  it('AlgorithmA128GCM', async () => {
    const key = AesGcmKey.fromSecret(
      hexToBytes('849B57219DAE48DE646D07DBB533566E')
    )
    assert.equal(key.alg, iana.AlgorithmA128GCM)

    const ciphertext = await key.encrypt(
      utf8ToBytes('This is the content.'),
      hexToBytes('02D1F7E6F26C43D4868D87CE'),
      hexToBytes('8367456E637279707443A1010140')
    )
    assert.equal(
      bytesToHex(ciphertext).toUpperCase(),
      '60973A94BB2898009EE52ECFD9AB1DD25867374B3581F2C80039826350B97AE2300E42FC'
    )

    const plaintext = await key.decrypt(
      ciphertext,
      hexToBytes('02D1F7E6F26C43D4868D87CE'),
      hexToBytes('8367456E637279707443A1010140')
    )
    assert.equal(
      bytesToHex(plaintext),
      bytesToHex(utf8ToBytes('This is the content.'))
    )

    let err = null
    try {
      await key.decrypt(
        ciphertext,
        hexToBytes('02D1F7E6F26C43D4868D87CE'),
        hexToBytes('8367456E637279707443A1010141')
      )
    } catch (_err) {
      err = _err
    }
    assert.exists(err)
  })

  it('AlgorithmA192GCM', async () => {
    const key = AesGcmKey.fromSecret(
      hexToBytes('0F1E2D3C4B5A69788796A5B4C3D2E1F01F2E3D4C5B6A7988')
    )
    assert.equal(key.alg, iana.AlgorithmA192GCM)

    const ciphertext = await key.encrypt(
      utf8ToBytes('This is the content.'),
      hexToBytes('02D1F7E6F26C43D4868D87CE'),
      hexToBytes('8367456E637279707443A1010240')
    )
    assert.equal(
      bytesToHex(ciphertext).toUpperCase(),
      '134D3B9223A00C1552C77585C157F467F295919D12124F19F521484C0725410947B4D1CA'
    )

    const plaintext = await key.decrypt(
      ciphertext,
      hexToBytes('02D1F7E6F26C43D4868D87CE'),
      hexToBytes('8367456E637279707443A1010240')
    )
    assert.equal(
      bytesToHex(plaintext),
      bytesToHex(utf8ToBytes('This is the content.'))
    )

    let err = null
    try {
      await key.decrypt(
        ciphertext,
        hexToBytes('02D1F7E6F26C43D4868D87CE'),
        hexToBytes('8367456E637279707443A1010241')
      )
    } catch (_err) {
      err = _err
    }
    assert.exists(err)
  })

  it('AlgorithmA256GCM', async () => {
    const key = AesGcmKey.fromSecret(
      hexToBytes(
        '0F1E2D3C4B5A69788796A5B4C3D2E1F01F2E3D4C5B6A798897A6B5C4D3E2F100'
      )
    )
    assert.equal(key.alg, iana.AlgorithmA256GCM)

    const ciphertext = await key.encrypt(
      utf8ToBytes('This is the content.'),
      hexToBytes('02D1F7E6F26C43D4868D87CE'),
      hexToBytes('8367456E637279707443A1010340')
    )
    assert.equal(
      bytesToHex(ciphertext).toUpperCase(),
      '9D64A5A59A3B04867DCCF6B8EF82F7D1A3B25EF862B6EDDB29DF2EF16582172E5B5FC757'
    )

    const plaintext = await key.decrypt(
      ciphertext,
      hexToBytes('02D1F7E6F26C43D4868D87CE'),
      hexToBytes('8367456E637279707443A1010340')
    )
    assert.equal(
      bytesToHex(plaintext),
      bytesToHex(utf8ToBytes('This is the content.'))
    )

    let err = null
    try {
      await key.decrypt(
        ciphertext,
        hexToBytes('02D1F7E6F26C43D4868D87CE'),
        hexToBytes('8367456E637279707443A1010341')
      )
    } catch (_err) {
      err = _err
    }
    assert.exists(err)
  })
})
