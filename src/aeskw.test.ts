// (c) 2023-present, LDC Labs. All rights reserved.
// See the file LICENSE for licensing terms.

import { assert, describe, it } from 'vitest'
import * as iana from './iana'
import { hexToBytes, bytesToHex } from './utils'
import { AesKwKey } from './aeskw'

describe('AesKwKey (RFC 3394)', () => {
  it('4.1: wraps a 128-bit key with a 128-bit KEK', () => {
    const kek = AesKwKey.fromSecret(
      hexToBytes('000102030405060708090a0b0c0d0e0f')
    )
    assert.equal(kek.alg, iana.AlgorithmA128KW)
    const wrapped = kek.wrapKey(hexToBytes('00112233445566778899aabbccddeeff'))
    assert.equal(
      bytesToHex(wrapped).toUpperCase(),
      '1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5'
    )
    assert.equal(
      bytesToHex(kek.unwrapKey(wrapped)),
      '00112233445566778899aabbccddeeff'
    )
  })

  it('4.6: wraps a 256-bit key with a 256-bit KEK', () => {
    const kek = AesKwKey.fromSecret(
      hexToBytes(
        '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'
      )
    )
    assert.equal(kek.alg, iana.AlgorithmA256KW)
    const wrapped = kek.wrapKey(
      hexToBytes(
        '00112233445566778899aabbccddeeff000102030405060708090a0b0c0d0e0f'
      )
    )
    assert.equal(
      bytesToHex(wrapped).toUpperCase(),
      '28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21'
    )
  })

  it('round-trips a generated key', () => {
    const kek = AesKwKey.generate(iana.AlgorithmA192KW)
    const cek = hexToBytes('00112233445566778899aabbccddeeff')
    assert.deepEqual(kek.unwrapKey(kek.wrapKey(cek)), cek)
  })
})
