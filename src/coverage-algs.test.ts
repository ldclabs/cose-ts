// (c) 2023-present, LDC Labs. All rights reserved.
// See the file LICENSE for licensing terms.

// Coverage tests for the symmetric algorithm classes.
import { assert, describe, it } from 'vitest'
import * as iana from './iana'
import { randomBytes, utf8ToBytes, bytesToHex } from './utils'
import { AesGcmKey } from './aesgcm'
import { AesKwKey } from './aeskw'
import { ChaCha20Poly1305Key } from './chacha20poly1305'
import { HMACKey } from './hmac'

describe('aesgcm coverage', () => {
  it('covers all key sizes and rejects invalid ones', () => {
    assert.equal(
      AesGcmKey.generate(iana.AlgorithmA192GCM).alg,
      iana.AlgorithmA192GCM
    )
    assert.equal(
      AesGcmKey.generate(iana.AlgorithmA256GCM).alg,
      iana.AlgorithmA256GCM
    )
    assert.throws(() => AesGcmKey.generate(99999))
    assert.throws(() => AesGcmKey.fromSecret(new Uint8Array(20)))

    const k = AesGcmKey.generate(iana.AlgorithmA128GCM)
    assert.equal(AesGcmKey.fromBytes(k.toBytes()).alg, iana.AlgorithmA128GCM)
  })
})

describe('aeskw coverage', () => {
  it('covers fromBytes and rejects invalid sizes', () => {
    const k = AesKwKey.generate(iana.AlgorithmA128KW)
    assert.equal(AesKwKey.fromBytes(k.toBytes()).alg, iana.AlgorithmA128KW)
    assert.throws(() => AesKwKey.generate(99999))
    assert.throws(() => AesKwKey.fromSecret(new Uint8Array(20)))
  })
})

describe('chacha20poly1305 coverage', () => {
  it('rejects wrong-sized secrets and accepts a kid', () => {
    assert.throws(() => ChaCha20Poly1305Key.fromSecret(new Uint8Array(31)))
    const k = ChaCha20Poly1305Key.fromSecret(randomBytes(32), utf8ToBytes('cc'))
    assert.equal(k.alg, iana.AlgorithmChaCha20Poly1305)
    assert.equal(
      ChaCha20Poly1305Key.fromBytes(k.toBytes()).alg,
      iana.AlgorithmChaCha20Poly1305
    )
  })
})

describe('hmac coverage', () => {
  it('rejects a wrong-sized secret and unknown algorithm', () => {
    assert.throws(() =>
      HMACKey.fromSecret(new Uint8Array(8), iana.AlgorithmHMAC_256_256)
    )
    assert.throws(() => HMACKey.generate(99999))
  })

  it('covers every HMAC variant tag size', () => {
    const msg = utf8ToBytes('mac me')
    for (const alg of [
      iana.AlgorithmHMAC_256_64,
      iana.AlgorithmHMAC_256_256,
      iana.AlgorithmHMAC_384_384,
      iana.AlgorithmHMAC_512_512
    ]) {
      const k = HMACKey.generate(alg)
      const k2 = HMACKey.fromBytes(k.toBytes())
      assert.equal(bytesToHex(k.mac(msg)), bytesToHex(k2.mac(msg)))
    }
  })
})
