// (c) 2023-present, LDC Labs. All rights reserved.
// See the file LICENSE for licensing terms.

// Supplementary coverage for header-defaulting branches, setters and throws.
import { assert, describe, expect, it } from 'vitest'
import * as iana from './iana'
import { compareBytes, encodeCBOR, utf8ToBytes, hexToBytes } from './utils'
import { skipTag, CwtPrefix } from './tag'
import { Header } from './header'
import { Key } from './key'
import { ECDHKey, getKeySize } from './ecdh'
import { ECDSAKey } from './ecdsa'
import { HMACKey } from './hmac'
import { AesGcmKey } from './aesgcm'
import { AesKwKey } from './aeskw'
import { Mac0Message } from './mac0'
import { MacMessage } from './mac'
import { Encrypt0Message } from './encrypt0'
import { Recipient } from './recipient'
import { Claims, Validator } from './cwt'

const payload = utf8ToBytes('This is the content.')

describe('supplementary coverage', () => {
  it('skipTag returns data shorter than a multi-byte tag', () => {
    const data = new Uint8Array([0x01])
    assert.equal(skipTag(CwtPrefix, data), data)
  })

  it('compareBytes short-circuits identical references', () => {
    const a = new Uint8Array([1, 2, 3])
    assert.equal(compareBytes(a, a), 0)
  })

  it('Key.ops setter rejects non-arrays; getSecret reads EC2 keys', () => {
    const key = new Key()
    key.kty = iana.KeyTypeSymmetric
    assert.throws(() => {
      key.ops = 5 as never
    })

    const ec = new Key()
    ec.kty = iana.KeyTypeEC2
    ec.setParam(iana.EC2KeyParameterD, hexToBytes('0102'))
    assert.deepEqual(ec.getSecret(), hexToBytes('0102'))

    const okp = new Key()
    okp.kty = iana.KeyTypeOKP
    okp.setParam(iana.OKPKeyParameterD, hexToBytes('0304'))
    assert.deepEqual(okp.getSecret(), hexToBytes('0304'))
  })

  it('ECDSAKey.fromPublic handles an even-y compressed key', () => {
    const evenX = hexToBytes(
      '65eda5a12577c2bae829437fe338701a10aaa375e1bb5b5de108de439c08551d'
    )
    const k = ECDSAKey.fromPublic(new Uint8Array([0x02, ...evenX]))
    assert.equal(k.getBool(iana.EC2KeyParameterY), false)
  })

  it('ECDHKey.fromSecret accepts a kid; fromPublic checks x25519 size', () => {
    const k = ECDHKey.generate(iana.EllipticCurveP_256, hexToBytes('01'))
    assert.equal(k.crv, iana.EllipticCurveP_256)
    assert.throws(() =>
      ECDHKey.fromPublic(iana.EllipticCurveX25519, new Uint8Array(31))
    )
  })

  it('ECDHKey.fromPublic handles both compressed parities', () => {
    // even y (0x02): RFC 9052 "meriadoc" P-256 key
    const evenX = hexToBytes(
      '65eda5a12577c2bae829437fe338701a10aaa375e1bb5b5de108de439c08551d'
    )
    const even = ECDHKey.fromPublic(
      iana.EllipticCurveP_256,
      new Uint8Array([0x02, ...evenX])
    )
    assert.equal(even.getBool(iana.EC2KeyParameterY), false)

    // odd y (0x03): RFC 9052 "peregrin" P-256 key
    const oddX = hexToBytes(
      '98f50a4ff6c05861c8860d13a638ea56c3f5ad7590bbfbf054e1c7b4d91d6280'
    )
    const odd = ECDHKey.fromPublic(
      iana.EllipticCurveP_256,
      new Uint8Array([0x03, ...oddX])
    )
    assert.equal(odd.getBool(iana.EC2KeyParameterY), true)

    // getKeySize for x25519
    assert.equal(getKeySize(iana.EllipticCurveX25519), 32)
  })

  it('Recipient.keyWrap accepts an explicit kid', () => {
    const kek = AesKwKey.generate(iana.AlgorithmA256KW)
    const r = Recipient.keyWrap(kek, utf8ToBytes('explicit'))
    assert.equal(r.alg(), iana.AlgorithmA256KW)
  })

  it('Mac0Message.toBytes auto-fills headers and checks alg', () => {
    // protected/unprotected default from the key (alg + kid)
    const k = HMACKey.fromSecret(
      new Uint8Array(32),
      iana.AlgorithmHMAC_256_256,
      utf8ToBytes('kid')
    )
    const out = new Mac0Message(payload).toBytes(k)
    assert.deepEqual(Mac0Message.fromBytes(k, out).payload, payload)

    // protected alg conflicting with the key
    const bad = new Mac0Message(
      payload,
      new Header().setParam(iana.HeaderParameterAlg, iana.AlgorithmHMAC_256_64)
    )
    assert.throws(() => bad.toBytes(k))
  })

  it('MacMessage.toBytes defaults the protected header from the key', () => {
    const msg = new MacMessage(payload, undefined, undefined, undefined, [
      Recipient.direct()
    ])
    const k = HMACKey.generate(iana.AlgorithmHMAC_256_256)
    const out = msg.toBytes(k)
    assert.deepEqual(MacMessage.fromBytes([k], out).payload, payload)
  })

  it('Encrypt0Message.toBytes defaults headers; fromBytes checks IV size', async () => {
    const k = AesGcmKey.fromSecret(new Uint8Array(16), utf8ToBytes('kid'))
    const out = await new Encrypt0Message(payload).toBytes(k)
    const msg = await Encrypt0Message.fromBytes(k, out)
    assert.deepEqual(msg.payload, payload)

    // a message whose IV has the wrong length
    const badIV = encodeCBOR([
      new Header()
        .setParam(iana.HeaderParameterAlg, iana.AlgorithmA128GCM)
        .toBytes(),
      new Map([[iana.HeaderParameterIV, new Uint8Array(11)]]),
      new Uint8Array(28)
    ])
    await expect(Encrypt0Message.fromBytes(k, badIV)).rejects.toThrow(
      /iv size mismatch/
    )
  })

  it('HMACKey.mac rejects an algorithm without a defined tag size', () => {
    const k = new HMACKey()
    k.alg = iana.AlgorithmES256
    k.setParam(iana.SymmetricKeyParameterK, new Uint8Array(32))
    assert.throws(() => k.mac(utf8ToBytes('x')))
  })

  it('Validator rejects a non-positive expiration', () => {
    const validator = new Validator()
    const claims = new Claims()
    claims.exp = -1
    assert.throws(() => validator.validate(claims))
  })
})
