// (c) 2023-present, LDC Labs. All rights reserved.
// See the file LICENSE for licensing terms.

// Coverage tests for the COSE message classes and helpers.
import { assert, describe, expect, it } from 'vitest'
import * as iana from './iana'
import { encodeCBOR, utf8ToBytes, hexToBytes } from './utils'
import { Header } from './header'
import { ECDSAKey } from './ecdsa'
import { HMACKey } from './hmac'
import { AesGcmKey } from './aesgcm'
import { AesKwKey } from './aeskw'
import { Key } from './key'
import { Sign1Message } from './sign1'
import { SignMessage, Signature } from './sign'
import { Mac0Message } from './mac0'
import { MacMessage } from './mac'
import { Encrypt0Message } from './encrypt0'
import { EncryptMessage } from './encrypt'
import { Recipient } from './recipient'
import { KDFContext, PartyInfo, SuppPubInfo } from './kdfcontext'
import { Claims, Validator } from './cwt'

const payload = utf8ToBytes('This is the content.')

describe('sign coverage', () => {
  it('toBytes validates keys and signatures', () => {
    assert.throws(() => new SignMessage(payload).toBytes([]))

    // signatures/keys length mismatch
    const k1 = ECDSAKey.generate(iana.AlgorithmES256)
    const msg = new SignMessage(payload, undefined, undefined, [
      new Signature()
    ])
    assert.throws(() => msg.toBytes([k1, k1]))

    // per-signature alg mismatch
    const sig = new Signature(
      new Header().setParam(iana.HeaderParameterAlg, iana.AlgorithmES384)
    )
    const msg2 = new SignMessage(payload, undefined, undefined, [sig])
    assert.throws(() => msg2.toBytes([k1]))
  })

  it('fromBytes rejects an empty signatures array', () => {
    const data = encodeCBOR([new Uint8Array(), new Map(), payload, []])
    const k1 = ECDSAKey.generate(iana.AlgorithmES256)
    assert.throws(() => SignMessage.fromBytes([k1.public()], data))
  })
})

describe('sign1 coverage', () => {
  it('fromBytes rejects an algorithm mismatch', () => {
    const k256 = ECDSAKey.generate(iana.AlgorithmES256)
    const out = new Sign1Message(
      payload,
      new Header().setParam(iana.HeaderParameterAlg, iana.AlgorithmES256)
    ).toBytes(k256)
    const k384 = ECDSAKey.generate(iana.AlgorithmES384)
    assert.throws(() => Sign1Message.fromBytes(k384, out))
  })
})

describe('mac coverage', () => {
  it('toBytes requires recipients and a matching algorithm', () => {
    assert.throws(() => new MacMessage(payload).toBytes(HMACKey.generate(5)))

    const msg = new MacMessage(
      payload,
      new Header().setParam(
        iana.HeaderParameterAlg,
        iana.AlgorithmHMAC_256_256
      ),
      undefined,
      undefined,
      [Recipient.direct()]
    )
    const k384 = HMACKey.generate(iana.AlgorithmHMAC_384_384)
    assert.throws(() => msg.toBytes(k384))
  })

  it('toBytes rejects mixing direct recipients with other MAC modes', () => {
    const macKey = HMACKey.generate(iana.AlgorithmHMAC_256_256)
    const kek = AesKwKey.fromSecret(new Uint8Array(32))
    const msg = new MacMessage(
      payload,
      new Header().setParam(
        iana.HeaderParameterAlg,
        iana.AlgorithmHMAC_256_256
      ),
      undefined,
      undefined,
      [Recipient.direct(), Recipient.keyWrap(kek)]
    )
    assert.throws(() => msg.toBytes(macKey), /direct recipient mode/)
  })

  it('fromBytes rejects no recipients and unsupported content algorithms', () => {
    const protectedBytes = new Header()
      .setParam(iana.HeaderParameterAlg, iana.AlgorithmHMAC_256_256)
      .toBytes()
    const noRecips = encodeCBOR([
      protectedBytes,
      new Map(),
      payload,
      new Uint8Array(8),
      []
    ])
    assert.throws(() => MacMessage.fromBytes([HMACKey.generate(5)], noRecips))

    // body alg that is not a MAC algorithm → makeMACer throws (caught) → tag mismatch
    const badAlg = encodeCBOR([
      new Header()
        .setParam(iana.HeaderParameterAlg, iana.AlgorithmA128GCM)
        .toBytes(),
      new Map(),
      payload,
      new Uint8Array(8),
      [
        [
          new Uint8Array(),
          new Map([[1, iana.AlgorithmDirect]]),
          new Uint8Array()
        ]
      ]
    ])
    assert.throws(() => MacMessage.fromBytes([HMACKey.generate(5)], badAlg))
  })
})

describe('mac0 coverage', () => {
  it('fromBytes rejects an algorithm mismatch', () => {
    const k = HMACKey.fromSecret(new Uint8Array(32), iana.AlgorithmHMAC_256_256)
    const out = new Mac0Message(
      payload,
      new Header().setParam(iana.HeaderParameterAlg, iana.AlgorithmHMAC_256_256)
    ).toBytes(k)
    const k2 = HMACKey.fromSecret(new Uint8Array(32), iana.AlgorithmHMAC_256_64)
    assert.throws(() => Mac0Message.fromBytes(k2, out))
  })

  it('toBytes pulls kid from the key when headers are absent', () => {
    const k = HMACKey.fromSecret(
      new Uint8Array(32),
      iana.AlgorithmHMAC_256_256,
      utf8ToBytes('kid-1')
    )
    const out = new Mac0Message(payload).toBytes(k)
    const msg = Mac0Message.fromBytes(k, out)
    assert.deepEqual(msg.payload, payload)
  })
})

describe('encrypt0 coverage', () => {
  it('toBytes validates the algorithm and IV size', async () => {
    const k128 = AesGcmKey.fromSecret(new Uint8Array(16))

    const wrongAlg = new Encrypt0Message(
      payload,
      new Header().setParam(iana.HeaderParameterAlg, iana.AlgorithmA256GCM)
    )
    await expect(wrongAlg.toBytes(k128)).rejects.toThrow(/alg mismatch/)

    const wrongIV = new Encrypt0Message(
      payload,
      new Header().setParam(iana.HeaderParameterAlg, iana.AlgorithmA128GCM),
      new Header().setParam(iana.HeaderParameterIV, new Uint8Array(11))
    )
    await expect(wrongIV.toBytes(k128)).rejects.toThrow(/iv size mismatch/)
  })

  it('fromBytes rejects an algorithm mismatch', async () => {
    const k128 = AesGcmKey.fromSecret(new Uint8Array(16))
    const out = await new Encrypt0Message(
      payload,
      new Header().setParam(iana.HeaderParameterAlg, iana.AlgorithmA128GCM)
    ).toBytes(k128)
    const k256 = AesGcmKey.fromSecret(new Uint8Array(32))
    await expect(Encrypt0Message.fromBytes(k256, out)).rejects.toThrow(
      /alg mismatch/
    )
  })
})

describe('encrypt coverage', () => {
  it('toBytes validates recipients, algorithm and IV', async () => {
    const k128 = AesGcmKey.fromSecret(new Uint8Array(16))
    await expect(new EncryptMessage(payload).toBytes(k128)).rejects.toThrow(
      /no recipients/
    )

    const wrongAlg = new EncryptMessage(
      payload,
      new Header().setParam(iana.HeaderParameterAlg, iana.AlgorithmA256GCM),
      undefined,
      [Recipient.direct()]
    )
    await expect(wrongAlg.toBytes(k128)).rejects.toThrow(/alg mismatch/)

    const wrongIV = new EncryptMessage(
      payload,
      new Header().setParam(iana.HeaderParameterAlg, iana.AlgorithmA128GCM),
      new Header().setParam(iana.HeaderParameterIV, new Uint8Array(11)),
      [Recipient.direct()]
    )
    await expect(wrongIV.toBytes(k128)).rejects.toThrow(/iv size mismatch/)
  })

  it('toBytes rejects conflicting / unsupported IV parameters', async () => {
    const k128 = AesGcmKey.fromSecret(new Uint8Array(16))
    const both = new EncryptMessage(
      payload,
      new Header().setParam(iana.HeaderParameterAlg, iana.AlgorithmA128GCM),
      new Header()
        .setParam(iana.HeaderParameterIV, new Uint8Array(12))
        .setParam(iana.HeaderParameterPartialIV, new Uint8Array([1])),
      [Recipient.direct()]
    )
    await expect(both.toBytes(k128)).rejects.toThrow(/must not both be present/)

    const partial = new EncryptMessage(
      payload,
      new Header().setParam(iana.HeaderParameterAlg, iana.AlgorithmA128GCM),
      new Header().setParam(iana.HeaderParameterPartialIV, new Uint8Array([1])),
      [Recipient.direct()]
    )
    await expect(partial.toBytes(k128)).rejects.toThrow(/Partial IV/)
  })

  it('toBytes rejects mixing direct recipients with other modes', async () => {
    const k128 = AesGcmKey.fromSecret(new Uint8Array(16))
    const kek = AesKwKey.fromSecret(new Uint8Array(32))
    const msg = new EncryptMessage(
      payload,
      new Header().setParam(iana.HeaderParameterAlg, iana.AlgorithmA128GCM),
      undefined,
      [Recipient.direct(), Recipient.keyWrap(kek)]
    )
    await expect(msg.toBytes(k128)).rejects.toThrow(/direct recipient mode/)
  })

  it('fromBytes rejects no recipients, bad content alg and IV size', async () => {
    const noRecips = encodeCBOR([
      new Header()
        .setParam(iana.HeaderParameterAlg, iana.AlgorithmA128GCM)
        .toBytes(),
      new Map([[iana.HeaderParameterIV, new Uint8Array(12)]]),
      new Uint8Array(28),
      []
    ])
    await expect(
      EncryptMessage.fromBytes(
        [AesGcmKey.fromSecret(new Uint8Array(16))],
        noRecips
      )
    ).rejects.toThrow(/no recipients/)

    const directRecipient = [
      new Uint8Array(),
      new Map([[1, iana.AlgorithmDirect]]),
      new Uint8Array()
    ]

    // body alg HMAC is not an AEAD → makeEncryptor throws (caught) → decryption failed
    const badAlg = encodeCBOR([
      new Header()
        .setParam(iana.HeaderParameterAlg, iana.AlgorithmHMAC_256_256)
        .toBytes(),
      new Map([[iana.HeaderParameterIV, new Uint8Array(12)]]),
      new Uint8Array(28),
      [directRecipient]
    ])
    await expect(
      EncryptMessage.fromBytes(
        [HMACKey.generate(iana.AlgorithmHMAC_256_256)],
        badAlg
      )
    ).rejects.toThrow(/decryption failed/)

    // valid content key but wrong IV length → hard error
    const badIV = encodeCBOR([
      new Header()
        .setParam(iana.HeaderParameterAlg, iana.AlgorithmA128GCM)
        .toBytes(),
      new Map([[iana.HeaderParameterIV, new Uint8Array(11)]]),
      new Uint8Array(28),
      [directRecipient]
    ])
    await expect(
      EncryptMessage.fromBytes(
        [AesGcmKey.fromSecret(new Uint8Array(16))],
        badIV
      )
    ).rejects.toThrow(/iv size mismatch/)
  })
})

describe('recipient coverage', () => {
  it('keyWrap takes the kid from the KEK', () => {
    const kek = AesKwKey.fromSecret(new Uint8Array(32), utf8ToBytes('kek'))
    const r = Recipient.keyWrap(kek)
    assert.equal(r.alg(), iana.AlgorithmA256KW)
  })

  it('alg() reads from the protected bucket and tolerates absence', () => {
    const withProtected = new Recipient(
      new Header().setParam(iana.HeaderParameterAlg, iana.AlgorithmA256KW)
    )
    assert.equal(withProtected.alg(), iana.AlgorithmA256KW)
    assert.equal(new Recipient().alg(), undefined)
  })

  it('fromCBORValue rejects malformed values and supports nesting', () => {
    assert.throws(() => Recipient.fromCBORValue(123))
    assert.throws(() =>
      Recipient.fromCBORValue([
        new Uint8Array(),
        new Map(),
        new Uint8Array(),
        []
      ])
    )

    const innerKek = AesKwKey.fromSecret(
      new Uint8Array(32),
      utf8ToBytes('inner')
    )
    const outerKek = AesKwKey.fromSecret(
      new Uint8Array(32),
      utf8ToBytes('outer')
    )
    const inner = Recipient.keyWrap(innerKek)
    const outer = Recipient.keyWrap(outerKek)
    outer.recipients = [inner]
    const encoded = outer.encode(new Uint8Array(16))
    const decoded = Recipient.fromCBORValue(encoded)
    assert.equal(decoded.recipients.length, 1)

    const direct = Recipient.direct()
    direct.recipients = [Recipient.direct()]
    assert.throws(() => direct.encode(new Uint8Array(16)), /direct recipient/)
  })

  it('validates supported recipient algorithm shapes', () => {
    assert.throws(() =>
      Recipient.fromCBORValue([
        new Header()
          .setParam(iana.HeaderParameterAlg, iana.AlgorithmDirect)
          .toBytes(),
        new Map(),
        new Uint8Array()
      ])
    )
    assert.throws(() =>
      Recipient.fromCBORValue([
        new Uint8Array(),
        new Map([[iana.HeaderParameterAlg, iana.AlgorithmDirect]]),
        new Uint8Array([1])
      ])
    )
    assert.throws(() =>
      Recipient.fromCBORValue([
        new Header()
          .setParam(iana.HeaderParameterAlg, iana.AlgorithmA256KW)
          .toBytes(),
        new Map(),
        new Uint8Array(40)
      ])
    )
    assert.throws(() =>
      Recipient.fromCBORValue([
        new Uint8Array(),
        new Map([[iana.HeaderParameterAlg, iana.AlgorithmA256KW]]),
        null
      ])
    )

    const unsupported = Recipient.fromCBORValue([
      new Uint8Array(),
      new Map([[iana.HeaderParameterAlg, -9999]]),
      null
    ])
    assert.equal(unsupported.ciphertext, null)

    assert.throws(() => new Recipient().encode(new Uint8Array(16)), /alg/)
    const badWrap = new Recipient(
      undefined,
      new Header().setParam(iana.HeaderParameterAlg, iana.AlgorithmA128KW)
    )
    assert.throws(() => badWrap.encode(new Uint8Array(16)), /key wrapper/)

    const mismatchedWrap = Recipient.keyWrap(
      AesKwKey.fromSecret(new Uint8Array(32))
    )
    mismatchedWrap.unprotected?.setParam(
      iana.HeaderParameterAlg,
      iana.AlgorithmA128KW
    )
    assert.throws(
      () => mismatchedWrap.encode(new Uint8Array(16)),
      /alg mismatch/
    )
  })

  it('recoverCEK fails when the key cannot unwrap', () => {
    const r = new Recipient(
      undefined,
      new Header().setParam(iana.HeaderParameterAlg, iana.AlgorithmA256KW)
    )
    r.ciphertext = new Uint8Array(40)
    const plain = new Key()
    plain.kty = iana.KeyTypeSymmetric
    assert.throws(() => r.recoverCEK(plain))

    const wrongAlg = HMACKey.generate(iana.AlgorithmHMAC_256_256)
    assert.throws(() => r.recoverCEK(wrongAlg), /alg mismatch/)

    assert.throws(() => new Recipient().recoverCEK(plain), /alg/)

    const missingCiphertext = new Recipient(
      undefined,
      new Header().setParam(iana.HeaderParameterAlg, iana.AlgorithmA256KW)
    )
    missingCiphertext.ciphertext = null
    assert.throws(
      () =>
        missingCiphertext.recoverCEK(AesKwKey.fromSecret(new Uint8Array(32))),
      /encrypted content key/
    )
  })
})

describe('kdfcontext coverage', () => {
  it('round-trips with SuppPrivInfo and SuppPubInfo other', () => {
    const ctx = new KDFContext(
      iana.AlgorithmA128GCM,
      new PartyInfo(utf8ToBytes('U')),
      new PartyInfo(null, utf8ToBytes('nonce')),
      new SuppPubInfo(128, new Header(), utf8ToBytes('pub-other')),
      utf8ToBytes('priv')
    )
    const ctx2 = KDFContext.fromBytes(ctx.toBytes())
    assert.equal(ctx2.algorithmID, iana.AlgorithmA128GCM)
    assert.deepEqual(ctx2.suppPrivInfo, utf8ToBytes('priv'))
    assert.deepEqual(ctx2.suppPubInfo.other, utf8ToBytes('pub-other'))
  })

  it('rejects malformed encodings', () => {
    assert.throws(() => KDFContext.fromBytes(new Uint8Array()))
    assert.throws(() => KDFContext.fromBytes(encodeCBOR([1, 2, 3])))
    assert.throws(() => SuppPubInfo.fromCBORValue([1]))
  })
})

describe('cwt coverage', () => {
  it('cnf / scope / nonce round-trip', () => {
    const claims = new Claims()
    const cnf = new Map<number, unknown>([[1, hexToBytes('00')]])
    claims.cnf = cnf
    claims.scope = 'read write'
    claims.nonce = hexToBytes('aabb')
    assert.deepEqual(claims.cnf, cnf)
    assert.equal(claims.scope, 'read write')
    assert.deepEqual(claims.nonce, hexToBytes('aabb'))
  })

  it('rejects an iat in the future when configured', () => {
    const validator = new Validator({
      allowMissingExpiration: true,
      expectIssuedInThePast: true
    })
    const claims = new Claims()
    claims.iat = Math.floor(Date.now() / 1000) + 10000
    assert.throws(() => validator.validate(claims))
  })
})
