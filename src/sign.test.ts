// (c) 2023-present, LDC Labs. All rights reserved.
// See the file LICENSE for licensing terms.

import { assert, describe, it } from 'vitest'
import * as iana from './iana'
import { base64ToBytes, bytesToHex, utf8ToBytes } from './utils'
import { Header } from './header'
import { ECDSAKey } from './ecdsa'
import { Ed25519Key } from './ed25519'
import { SignMessage, Signature } from './sign'

const payload = utf8ToBytes('This is the content.')

describe('SignMessage', () => {
  // RFC 9052 Appendix C.1.1: Single Signature (ECDSA w/ SHA-256, P-256).
  it('C.1.1: single signature matches the RFC test vector', () => {
    const key = ECDSAKey.fromSecret(
      base64ToBytes('V8kgd2ZBRuh2dgyVINBUqpPDr7BOMGcF22CQMIUHtNM')
    )
    const sig = new Signature(
      new Header().setParam(iana.HeaderParameterAlg, iana.AlgorithmES256),
      new Header().setParam(iana.HeaderParameterKid, utf8ToBytes('11'))
    )
    const msg = new SignMessage(payload, undefined, undefined, [sig])
    const output = SignMessage.withTag(msg.toBytes([key]))

    assert.equal(
      bytesToHex(output),
      'd8628440a054546869732069732074686520636f6e74656e742e818343a10126' +
        'a1044231315840e2aeafd40d69d19dfe6e52077c5d7ff4e408282cbefb5d06cb' +
        'f414af2e19d982ac45ac98b8544c908b4507de1e90b717c3d34816fe926a2b98' +
        'f53afd2fa0f30a'
    )

    // Round-trips and verifies.
    const msg2 = SignMessage.fromBytes([key], output)
    assert.deepEqual(msg2.payload, payload)
    assert.equal(msg2.signatures.length, 1)
  })

  it('round-trips a message with two signers', () => {
    const k1 = ECDSAKey.generate(iana.AlgorithmES256, utf8ToBytes('ec'))
    const k2 = Ed25519Key.generate('ed')

    const msg = new SignMessage(payload)
    const output = msg.toBytes([k1, k2])

    // Both public keys must verify.
    const verified = SignMessage.fromBytes([k1.public(), k2.public()], output)
    assert.deepEqual(verified.payload, payload)
    assert.equal(verified.signatures.length, 2)

    // A single signer is also accepted as present.
    const one = SignMessage.fromBytes([k2.public()], output)
    assert.equal(one.signatures.length, 2)
  })

  it('rejects when a provided key has no valid signature', () => {
    const k1 = ECDSAKey.generate(iana.AlgorithmES256)
    const msg = new SignMessage(payload)
    const output = msg.toBytes([k1])

    const stranger = Ed25519Key.generate()
    assert.throw(
      () => SignMessage.fromBytes([stranger], output),
      /no signature verified/
    )
  })

  it('rejects external data tampering', () => {
    const key = ECDSAKey.generate(iana.AlgorithmES256)
    const msg = new SignMessage(payload)
    const output = msg.toBytes([key], utf8ToBytes('aad'))

    SignMessage.fromBytes([key.public()], output, utf8ToBytes('aad'))
    assert.throw(() =>
      SignMessage.fromBytes([key.public()], output, utf8ToBytes('bad'))
    )
  })
})
