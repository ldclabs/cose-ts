// (c) 2023-present, LDC Labs. All rights reserved.
// See the file LICENSE for licensing terms.

// Regression tests for the RFC 9052 processing rules enforced by cose-ts:
//   - "crit" critical header parameters (§3.1)
//   - the same label MUST NOT occur in both header buckets (§3)
//   - "alg" may be an int or a tstr (Table 3)
//   - key_ops usage restriction (§7.1)
//   - IV and Partial IV MUST NOT both be present (§3.1)
import { assert, describe, expect, it } from 'vitest'
import * as iana from './iana'
import { base64ToBytes, utf8ToBytes, encodeCBOR, decodeCBOR } from './utils'
import { Header } from './header'
import { ECDSAKey } from './ecdsa'
import { HMACKey } from './hmac'
import { AesGcmKey } from './aesgcm'
import { Sign1Message } from './sign1'
import { Mac0Message } from './mac0'
import { Encrypt0Message } from './encrypt0'

const ecSecret = base64ToBytes('V8kgd2ZBRuh2dgyVINBUqpPDr7BOMGcF22CQMIUHtNM')
const payload = utf8ToBytes('This is the content.')

describe('RFC 9052 compliance', () => {
  it('crit: rejects a critical label missing from the protected bucket', () => {
    const key = ECDSAKey.fromSecret(ecSecret)
    const msg = new Sign1Message(
      payload,
      new Header()
        .setParam(iana.HeaderParameterAlg, iana.AlgorithmES256)
        // crit references content type (3), but it is not in the bucket.
        .setParam(iana.HeaderParameterCrit, [iana.HeaderParameterContentType])
    )
    assert.throw(() => msg.toBytes(key), /critical header parameter/)
  })

  it('crit: accepts a critical label present in the protected bucket', () => {
    const key = ECDSAKey.fromSecret(ecSecret)
    const msg = new Sign1Message(
      payload,
      new Header()
        .setParam(iana.HeaderParameterAlg, iana.AlgorithmES256)
        .setParam(iana.HeaderParameterContentType, 0)
        .setParam(iana.HeaderParameterCrit, [iana.HeaderParameterContentType])
    )
    const output = msg.toBytes(key)
    const msg2 = Sign1Message.fromBytes(key, output)
    assert.deepEqual(msg2.payload, payload)
  })

  it('crit: rejects an empty crit array', () => {
    const key = ECDSAKey.fromSecret(ecSecret)
    const msg = new Sign1Message(
      payload,
      new Header()
        .setParam(iana.HeaderParameterAlg, iana.AlgorithmES256)
        .setParam(iana.HeaderParameterCrit, [])
    )
    assert.throw(() => msg.toBytes(key), /at least one value/)
  })

  it('headers: rejects a label present in both buckets', () => {
    const key = ECDSAKey.fromSecret(ecSecret)
    const msg = new Sign1Message(
      payload,
      new Header().setParam(iana.HeaderParameterAlg, iana.AlgorithmES256),
      // alg duplicated in the unprotected bucket.
      new Header().setParam(iana.HeaderParameterAlg, iana.AlgorithmES256)
    )
    assert.throw(() => msg.toBytes(key), /both the protected and unprotected/)
  })

  it('alg: a text-string alg yields a clean mismatch, not a TypeError', () => {
    const key = ECDSAKey.fromSecret(ecSecret)
    const msg = new Sign1Message(
      payload,
      new Header().setParam(iana.HeaderParameterAlg, 'ES256')
    )
    assert.throw(() => msg.toBytes(key), /alg mismatch/)
  })

  it('key_ops: signing requires the sign operation', () => {
    const key = ECDSAKey.fromSecret(ecSecret)
    key.ops = [iana.KeyOperationVerify]
    const msg = new Sign1Message(payload)
    assert.throw(() => msg.toBytes(key), /key_ops/)

    key.ops = [iana.KeyOperationSign]
    const output = msg.toBytes(key)
    const pub = key.public() // public() restricts ops to verify
    const msg2 = Sign1Message.fromBytes(pub, output)
    assert.deepEqual(msg2.payload, payload)
  })

  it('key_ops: MAC requires a MAC operation', () => {
    const key = HMACKey.fromSecret(
      base64ToBytes('hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYg'),
      iana.AlgorithmHMAC_256_256
    )
    key.ops = [iana.KeyOperationVerify] // signature verify, not MAC
    const msg = new Mac0Message(payload)
    assert.throw(() => msg.toBytes(key), /key_ops/)

    key.ops = [iana.KeyOperationMacCreate, iana.KeyOperationMacVerify]
    const output = msg.toBytes(key)
    const msg2 = Mac0Message.fromBytes(key, output)
    assert.deepEqual(msg2.payload, payload)
  })

  it('IV: rejects both IV and Partial IV in the same layer', async () => {
    const key = AesGcmKey.fromSecret(base64ToBytes('hJtXIZ2uSN5kbQfbtTNWbg'))
    const msg = new Encrypt0Message(
      payload,
      new Header().setParam(iana.HeaderParameterAlg, iana.AlgorithmA128GCM),
      new Header()
        .setParam(iana.HeaderParameterIV, new Uint8Array(12))
        .setParam(iana.HeaderParameterPartialIV, new Uint8Array([1]))
    )
    await expect(msg.toBytes(key)).rejects.toThrow(/must not both be present/)
  })

  it('encoding: an array element that is a map with >=4 entries keeps the array header', () => {
    // Regression: the deterministic map sorter used to re-enter cborg's encoder,
    // corrupting the shared buffer and dropping the enclosing array header for
    // maps with four or more entries.
    const four = new Map<number, number>([
      [1, 1],
      [2, 2],
      [3, 3],
      [4, 4]
    ])
    const decoded = decodeCBOR<unknown>(encodeCBOR([four]))
    assert.isTrue(Array.isArray(decoded))
    assert.equal((decoded as unknown[]).length, 1)
  })

  it('Sign1: round-trips an unprotected header with >=4 entries', () => {
    const key = ECDSAKey.fromSecret(ecSecret)
    const msg = new Sign1Message(
      payload,
      new Header().setParam(iana.HeaderParameterAlg, iana.AlgorithmES256),
      new Header()
        .setParam(iana.HeaderParameterKid, utf8ToBytes('11'))
        .setParam(iana.HeaderParameterContentType, 0)
        .setParam(100, 1)
        .setParam(101, 2)
    )
    const output = msg.toBytes(key)
    // The COSE_Sign1 structure must remain a 4-element array.
    const decoded = decodeCBOR<unknown[]>(output)
    assert.equal(decoded.length, 4)

    const msg2 = Sign1Message.fromBytes(key, output)
    assert.deepEqual(msg2.payload, payload)
  })

  it('IV: rejects an unsupported Partial IV', async () => {
    const key = AesGcmKey.fromSecret(base64ToBytes('hJtXIZ2uSN5kbQfbtTNWbg'))
    const msg = new Encrypt0Message(
      payload,
      new Header().setParam(iana.HeaderParameterAlg, iana.AlgorithmA128GCM),
      new Header().setParam(iana.HeaderParameterPartialIV, new Uint8Array([1]))
    )
    await expect(msg.toBytes(key)).rejects.toThrow(
      /Partial IV is not supported/
    )
  })
})
