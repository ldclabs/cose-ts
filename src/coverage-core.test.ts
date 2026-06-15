// (c) 2023-present, LDC Labs. All rights reserved.
// See the file LICENSE for licensing terms.

// Coverage tests for core utilities: utils, map, tag, hash, header, key, keyset.
import { assert, describe, it } from 'vitest'
import * as iana from './iana'
import {
  compareBytes,
  equalBytes,
  assertEqual,
  encodeCBOR,
  decodeCBOR,
  hexToBytes,
  utf8ToBytes
} from './utils'
import {
  KVMap,
  assertText,
  assertInt,
  assertIntOrText,
  assertBytes,
  assertBool,
  assertMap
} from './map'
import { skipTag, Sign1MessagePrefix } from './tag'
import { getHash } from './hash'
import { Header, verifyHeaders } from './header'
import { Key } from './key'
import { KeySet } from './keyset'

describe('utils coverage', () => {
  it('compareBytes / equalBytes / assertEqual', () => {
    // a is a strict prefix of b → -1
    assert.equal(
      compareBytes(new Uint8Array([1, 2]), new Uint8Array([1, 2, 3])),
      -1
    )
    assert.equal(
      compareBytes(new Uint8Array([1, 2, 3]), new Uint8Array([1, 2])),
      1
    )
    assert.throws(() => compareBytes(1 as never, 2 as never))
    assert.throws(() => equalBytes(1 as never, 2 as never))
    assert.throws(() => assertEqual(1, 2))
    assertEqual(1, 1)
  })

  it('deterministic map sorter handles all key magnitudes and rejects complex keys', () => {
    // Integer keys spanning every cborHead branch (1B, 2B, 4B, 8B argument).
    const m = new Map<number, number>([
      [1, 0],
      [1000, 0],
      [70000, 0],
      [5000000000, 0]
    ])
    const decoded = decodeCBOR<Map<number, number>>(encodeCBOR(m))
    assert.equal(decoded.size, 4)

    // Text-string keys.
    const ms = new Map<string, number>([
      ['bb', 0],
      ['a', 0]
    ])
    assert.equal(decodeCBOR<Map<string, number>>(encodeCBOR(ms)).size, 2)

    // Byte-string keys are not supported by the sorter.
    assert.throws(() =>
      encodeCBOR(
        new Map<Uint8Array, number>([
          [new Uint8Array([2]), 0],
          [new Uint8Array([1]), 0]
        ])
      )
    )

    // Array (complex) keys are not supported.
    assert.throws(() =>
      encodeCBOR(
        new Map<number[], number>([
          [[2], 0],
          [[1], 0]
        ])
      )
    )
  })
})

describe('map coverage', () => {
  it('assert helpers reject the wrong type', () => {
    assert.throws(() => assertText(1, 'x'))
    assert.equal(assertText('a', 'x'), 'a')
    assert.throws(() => assertInt('x', 'x'))
    assert.throws(() => assertIntOrText(true, 'x'))
    assert.equal(assertIntOrText('a', 'x'), 'a')
    assert.equal(assertIntOrText(3, 'x'), 3)
    assert.throws(() => assertBytes('x', 'x'))
    assert.throws(() => assertBool(1, 'x'))
    assert.throws(() => assertMap(1, 'x'))
    assert.equal(assertMap(new Map()).size, 0)
  })

  it('KVMap accessors', () => {
    assert.throws(() => new KVMap(1 as never))

    const raw = new Map<number | string, unknown>([
      [1, 7],
      [2, 'txt'],
      [3, new Uint8Array([9])],
      [4, true],
      [5, [1, 2, 3]]
    ])
    const kv = KVMap.fromBytes(encodeCBOR(raw))
    assert.equal(kv.getInt(1), 7)
    assert.equal(kv.getText(2), 'txt')
    assert.equal(kv.getBytes(3)[0], 9)
    assert.equal(kv.getBool(4), true)
    assert.deepEqual(kv.getArray(5, assertInt), [1, 2, 3])
    assert.throws(() => kv.getArray(1, assertInt))
    assert.equal(kv.getParam(1), 7)
    assert.equal(kv.getCBORParam(99), undefined)

    const kv2 = new KVMap()
    kv2.setCBORParam(1, { a: 1 })
    assert.deepEqual(kv2.getCBORParam(1), new Map([['a', 1]]))
  })
})

describe('tag / hash coverage', () => {
  it('skipTag returns data shorter than the tag unchanged', () => {
    const short = new Uint8Array([0x01])
    assert.equal(skipTag(Sign1MessagePrefix, short), short)
  })

  it('getHash rejects an unknown algorithm', () => {
    assert.throws(() => getHash(99999))
  })
})

describe('header coverage', () => {
  it('verifyHeaders rejects crit in the unprotected bucket', () => {
    assert.throws(() =>
      verifyHeaders(
        new Header(),
        new Header().setParam(iana.HeaderParameterCrit, [1])
      )
    )
  })

  it('verifyHeaders rejects a non-int/non-text label', () => {
    assert.throws(() =>
      verifyHeaders(new Header(new Map([[true as never, 1]])), new Header())
    )
  })

  it('verifyHeaders validates common header parameter values', () => {
    verifyHeaders(
      new Header().setParam(iana.HeaderParameterContentType, 'text/plain'),
      new Header()
    )
    verifyHeaders(
      new Header().setParam(iana.HeaderParameterContentType, 0),
      new Header().setParam(iana.HeaderParameterKid, utf8ToBytes('kid'))
    )
    assert.throws(() =>
      verifyHeaders(
        new Header().setParam(iana.HeaderParameterContentType, -1),
        new Header()
      )
    )
    assert.throws(() =>
      verifyHeaders(
        new Header(),
        new Header().setParam(iana.HeaderParameterKid, 'kid' as never)
      )
    )
  })
})

describe('key coverage', () => {
  it('baseIV round-trips', () => {
    const key = new Key()
    key.kty = iana.KeyTypeSymmetric
    const iv = hexToBytes('0102030405')
    key.baseIV = iv
    assert.deepEqual(key.baseIV, iv)
  })

  it('getSecret throws for an unsupported key type', () => {
    const key = new Key()
    key.kty = 9999
    assert.throws(() => key.getSecret())
  })

  it('verifyOps enforces and permits key_ops', () => {
    const key = new Key()
    key.kty = iana.KeyTypeSymmetric
    key.ops = [iana.KeyOperationMacVerify]
    assert.throws(() => key.verifyOps(iana.KeyOperationMacCreate))
    key.verifyOps(iana.KeyOperationMacVerify)
  })
})

describe('keyset coverage', () => {
  it('rejects malformed input', () => {
    assert.throws(() => KeySet.fromBytes(encodeCBOR(123)))
    assert.throws(() => KeySet.fromBytes(encodeCBOR([])))
    assert.throws(() => new KeySet(1 as never))
  })

  it('getByKid skips keys without a kid', () => {
    const k = new Key()
    k.kty = iana.KeyTypeSymmetric
    const set = new KeySet([k])
    assert.equal(set.getByKid(utf8ToBytes('x')).length, 0)
  })
})
