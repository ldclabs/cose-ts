import { AesGcmKey } from '@ldclabs/cose-ts/aesgcm'
import { Ed25519Key } from '@ldclabs/cose-ts/ed25519'
import { Encrypt0Message } from '@ldclabs/cose-ts/encrypt0'
import * as iana from '@ldclabs/cose-ts/iana'
import { Sign1Message } from '@ldclabs/cose-ts/sign1'
import { utf8ToBytes } from '@ldclabs/cose-ts/utils'
import { describe, expect, it } from 'vitest'

describe('common agent pitfalls', () => {
  it('rejects package root imports with a repair hint', async () => {
    await expect(import('@ldclabs/cose-ts')).rejects.toThrow(/subpath/)
  })

  it('requires matching externalData for signatures', () => {
    const key = Ed25519Key.generate()
    const signed = new Sign1Message(utf8ToBytes('hello')).toBytes(
      key,
      utf8ToBytes('profile:v1')
    )

    expect(() =>
      Sign1Message.fromBytes(key.public(), signed, utf8ToBytes('profile:v2'))
    ).toThrow(/signature mismatch/)
  })

  it('requires matching externalData for AEAD encryption', async () => {
    const key = AesGcmKey.generate(iana.AlgorithmA128GCM)
    const encrypted = await new Encrypt0Message(utf8ToBytes('secret')).toBytes(
      key,
      utf8ToBytes('profile:v1')
    )

    await expect(
      Encrypt0Message.fromBytes(key, encrypted, utf8ToBytes('profile:v2'))
    ).rejects.toThrow()
  })
})
