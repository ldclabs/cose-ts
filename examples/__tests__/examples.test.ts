import { describe, expect, it } from 'vitest'
import { runCwtSign1Example } from '../cwt-sign1'
import { runEncrypt0AesGcmExample } from '../encrypt0-aesgcm'
import { runEncryptAesKwExample } from '../encrypt-aeskw'
import { runMac0HmacExample } from '../mac0-hmac'
import { runSign1Ed25519Example } from '../sign1-ed25519'

describe('README-style examples', () => {
  it('runs Sign1 with Ed25519', () => {
    const result = runSign1Ed25519Example()
    expect(result.payload).toBe('hello cose')
    expect(result.cose.length).toBeGreaterThan(0)
  })

  it('runs Encrypt0 with AES-GCM', async () => {
    const result = await runEncrypt0AesGcmExample()
    expect(result.payload).toBe('shared-key secret')
    expect(result.cose.length).toBeGreaterThan(0)
  })

  it('runs Encrypt with AES-KW recipients', async () => {
    const result = await runEncryptAesKwExample()
    expect(result.payload).toBe('wrapped-key secret')
    expect(result.cose.length).toBeGreaterThan(0)
  })

  it('runs Mac0 with HMAC', () => {
    const result = runMac0HmacExample()
    expect(result.payload).toBe('authenticated content')
    expect(result.cose.length).toBeGreaterThan(0)
  })

  it('runs CWT over Sign1', () => {
    const result = runCwtSign1Example()
    expect(result.claims.iss).toBe('issuer')
    expect(result.claims.aud).toBe('service')
    expect(result.claims.sub).toBe('user-123')
    expect(result.token.length).toBeGreaterThan(0)
  })
})
