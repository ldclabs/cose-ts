// (c) 2023-present, LDC Labs. All rights reserved.
// See the file LICENSE for licensing terms.

import { assert, describe, it } from 'vitest'
import { utf8ToBytes, bytesToHex, randomBytes, compareBytes } from './utils'
import * as iana from './iana'
import { Validator, Claims, withCWTTag } from './cwt'
import { Ed25519Key } from './ed25519'
import { Sign1Message } from './sign1'

describe('CWT', () => {
  it('with Sign1Message and Ed25519 Key', () => {
    const key = Ed25519Key.generate()
    const pubKey = key.public()

    const claims = new Claims()
    claims.iss = 'ldclabs'
    claims.aud = 'cose-ts'
    claims.sub = 'tester'
    claims.exp = Math.floor(Date.now() / 1000) + 3600
    claims.cti = randomBytes(16)

    const cwtMsg = new Sign1Message(claims.toBytes())

    const cwtData = cwtMsg.toBytes(key, utf8ToBytes('@ldclabs/cose-ts'))
    const cwtDataWithTag = withCWTTag(cwtData)

    // verifing
    const validator = new Validator({ expectedIssuer: 'ldclabs' })
    assert.throw(
      () => Sign1Message.fromBytes(pubKey, cwtDataWithTag),
      'signature mismatch'
    )
    const cwtMsg2 = Sign1Message.fromBytes(
      pubKey,
      cwtDataWithTag, // or cwtData
      utf8ToBytes('@ldclabs/cose-ts')
    )
    const claims2 = Claims.fromBytes(cwtMsg2.payload)
    validator.validate(claims2)
    assert.equal(claims2.iss, claims.iss)
    assert.equal(claims2.aud, claims.aud)
    assert.equal(claims2.sub, claims.sub)
    assert.equal(claims2.exp, claims.exp)
    assert.equal(compareBytes(claims2.cti, claims.cti), 0)
  })
})

describe('Claims & Validator', () => {
  it('new Validator', () => {
    assert.throw(
      () => new Validator({ clockSkew: 11 * 60 }),
      'clock skew cannot be greater than'
    )

    const validator = new Validator()
    assert.throw(
      () => validator.validate(null as unknown as Claims),
      'claims must be a Claims'
    )
    assert.throw(
      () => validator.validate({} as unknown as Claims),
      'claims must be a Claims'
    )
  })

  it('Expiration', () => {
    let validator = new Validator()
    assert.throw(
      () => validator.validate(new Claims()),
      'token must have an expiration set'
    )

    validator = new Validator({ allowMissingExpiration: true })
    const claims = new Claims()
    validator.validate(claims)
    claims.exp = 123
    assert.throw(() => validator.validate(claims), 'token has expired')

    validator = new Validator({ fixedNow: new Date(100 * 1000) })
    validator.validate(claims)
  })

  it('NotBefore', () => {
    const validator = new Validator({
      allowMissingExpiration: true,
      fixedNow: new Date(100 * 1000),
    })
    const claims = new Claims()
    validator.validate(claims)
    claims.nbf = 123
    assert.throw(() => validator.validate(claims), 'token cannot be used yet')
  })

  it('IssuedAt', () => {
    const validator = new Validator({
      allowMissingExpiration: true,
      expectIssuedInThePast: true,
    })
    const claims = new Claims()
    validator.validate(claims)
    claims.iat = Math.floor(Date.now() / 1000) + 100
    assert.throw(
      () => validator.validate(claims),
      'token has an invalid iat claim in the future'
    )
  })

  it('ExpectedIssuer', () => {
    const validator = new Validator({
      expectedIssuer: 'ldclabs',
    })

    const claims = new Claims()
    claims.exp = Math.floor(Date.now() / 1000) + 100

    assert.throw(
      () => validator.validate(claims),
      'token has an invalid iss claim'
    )

    claims.iss = 'ldclabs'
    validator.validate(claims)
  })

  it('ExpectedAudience', () => {
    const validator = new Validator({
      expectedAudience: 'ldclabs',
    })

    const claims = new Claims()
    claims.exp = Math.floor(Date.now() / 1000) + 100

    assert.throw(
      () => validator.validate(claims),
      'token has an invalid aud claim'
    )

    claims.aud = 'ldclabs'
    validator.validate(claims)
  })
})
