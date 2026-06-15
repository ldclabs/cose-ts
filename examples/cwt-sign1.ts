import { Claims, Validator, withCWTTag } from '@ldclabs/cose-ts/cwt'
import { Ed25519Key } from '@ldclabs/cose-ts/ed25519'
import { Sign1Message } from '@ldclabs/cose-ts/sign1'
import { randomBytes, utf8ToBytes } from '@ldclabs/cose-ts/utils'

export function runCwtSign1Example() {
  const signingKey = Ed25519Key.generate('issuer-key-1')
  const externalData = utf8ToBytes('profile:cwt:v1')
  const now = Math.floor(Date.now() / 1000)

  const claims = new Claims()
  claims.iss = 'issuer'
  claims.aud = 'service'
  claims.sub = 'user-123'
  claims.iat = now
  claims.exp = now + 3600
  claims.cti = randomBytes(16)

  const token = withCWTTag(
    new Sign1Message(claims.toBytes()).toBytes(signingKey, externalData)
  )
  const signed = Sign1Message.fromBytes(
    signingKey.public(),
    token,
    externalData
  )
  const decodedClaims = Claims.fromBytes(signed.payload)

  new Validator({
    expectedIssuer: 'issuer',
    expectedAudience: 'service',
    fixedNow: new Date(now * 1000)
  }).validate(decodedClaims)

  return {
    token,
    claims: decodedClaims
  }
}
