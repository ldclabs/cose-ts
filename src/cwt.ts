// (c) 2023-present, LDC Labs. All rights reserved.
// See the file LICENSE for licensing terms.

import {
  KVMap,
  RawMap,
  assertText,
  assertInt,
  assertBytes,
  assertMap,
} from './map'
import * as iana from './iana'
import { decodeCBOR } from './utils'
import { withTag, CwtPrefix } from './tag'

const cwtMaxClockSkewMinutes = 10

// Claims represents a set of common claims for CWT.
//
// Reference https://www.iana.org/assignments/cwt/cwt.xhtml
export class Claims extends KVMap {
  static fromBytes(data: Uint8Array): Claims {
    return new Claims(decodeCBOR(data))
  }

  constructor(kv: RawMap = new Map()) {
    super(kv)
  }

  get iss(): string {
    return this.getText(iana.CWTClaimIss, 'iss')
  }

  set iss(iss: string) {
    this.setParam(iana.CWTClaimIss, assertText(iss, 'iss'))
  }

  get sub(): string {
    return this.getText(iana.CWTClaimSub, 'sub')
  }

  set sub(sub: string) {
    this.setParam(iana.CWTClaimSub, assertText(sub, 'sub'))
  }

  get aud(): string {
    return this.getText(iana.CWTClaimAud, 'aud')
  }

  set aud(aud: string) {
    this.setParam(iana.CWTClaimAud, assertText(aud, 'aud'))
  }

  get exp(): number {
    return this.getInt(iana.CWTClaimExp, 'exp')
  }

  set exp(exp: number) {
    this.setParam(iana.CWTClaimExp, assertInt(exp, 'exp'))
  }

  get nbf(): number {
    return this.getInt(iana.CWTClaimNbf, 'nbf')
  }

  set nbf(nbf: number) {
    this.setParam(iana.CWTClaimNbf, assertInt(nbf, 'nbf'))
  }

  get iat(): number {
    return this.getInt(iana.CWTClaimIat, 'iat')
  }

  set iat(iat: number) {
    this.setParam(iana.CWTClaimIat, assertInt(iat, 'iat'))
  }

  get cti(): Uint8Array {
    return this.getBytes(iana.CWTClaimCti, 'cti')
  }

  set cti(cti: Uint8Array) {
    this.setParam(iana.CWTClaimCti, assertBytes(cti, 'cti'))
  }

  get cnf(): RawMap {
    return this.getType(iana.CWTClaimCnf, assertMap, 'cnf')
  }

  set cnf(cnf: RawMap) {
    this.setParam(iana.CWTClaimCnf, assertMap(cnf, 'cnf'))
  }

  get scope(): string {
    return this.getText(iana.CWTClaimScope, 'scope')
  }

  set scope(scope: string) {
    this.setParam(iana.CWTClaimScope, assertText(scope, 'scope'))
  }

  get nonce(): Uint8Array {
    return this.getBytes(iana.CWTClaimNonce, 'nonce')
  }

  set nonce(nonce: Uint8Array) {
    this.setParam(iana.CWTClaimNonce, assertBytes(nonce, 'nonce'))
  }
}

export function withCWTTag(coseData: Uint8Array): Uint8Array {
  return withTag(CwtPrefix, coseData)
}

// ValidatorOpts defines validation options for CWT validators.
export interface ValidatorOpts {
  expectedIssuer: string
  expectedAudience: string
  allowMissingExpiration: boolean
  expectIssuedInThePast: boolean
  clockSkew: number // seconds
  fixedNow: Date | null
}

export class Validator {
  private opts: ValidatorOpts
  constructor(opts?: Partial<ValidatorOpts>) {
    this.opts = {
      expectedIssuer: '',
      expectedAudience: '',
      allowMissingExpiration: false,
      expectIssuedInThePast: false,
      clockSkew: 0,
      fixedNow: null,
      ...opts,
    }

    if (this.opts.clockSkew > cwtMaxClockSkewMinutes * 60) {
      throw new Error(
        `cose-ts: clock skew cannot be greater than ${cwtMaxClockSkewMinutes} minutes`
      )
    }
  }

  // Validate validates a *Claims according to the options provided.
  validate(claims: Claims) {
    if (!(claims instanceof Claims)) {
      throw new TypeError('cose-ts: claims must be a Claims')
    }

    const now_secs =
      this.opts.fixedNow == null
        ? Date.now() / 1000
        : this.opts.fixedNow.getTime() / 1000

    if (!claims.has(iana.CWTClaimExp)) {
      if (!this.opts.allowMissingExpiration) {
        throw new Error('cose-ts: token must have an expiration set')
      }
    } else {
      const exp = claims.exp
      if (exp <= 0) {
        throw new Error('cose-ts: token must have a positive expiration')
      }

      if (exp + this.opts.clockSkew < now_secs) {
        throw new Error('cose-ts: token has expired')
      }
    }

    if (claims.has(iana.CWTClaimNbf)) {
      const nbf = claims.nbf
      if (nbf <= 0 || nbf > now_secs + this.opts.clockSkew) {
        throw new Error('cose-ts: token cannot be used yet')
      }
    }

    if (claims.has(iana.CWTClaimIat)) {
      const iat = claims.iat
      if (
        iat > now_secs + this.opts.clockSkew &&
        this.opts.expectIssuedInThePast
      ) {
        throw new Error('cose-ts: token has an invalid iat claim in the future')
      }
    }

    if (this.opts.expectedIssuer !== '') {
      const iss = claims.has(iana.CWTClaimIss) ? claims.iss : ''
      if (iss !== this.opts.expectedIssuer) {
        throw new Error(
          `cose-ts: token has an invalid iss claim, expected ${this.opts.expectedIssuer}, got ${iss}`
        )
      }
    }

    if (this.opts.expectedAudience !== '') {
      const aud = claims.has(iana.CWTClaimAud) ? claims.aud : ''
      if (aud !== this.opts.expectedAudience) {
        throw new Error(
          `cose-ts: token has an invalid aud claim, expected ${this.opts.expectedAudience}, got ${aud}`
        )
      }
    }
  }
}
