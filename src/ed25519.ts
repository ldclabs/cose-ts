// (c) 2023-present, LDC Labs. All rights reserved.
// See the file LICENSE for licensing terms.

import { ed25519 } from '@noble/curves/ed25519'
import * as iana from './iana'
import { RawMap, assertBytes } from './map'
import { Key, type Signer, Verifier } from './key'
import { utf8ToBytes, randomBytes } from './utils'

// TODO: more checks
// Ed25519Key implements signature algorithm Ed25519 for COSE as defined in RFC9053.
// https://datatracker.ietf.org/doc/html/rfc9053#name-edwards-curve-digital-signa.
export class Ed25519Key extends Key implements Signer, Verifier {
  static generate(kid?: string): Ed25519Key {
    return Ed25519Key.fromSecret(randomBytes(32), kid)
  }

  static fromSecret(secret: Uint8Array, kid?: string): Ed25519Key {
    assertBytes(secret, 'secret')
    if (secret.length !== 32) {
      throw new Error(
        `cose-ts: Ed25519Key.fromSecret: secret size mismatch, expected 32, got ${secret.length}`
      )
    }

    const key = new Ed25519Key()
    key.setParam(iana.OKPKeyParameterD, secret)
    if (kid) {
      key.kid = utf8ToBytes(kid)
    }
    return key
  }

  static fromPublic(pubkey: Uint8Array, kid?: string): Ed25519Key {
    assertBytes(pubkey, 'public key')
    if (pubkey.length !== 32) {
      throw new Error(
        `cose-ts: Ed25519Key.fromPublic: public key size mismatch, expected 32, got ${pubkey.length}`
      )
    }

    const key = new Ed25519Key()

    key.setParam(iana.OKPKeyParameterX, pubkey)
    if (kid) {
      key.kid = utf8ToBytes(kid)
    }
    return key
  }

  constructor(kv?: RawMap) {
    super(kv)

    this.kty = iana.KeyTypeOKP
    this.alg = iana.AlgorithmEdDSA
    this.setParam(iana.OKPKeyParameterCrv, iana.EllipticCurveEd25519)
  }

  getSecretKey(): Uint8Array {
    return this.getBytes(iana.OKPKeyParameterD, 'd')
  }

  getPublicKey(): Uint8Array {
    if (this.has(iana.OKPKeyParameterX)) {
      return this.getBytes(iana.OKPKeyParameterX, 'x')
    }

    return ed25519.getPublicKey(this.getSecretKey())
  }

  public(): Ed25519Key {
    const key = new Ed25519Key(this.toRaw())
    if (key.has(iana.OKPKeyParameterD)) {
      key.setParam(iana.OKPKeyParameterX, key.getPublicKey())
      key.delete(iana.OKPKeyParameterD)
    }

    if (this.has(iana.KeyParameterKeyOps)) {
      this.ops = [iana.KeyOperationVerify]
    }

    return key
  }

  sign(message: Uint8Array): Uint8Array {
    return ed25519.sign(message, this.getSecretKey())
  }

  verify(message: Uint8Array, signature: Uint8Array): boolean {
    return ed25519.verify(signature, message, this.getPublicKey())
  }
}
