// (c) 2023-present, LDC Labs. All rights reserved.
// See the file LICENSE for licensing terms.

import { p256 } from '@noble/curves/p256'
import { p384 } from '@noble/curves/p384'
import { p521 } from '@noble/curves/p521'
import { CurveFn } from '@noble/curves/abstract/weierstrass'
import * as iana from './iana'
import { RawMap, assertBytes } from './map'
import { Key, type Signer, Verifier } from './key'
import { utf8ToBytes } from './utils'

// TODO: more checks
// ECDSAKey implements signature algorithm ECDSA for COSE as defined in RFC9053.
// https://datatracker.ietf.org/doc/html/rfc9053#name-ecdsa.
export class ECDSAKey extends Key implements Signer, Verifier {
  static generate(alg: number, kid?: string): ECDSAKey {
    const curve = getCurve(alg)
    return ECDSAKey.fromSecret(curve.utils.randomPrivateKey(), kid)
  }

  static fromSecret(secret: Uint8Array, kid?: string): ECDSAKey {
    assertBytes(secret, 'secret')
    let alg = iana.AlgorithmES256
    if (secret.length === 48) {
      alg = iana.AlgorithmES384
    } else if (secret.length >= 65) {
      alg = iana.AlgorithmES512
    }

    const key = new ECDSAKey()
    key.alg = alg

    const curve = getCurve(alg)
    if (!curve.utils.isValidPrivateKey(secret)) {
      throw new Error(
        `cose-ts: ECDSAKey.fromSecret: secret is not a valid private key for ECDSA alg ${alg}`
      )
    }
    key.setParam(iana.EC2KeyParameterD, secret)

    if (kid) {
      key.kid = utf8ToBytes(kid)
    }
    return key
  }

  static fromPublic(pubkey: Uint8Array, kid?: string): ECDSAKey {
    assertBytes(pubkey, 'public key')
    if (pubkey.length !== 32) {
      throw new Error(
        `cose-ts: ECDSAKey.fromPublic: public key size mismatch, expected 32, got ${pubkey.length}`
      )
    }

    const key = new ECDSAKey()

    key.setParam(iana.EC2KeyParameterX, pubkey)
    if (kid) {
      key.kid = utf8ToBytes(kid)
    }
    return key
  }

  constructor(kv?: RawMap) {
    super(kv)

    this.kty = iana.KeyTypeEC2
  }

  get alg(): number {
    return super.alg as number
  }

  set alg(alg: number) {
    super.alg = alg
    this.setParam(iana.OKPKeyParameterCrv, getCrv(alg))
  }

  getSecretKey(): Uint8Array {
    return this.getBytes(iana.EC2KeyParameterD, 'd')
  }

  getPublicKey(): Uint8Array {
    const curve = getCurve(this.alg)
    if (this.has(iana.EC2KeyParameterX)) {
      const x = this.getBytes(iana.EC2KeyParameterX, 'x')
      try {
        const y = this.getBool(iana.EC2KeyParameterY, 'y')
        const pk = new Uint8Array(1 + x.length)
        pk[0] = y ? 0x03 : 0x02
        pk.set(x, 1)
        return pk
      } catch (_e) {
        const y = this.getBytes(iana.EC2KeyParameterY, 'y')
        const pk = new Uint8Array(1 + x.length + y.length)
        pk[0] = 0x04
        pk.set(x, 1)
        pk.set(y, x.length + 1)
        return pk
      }
    }

    return curve.getPublicKey(this.getSecretKey(), true)
  }

  public(): ECDSAKey {
    const key = new ECDSAKey(this.toRaw())
    if (key.has(iana.EC2KeyParameterD)) {
      const curve = getCurve(this.alg)
      const pk = key.getPublicKey()
      switch (pk[0]) {
        case 0x02:
          key.setParam(iana.EC2KeyParameterY, false)
          key.setParam(iana.EC2KeyParameterX, pk.subarray(1))
          break
        case 0x03:
          key.setParam(iana.EC2KeyParameterY, true)
          key.setParam(iana.EC2KeyParameterX, pk.subarray(1))
          break
        case 0x04:
          key.setParam(
            iana.EC2KeyParameterX,
            pk.subarray(1, curve.CURVE.Fp.BYTES + 1)
          )
          key.setParam(
            iana.EC2KeyParameterY,
            pk.subarray(curve.CURVE.Fp.BYTES + 1)
          )
          break
      }

      key.delete(iana.EC2KeyParameterD)
    }

    if (this.has(iana.KeyParameterKeyOps)) {
      this.ops = [iana.KeyOperationVerify]
    }

    return key
  }

  sign(message: Uint8Array): Uint8Array {
    const curve = getCurve(this.alg)
    const sig = curve.sign(message, this.getSecretKey(), {
      lowS: curve.CURVE.lowS,
      prehash: true,
    })
    return sig.toCompactRawBytes()
  }

  verify(message: Uint8Array, signature: Uint8Array): boolean {
    const curve = getCurve(this.alg)
    return curve.verify(signature, message, this.getPublicKey(), {
      lowS: curve.CURVE.lowS,
      prehash: true,
    })
  }
}

export function getCrv(alg: number): number {
  switch (alg) {
    case iana.AlgorithmES256:
      return iana.EllipticCurveP_256
    case iana.AlgorithmES384:
      return iana.EllipticCurveP_384
    case iana.AlgorithmES512:
      return iana.EllipticCurveP_521
    default:
      throw new Error(`cose-ts: unsupported ECDSA alg ${alg}`)
  }
}

export function getCurve(alg: number): CurveFn {
  switch (alg) {
    case iana.AlgorithmES256:
      return p256
    case iana.AlgorithmES384:
      return p384
    case iana.AlgorithmES512:
      return p521
    default:
      throw new Error(`cose-ts: unsupported ECDSA alg ${alg}`)
  }
}
