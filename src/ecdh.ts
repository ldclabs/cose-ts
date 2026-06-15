// (c) 2023-present, LDC Labs. All rights reserved.
// See the file LICENSE for licensing terms.

import { type MontgomeryECDH } from '@noble/curves/abstract/montgomery.js'
import { type ECDSA } from '@noble/curves/abstract/weierstrass.js'
import { x25519 } from '@noble/curves/ed25519.js'
import { p256, p384, p521 } from '@noble/curves/nist.js'
import * as iana from './iana'
import { Key, type ECDHer } from './key'
import { RawMap, assertBytes, assertInt } from './map'
import { decodeCBOR } from './utils'

// TODO: more checks
// ECDHKey implements key agreement algorithm ECDH for COSE as defined in RFC9053.
// https://datatracker.ietf.org/doc/html/rfc9053#name-direct-key-agreement.
export class ECDHKey extends Key implements ECDHer {
  static fromBytes(data: Uint8Array): ECDHKey {
    return new ECDHKey(decodeCBOR(data))
  }

  static generate<T>(crv: number, kid?: T): ECDHKey {
    const curve = getCurve(crv)
    return ECDHKey.fromSecret(crv, curve.utils.randomSecretKey(), kid)
  }

  static fromSecret<T>(crv: number, secret: Uint8Array, kid?: T): ECDHKey {
    assertBytes(secret, 'secret')
    const key = new ECDHKey()
    const curve = getCurve(crv)
    if (curve === x25519) {
      if (secret.length !== 32) {
        throw new Error(
          `cose-ts: ECDHKey.fromSecret: secret size mismatch, expected 32, got ${secret.length}`
        )
      }
    } else {
      if (!(curve as ECDSA).utils.isValidSecretKey(secret)) {
        throw new Error(
          `cose-ts: ECDSAKey.fromSecret: secret is not a valid private key for ECDH curve ${crv}`
        )
      }
    }

    key.crv = crv
    key.setParam(iana.EC2KeyParameterD, secret)
    if (kid != null) {
      key.setKid(kid)
    }
    return key
  }

  static fromPublic<T>(crv: number, pubkey: Uint8Array, kid?: T): ECDHKey {
    assertBytes(pubkey, 'public key')
    const key = new ECDHKey()
    const curve = getCurve(crv)
    if (curve === x25519) {
      if (pubkey.length !== 32) {
        throw new Error(
          `cose-ts: ECDHKey.fromPublic: key size mismatch, expected 32, got ${pubkey.length}`
        )
      }
      key.setParam(iana.EC2KeyParameterX, pubkey)
    } else {
      const crv = curve as ECDSA
      crv.Point.fromBytes(pubkey) // validate public key
      switch (pubkey[0]) {
        case 0x02:
          key.setParam(iana.EC2KeyParameterY, false)
          key.setParam(iana.EC2KeyParameterX, pubkey.subarray(1))
          break
        case 0x03:
          key.setParam(iana.EC2KeyParameterY, true)
          key.setParam(iana.EC2KeyParameterX, pubkey.subarray(1))
          break
        case 0x04:
          key.setParam(
            iana.EC2KeyParameterX,
            pubkey.subarray(1, crv.Point.Fp.BYTES + 1)
          )
          key.setParam(
            iana.EC2KeyParameterY,
            pubkey.subarray(crv.Point.Fp.BYTES + 1)
          )
          break
        default:
      }
    }

    key.crv = crv
    if (kid != null) {
      key.setKid(kid)
    }
    return key
  }

  constructor(kv?: RawMap) {
    super(kv)
  }

  get crv(): number {
    return this.getType(iana.EC2KeyParameterCrv, assertInt, 'crv')
  }

  set crv(crv: number) {
    const curve = getCurve(crv)
    this.setParam(iana.EC2KeyParameterCrv, crv)
    if (curve === x25519) {
      this.kty = iana.KeyTypeOKP
    } else {
      this.kty = iana.KeyTypeEC2
    }
  }

  ecdh(remotePublic: Key): Uint8Array {
    const remote =
      remotePublic instanceof ECDHKey
        ? remotePublic
        : new ECDHKey(remotePublic.toRaw())
    const priv = this.getSecretKey()
    const pub = remote.getPublicKey()
    const crv = this.crv
    if (crv !== remote.crv) {
      throw new Error(
        `cose-ts: ECDHKey.ecdh: curve mismatch, expected ${crv}, got ${remote.crv}`
      )
    }

    let curve = getCurve(crv)
    if (curve === x25519) {
      return x25519.getSharedSecret(priv, pub)
    }

    const secret = (curve as ECDSA).getSharedSecret(priv, pub, true)
    const size = getKeySize(crv)
    return secret.byteLength === size ? secret : secret.subarray(1)
  }

  getSecretKey(): Uint8Array {
    return this.getBytes(iana.EC2KeyParameterD, 'd')
  }

  getPublicKey(): Uint8Array {
    const curve = getCurve(this.crv)
    if (this.has(iana.EC2KeyParameterX)) {
      const x = this.getBytes(iana.EC2KeyParameterX, 'x')
      if (curve === x25519) {
        return x
      }

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

    if (curve === x25519) {
      return curve.getPublicKey(this.getSecretKey())
    } else {
      return (curve as ECDSA).getPublicKey(this.getSecretKey(), true)
    }
  }

  public(): ECDHKey {
    const key = new ECDHKey(this.clone())
    if (key.has(iana.EC2KeyParameterD)) {
      let curve = getCurve(this.crv)
      const pk = key.getPublicKey()
      if (curve === x25519) {
        key.setParam(iana.EC2KeyParameterX, pk)
      } else {
        curve = curve as ECDSA
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
              pk.subarray(1, curve.Point.Fp.BYTES + 1)
            )
            key.setParam(
              iana.EC2KeyParameterY,
              pk.subarray(curve.Point.Fp.BYTES + 1)
            )
            break
        }
      }

      key.delete(iana.EC2KeyParameterD)
    }

    if (key.has(iana.KeyParameterKeyOps)) {
      key.ops = []
    }

    return key
  }
}

export function getCurve(crv: number): ECDSA | MontgomeryECDH {
  switch (crv) {
    case iana.EllipticCurveP_256:
      return p256
    case iana.EllipticCurveP_384:
      return p384
    case iana.EllipticCurveP_521:
      return p521
    case iana.EllipticCurveX25519:
      return x25519
    default:
      throw new Error(`cose-ts: unsupported ECDH curve ${crv}`)
  }
}

export function getKeySize(crv: number): number {
  switch (crv) {
    case iana.EllipticCurveP_256:
      return 32
    case iana.EllipticCurveP_384:
      return 48
    case iana.EllipticCurveP_521:
      return 66
    case iana.EllipticCurveX25519:
      return 32
    default:
      throw new Error(`cose-ts: unsupported ECDH curve ${crv}`)
  }
}
