// (c) 2023-present, LDC Labs. All rights reserved.
// See the file LICENSE for licensing terms.

import { ed25519 } from '@noble/curves/ed25519.js'
import * as iana from './iana'
import { Key, type Signer, Verifier } from './key'
import { RawMap, assertBytes } from './map'
import { decodeCBOR, randomBytes } from './utils'

// TODO: more checks
/**
 * Ed25519Key implements the Ed25519 signature algorithm (EdDSA) for COSE, as
 * defined in RFC 9053. Use it with {@link Sign1Message} or {@link SignMessage}.
 *
 * Construction signature: `generate(kid?)` — the algorithm is fixed, so the
 * first argument is the optional key id, not the algorithm.
 *
 * @example
 * ```ts
 * const key = Ed25519Key.generate('signing-key-1')
 * const cose = new Sign1Message(payload).toBytes(key)
 * Sign1Message.fromBytes(key.public(), cose)
 * ```
 *
 * @see https://datatracker.ietf.org/doc/html/rfc9053#name-edwards-curve-digital-signa
 */
export class Ed25519Key extends Key implements Signer, Verifier {
  /** Decodes a COSE_Key from CBOR bytes into an Ed25519Key. */
  static fromBytes(data: Uint8Array): Ed25519Key {
    return new Ed25519Key(decodeCBOR(data))
  }

  /**
   * Generates a new Ed25519 private key from a random 32-byte seed.
   *
   * @param kid - Optional key id; stored CBOR-encoded in the COSE_Key and
   *   copied into the unprotected header by message helpers.
   */
  static generate<T>(kid?: T): Ed25519Key {
    return Ed25519Key.fromSecret(randomBytes(32), kid)
  }

  /**
   * Imports an Ed25519 private key from a raw 32-byte seed.
   *
   * @param secret - The 32-byte Ed25519 seed (private key).
   * @param kid - Optional key id.
   */
  static fromSecret<T>(secret: Uint8Array, kid?: T): Ed25519Key {
    assertBytes(secret, 'secret')
    if (secret.length !== 32) {
      throw new Error(
        `cose-ts: Ed25519Key.fromSecret: secret size mismatch, expected 32, got ${secret.length}`
      )
    }

    const key = new Ed25519Key()
    key.setParam(iana.OKPKeyParameterD, secret)
    if (kid != null) {
      key.setKid(kid)
    }
    return key
  }

  /**
   * Imports an Ed25519 public (verify-only) key from a raw 32-byte point.
   *
   * @param pubkey - The 32-byte Ed25519 public key.
   * @param kid - Optional key id.
   */
  static fromPublic<T>(pubkey: Uint8Array, kid?: T): Ed25519Key {
    assertBytes(pubkey, 'public key')
    if (pubkey.length !== 32) {
      throw new Error(
        `cose-ts: Ed25519Key.fromPublic: public key size mismatch, expected 32, got ${pubkey.length}`
      )
    }

    const key = new Ed25519Key()

    key.setParam(iana.OKPKeyParameterX, pubkey)
    if (kid != null) {
      key.setKid(kid)
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

  /**
   * Returns a verify-only copy of this key: the private seed is removed and
   * `key_ops` (if present) is narrowed to verify.
   */
  public(): Ed25519Key {
    const key = new Ed25519Key(this.clone())
    if (key.has(iana.OKPKeyParameterD)) {
      key.setParam(iana.OKPKeyParameterX, key.getPublicKey())
      key.delete(iana.OKPKeyParameterD)
    }

    if (key.has(iana.KeyParameterKeyOps)) {
      key.ops = [iana.KeyOperationVerify]
    }

    return key
  }

  sign(message: Uint8Array): Uint8Array {
    this.verifyOps(iana.KeyOperationSign)
    return ed25519.sign(message, this.getSecretKey())
  }

  verify(message: Uint8Array, signature: Uint8Array): boolean {
    this.verifyOps(iana.KeyOperationVerify)
    return ed25519.verify(signature, message, this.getPublicKey())
  }
}
