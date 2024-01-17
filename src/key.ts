// (c) 2023-present, LDC Labs. All rights reserved.
// See the file LICENSE for licensing terms.

import { KVMap, RawMap, assertIntOrText, assertBytes } from './map'
import * as iana from './iana'
import { decodeCBOR } from './utils'

export interface Encryptor {
  nonceSize(): number
  encrypt(
    plaintext: Uint8Array,
    nonce: Uint8Array,
    aad?: Uint8Array
  ): Promise<Uint8Array>
  decrypt(
    ciphertext: Uint8Array,
    nonce: Uint8Array,
    aad?: Uint8Array
  ): Promise<Uint8Array>
}

export interface MACer {
  mac(message: Uint8Array): Uint8Array
}

export interface Signer {
  sign(message: Uint8Array): Uint8Array
}

export interface Verifier {
  verify(message: Uint8Array, signature: Uint8Array): boolean
}

// Key implements algorithms and key objects for COSE as defined in RFC9052 and RFC9053.
// https://datatracker.ietf.org/doc/html/rfc9052#name-key-objects.
// https://datatracker.ietf.org/doc/html/rfc9053.
export class Key extends KVMap {
  static fromBytes(data: Uint8Array): Key {
    return new Key(decodeCBOR(data))
  }

  constructor(kv: RawMap = new Map()) {
    super(kv)
  }

  get kty(): number | string {
    return this.getType(iana.KeyParameterKty, assertIntOrText, 'kty')
  }

  set kty(kty: number) {
    this.setParam(iana.KeyParameterKty, assertIntOrText(kty, 'kty'))
  }

  get kid(): Uint8Array {
    return this.getBytes(iana.KeyParameterKid, 'kid')
  }

  set kid(kid: Uint8Array) {
    this.setParam(iana.KeyParameterKid, assertBytes(kid, 'kid'))
  }

  get alg(): number | string {
    return this.getType(iana.KeyParameterAlg, assertIntOrText, 'alg')
  }

  set alg(alg: number | string) {
    this.setParam(iana.KeyParameterAlg, assertIntOrText(alg, 'alg'))
  }

  get ops(): (number | string)[] {
    return this.getArray(iana.KeyParameterKeyOps, assertIntOrText, 'ops')
  }

  set ops(ops: (number | string)[]) {
    if (!Array.isArray(ops)) {
      throw new TypeError('ops must be an array')
    }
    ops.forEach((op) => assertIntOrText(op, 'ops'))
    this.setParam(iana.KeyParameterKeyOps, ops)
  }

  get baseIV(): Uint8Array {
    return this.getBytes(iana.KeyParameterBaseIV, 'Base IV')
  }

  set baseIV(iv: Uint8Array) {
    this.setParam(iana.KeyParameterBaseIV, assertBytes(iv, 'Base IV'))
  }
}
