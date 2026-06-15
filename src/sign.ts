// (c) 2023-present, LDC Labs. All rights reserved.
// See the file LICENSE for licensing terms.

import { Header, verifyHeaders } from './header'
import { RawMap, Value, assertIntOrText } from './map'
import { Key, type Verifier, Signer } from './key'
import * as iana from './iana'
import { decodeCBOR, encodeCBOR } from './utils'
import {
  skipTag,
  withTag,
  CwtPrefix,
  SignMessagePrefix,
  CBORSelfPrefix
} from './tag'

// Signature represents a COSE_Signature structure inside COSE_Sign.
//
// COSE_Sign separates body headers from per-signer headers. The per-signer
// protected header is included in the Sig_structure for this signature.
//
// Reference https://datatracker.ietf.org/doc/html/rfc9052#name-signing-with-one-or-more-si.
export class Signature {
  protected: Header | null
  unprotected: Header | null
  signature: Uint8Array

  constructor(protectedHeader?: Header, unprotected?: Header) {
    this.protected = protectedHeader
      ? new Header(protectedHeader.clone())
      : null
    this.unprotected = unprotected ? new Header(unprotected.clone()) : null
    this.signature = new Uint8Array()
  }
}

/**
 * SignMessage represents a COSE_Sign object, carrying one or more signatures.
 *
 * Use {@link Sign1Message} for the common single-signer case. Use this class
 * when a payload needs multiple signatures, potentially with different
 * algorithms or key identifiers.
 *
 * @example
 * ```ts
 * const a = Ed25519Key.generate()
 * const b = ECDSAKey.generate(iana.AlgorithmES256)
 * // With no Signature structures, toBytes() creates one per key.
 * const cose = new SignMessage(payload).toBytes([a, b])
 * SignMessage.fromBytes([a.public(), b.public()], cose)
 * ```
 *
 * @see https://datatracker.ietf.org/doc/html/rfc9052#name-signing-with-one-or-more-si
 */
export class SignMessage {
  payload: Uint8Array
  protected: Header | null = null
  unprotected: Header | null = null
  signatures: Signature[]

  private static signBytes(
    payload: Uint8Array,
    bodyProtected: Uint8Array,
    signProtected: Uint8Array,
    externalData?: Uint8Array
  ): Uint8Array {
    return encodeCBOR([
      'Signature',
      bodyProtected,
      signProtected,
      externalData ?? new Uint8Array(),
      payload
    ])
  }

  static withTag(coseData: Uint8Array): Uint8Array {
    return withTag(SignMessagePrefix, coseData)
  }

  static fromBytes(
    keys: (Key & Verifier)[],
    coseData: Uint8Array,
    externalData?: Uint8Array
  ): SignMessage {
    const data = skipTag(
      SignMessagePrefix,
      skipTag(CwtPrefix, skipTag(CBORSelfPrefix, coseData))
    )

    const [protectedBytes, unprotected, payload, signatures] = decodeCBOR(
      data
    ) as [Uint8Array, RawMap, Uint8Array, Value[][]]

    if (!Array.isArray(signatures) || signatures.length === 0) {
      throw new Error('cose-ts: SignMessage.fromBytes: no signatures')
    }

    const protectedHeader = Header.fromBytes(protectedBytes)
    const unprotectedHeader = new Header(unprotected)
    verifyHeaders(protectedHeader, unprotectedHeader)

    const decoded = signatures.map((s) => {
      const [signProtectedBytes, signUnprotected, signature] = s as [
        Uint8Array,
        RawMap,
        Uint8Array
      ]
      const signProtectedHeader = Header.fromBytes(signProtectedBytes)
      const signUnprotectedHeader = new Header(signUnprotected)
      verifyHeaders(signProtectedHeader, signUnprotectedHeader)

      const sig = new Signature(signProtectedHeader, signUnprotectedHeader)
      sig.signature = signature
      return { signProtectedBytes, signProtectedHeader, sig, signature }
    })

    // Each provided key MUST verify at least one signature. This treats a
    // successful validation of one signature per signer as success, as
    // described in RFC 9052 §4.1.
    for (const key of keys) {
      let verified = false
      for (const d of decoded) {
        if (d.signProtectedHeader.has(iana.HeaderParameterAlg)) {
          const alg = d.signProtectedHeader.getType(
            iana.HeaderParameterAlg,
            assertIntOrText,
            'alg'
          )
          if (alg !== key.alg) {
            continue
          }
        }

        try {
          if (
            key.verify(
              SignMessage.signBytes(
                payload,
                protectedBytes,
                d.signProtectedBytes,
                externalData
              ),
              d.signature
            )
          ) {
            verified = true
            break
          }
        } catch (_e) {
          // Mismatched key/curve; try the next signature.
        }
      }

      if (!verified) {
        throw new Error(
          'cose-ts: SignMessage.fromBytes: no signature verified for a provided key'
        )
      }
    }

    return new SignMessage(
      payload,
      protectedHeader,
      unprotectedHeader,
      decoded.map((d) => d.sig)
    )
  }

  /**
   * @param payload - The payload bytes to sign.
   * @param protectedHeader - Optional body protected header.
   * @param unprotected - Optional body unprotected header.
   * @param signatures - Optional per-signer {@link Signature} structures. When
   *   empty, `toBytes` creates one per signing key.
   */
  constructor(
    payload: Uint8Array,
    protectedHeader?: Header,
    unprotected?: Header,
    signatures: Signature[] = []
  ) {
    this.payload = payload
    this.protected = protectedHeader
      ? new Header(protectedHeader.clone())
      : null
    this.unprotected = unprotected ? new Header(unprotected.clone()) : null
    this.signatures = signatures
  }

  // toBytes signs the payload with each key and serializes the COSE_Sign.
  //
  // When the message has no Signature structures, one is created per key, with
  // the algorithm and key id taken from the key. Otherwise the number of
  // Signature structures MUST match the number of keys, and the i-th key signs
  // the i-th Signature.
  toBytes(keys: (Key & Signer)[], externalData?: Uint8Array): Uint8Array {
    if (keys.length === 0) {
      throw new Error('cose-ts: SignMessage.toBytes: no signing key provided')
    }

    if (this.protected == null) {
      this.protected = new Header()
    }
    if (this.unprotected == null) {
      this.unprotected = new Header()
    }
    verifyHeaders(this.protected, this.unprotected)
    const bodyProtected = this.protected.toBytes()

    if (this.signatures.length === 0) {
      this.signatures = keys.map(() => new Signature())
    }
    if (this.signatures.length !== keys.length) {
      throw new Error(
        `cose-ts: SignMessage.toBytes: signatures/keys length mismatch, expected ${this.signatures.length}, got ${keys.length}`
      )
    }

    const signatures: Value[] = []
    for (let i = 0; i < keys.length; i++) {
      const key = keys[i]
      const sig = this.signatures[i]

      if (sig.protected == null) {
        sig.protected = new Header()
        if (key.has(iana.KeyParameterAlg)) {
          sig.protected.setParam(iana.HeaderParameterAlg, key.alg)
        }
      } else if (sig.protected.has(iana.HeaderParameterAlg)) {
        const alg = sig.protected.getType(
          iana.HeaderParameterAlg,
          assertIntOrText,
          'alg'
        )
        if (alg !== key.alg) {
          throw new Error(
            `cose-ts: SignMessage.toBytes: alg mismatch, expected ${alg}, got ${key.alg}`
          )
        }
      }

      if (sig.unprotected == null) {
        sig.unprotected = new Header()
        if (key.has(iana.KeyParameterKid)) {
          sig.unprotected.setParam(iana.HeaderParameterKid, key.kid)
        }
      }

      verifyHeaders(sig.protected, sig.unprotected)

      const signProtected = sig.protected.toBytes()
      sig.signature = key.sign(
        SignMessage.signBytes(
          this.payload,
          bodyProtected,
          signProtected,
          externalData
        )
      )
      signatures.push([signProtected, sig.unprotected.toRaw(), sig.signature])
    }

    return encodeCBOR([
      bodyProtected,
      this.unprotected.toRaw(),
      this.payload,
      signatures
    ])
  }
}
