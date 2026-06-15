// (c) 2023-present, LDC Labs. All rights reserved.
// See the file LICENSE for licensing terms.

import { randomBytes } from './utils'
import { Header, verifyHeaders } from './header'
import { RawMap, Value, assertIntOrText } from './map'
import { Key, type Encryptor } from './key'
import { AesGcmKey } from './aesgcm'
import { ChaCha20Poly1305Key } from './chacha20poly1305'
import { Recipient } from './recipient'
import * as iana from './iana'
import { decodeCBOR, encodeCBOR } from './utils'
import {
  skipTag,
  withTag,
  CwtPrefix,
  EncryptMessagePrefix,
  CBORSelfPrefix
} from './tag'

// EncryptMessage represents a COSE_Encrypt object.
//
// The payload is encrypted with a caller-provided content encryption key (CEK).
// Each Recipient then carries or derives that CEK for a recipient. This class
// currently supports direct recipients and AES-KW recipients.
//
// Reference https://datatracker.ietf.org/doc/html/rfc9052#name-enveloped-cose-structure.
export class EncryptMessage {
  payload: Uint8Array
  protected: Header | null = null
  unprotected: Header | null = null
  recipients: Recipient[]

  private static encBytes(
    protectedHeader: Uint8Array,
    externalData?: Uint8Array
  ): Uint8Array {
    return encodeCBOR([
      'Encrypt',
      protectedHeader,
      externalData ?? new Uint8Array()
    ])
  }

  static withTag(coseData: Uint8Array): Uint8Array {
    return withTag(EncryptMessagePrefix, coseData)
  }

  static async fromBytes(
    keks: Key[],
    coseData: Uint8Array,
    externalData?: Uint8Array
  ): Promise<EncryptMessage> {
    const data = skipTag(
      EncryptMessagePrefix,
      skipTag(CwtPrefix, skipTag(CBORSelfPrefix, coseData))
    )

    const [protectedBytes, unprotected, ciphertext, recipients] = decodeCBOR(
      data
    ) as [Uint8Array, RawMap, Uint8Array, Value[]]

    if (!Array.isArray(recipients) || recipients.length === 0) {
      throw new Error('cose-ts: EncryptMessage.fromBytes: no recipients')
    }

    const protectedHeader = Header.fromBytes(protectedBytes)
    const unprotectedHeader = new Header(unprotected)
    verifyHeaders(protectedHeader, unprotectedHeader)
    assertIVParams(protectedHeader, unprotectedHeader, 'fromBytes')

    const alg = protectedHeader.getType(
      iana.HeaderParameterAlg,
      assertIntOrText,
      'alg'
    )
    const iv = unprotectedHeader.getBytes(iana.HeaderParameterIV)
    const aad = EncryptMessage.encBytes(protectedBytes, externalData)
    const recps = recipients.map((r) => Recipient.fromCBORValue(r))

    // Recover the content encryption key from a recipient using one of the
    // provided KEKs, then decrypt. The AEAD tag rejects a wrong key.
    for (const kek of keks) {
      for (const r of recps) {
        let contentKey: Key & Encryptor
        try {
          contentKey = makeEncryptor(alg, r.recoverCEK(kek))
        } catch (_e) {
          continue
        }

        if (iv.length !== contentKey.nonceSize()) {
          throw new Error(
            `cose-ts: EncryptMessage.fromBytes: iv size mismatch, expected ${contentKey.nonceSize()}, got ${iv.length}`
          )
        }

        try {
          const plaintext = await contentKey.decrypt(ciphertext, iv, aad)
          return new EncryptMessage(
            plaintext,
            protectedHeader,
            unprotectedHeader,
            recps
          )
        } catch (_e) {
          // Wrong key or tampered ciphertext; try the next candidate.
        }
      }
    }

    throw new Error('cose-ts: EncryptMessage.fromBytes: decryption failed')
  }

  constructor(
    payload: Uint8Array,
    protectedHeader?: Header,
    unprotected?: Header,
    recipients: Recipient[] = []
  ) {
    this.payload = payload
    this.protected = protectedHeader
      ? new Header(protectedHeader.clone())
      : null
    this.unprotected = unprotected ? new Header(unprotected.clone()) : null
    this.recipients = recipients
  }

  // toBytes encrypts the payload with the content encryption key and serializes
  // the COSE_Encrypt, wrapping the content key for each recipient.
  async toBytes(
    contentKey: Key & Encryptor,
    externalData?: Uint8Array
  ): Promise<Uint8Array> {
    if (this.recipients.length === 0) {
      throw new Error('cose-ts: EncryptMessage.toBytes: no recipients')
    }

    if (this.protected == null) {
      this.protected = new Header()
      if (contentKey.has(iana.KeyParameterAlg)) {
        this.protected.setParam(iana.HeaderParameterAlg, contentKey.alg)
      }
    } else if (this.protected.has(iana.HeaderParameterAlg)) {
      const alg = this.protected.getType(
        iana.HeaderParameterAlg,
        assertIntOrText,
        'alg'
      )
      if (alg !== contentKey.alg) {
        throw new Error(
          `cose-ts: EncryptMessage.toBytes: alg mismatch, expected ${alg}, got ${contentKey.alg}`
        )
      }
    }

    if (this.unprotected == null) {
      this.unprotected = new Header()
    }

    verifyHeaders(this.protected, this.unprotected)
    assertRecipientMode(this.recipients, 'EncryptMessage.toBytes')
    assertIVParams(this.protected, this.unprotected, 'toBytes')

    const ivSize = contentKey.nonceSize()
    if (!this.unprotected.has(iana.HeaderParameterIV)) {
      this.unprotected.setParam(iana.HeaderParameterIV, randomBytes(ivSize))
    }
    const iv = this.unprotected.getBytes(iana.HeaderParameterIV)
    if (iv.length !== ivSize) {
      throw new Error(
        `cose-ts: EncryptMessage.toBytes: iv size mismatch, expected ${ivSize}, got ${iv.length}`
      )
    }

    const protectedBytes = this.protected.toBytes()
    const ciphertext = await contentKey.encrypt(
      this.payload,
      iv,
      EncryptMessage.encBytes(protectedBytes, externalData)
    )

    const cek = contentKey.getSecret()
    const recipients = this.recipients.map((r) => r.encode(cek))

    return encodeCBOR([
      protectedBytes,
      this.unprotected.toRaw(),
      ciphertext,
      recipients
    ])
  }
}

// makeEncryptor builds the content encryption key from the body algorithm and
// the recovered content encryption key bytes.
function makeEncryptor(alg: number | string, cek: Uint8Array): Key & Encryptor {
  switch (alg) {
    case iana.AlgorithmA128GCM:
    case iana.AlgorithmA192GCM:
    case iana.AlgorithmA256GCM:
      return AesGcmKey.fromSecret(cek)
    case iana.AlgorithmChaCha20Poly1305:
      return ChaCha20Poly1305Key.fromSecret(cek)
    default:
      throw new Error(`cose-ts: EncryptMessage: unsupported content alg ${alg}`)
  }
}

function assertRecipientMode(recipients: Recipient[], fn: string): void {
  const directCount = recipients.filter(
    (r) => r.alg() === iana.AlgorithmDirect
  ).length
  if (directCount > 0 && recipients.length !== 1) {
    throw new Error(
      `cose-ts: ${fn}: direct recipient mode must be the only recipient mode`
    )
  }
}

// assertIVParams enforces the IV rules from RFC 9052 §3.1: the full IV and the
// Partial IV header parameters MUST NOT both be present. Partial IV is not
// supported yet, so its presence is rejected outright.
function assertIVParams(
  protectedHeader: Header,
  unprotectedHeader: Header,
  fn: string
): void {
  const hasPartialIV =
    protectedHeader.has(iana.HeaderParameterPartialIV) ||
    unprotectedHeader.has(iana.HeaderParameterPartialIV)

  if (hasPartialIV) {
    throw new Error(
      `cose-ts: EncryptMessage.${fn}: Partial IV is not supported`
    )
  }
}
