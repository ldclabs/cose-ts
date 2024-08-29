// (c) 2023-present, LDC Labs. All rights reserved.
// See the file LICENSE for licensing terms.

import { Header } from './header'
import { assertEqual, decodeCBOR, encodeCBOR } from './utils'

// PartyInfo represents a PartyInfo object.
export class PartyInfo {
  identity: Uint8Array | null
  nonce: Uint8Array | null
  other: Uint8Array | null

  static fromCBORValue(value: unknown): PartyInfo {
    const v = value as [
      Uint8Array | null,
      Uint8Array | null,
      Uint8Array | null
    ]
    assertEqual(Array.isArray(v), true, 'not an array')
    assertEqual(v.length, 3, 'invalid length')

    return new PartyInfo(v[0], v[1], v[2])
  }

  constructor(identity: Uint8Array | null = null, nonce: Uint8Array | null = null, other: Uint8Array | null = null) {
    this.identity = identity
    this.nonce = nonce
    this.other = other
  }

  toCBORValue(): unknown {
    return [this.identity, this.nonce, this.other]
  }
}

// SuppPubInfo represents a SuppPubInfo object.
export class SuppPubInfo {
  keyDataLength: number // bits
  protected: Header
  other: Uint8Array | null

  static fromCBORValue(value: unknown): SuppPubInfo {
    const v = value as [
      number,
      Uint8Array,
    ] | [
      number,
      Uint8Array,
      Uint8Array
    ]

    assertEqual(Array.isArray(v), true, 'not an array')

    if (v.length === 2) {
      return new SuppPubInfo(v[0], Header.fromBytes(v[1]))
    } else if (v.length === 3) {
      return new SuppPubInfo(v[0], Header.fromBytes(v[1]), v[2])
    } else {
      throw new Error('invalid SuppPubInfo data length')
    }
  }

  constructor(keyDataLength: number, protectedV: Header, other: Uint8Array | null = null) {
    this.keyDataLength = keyDataLength
    this.protected = protectedV
    this.other = other
  }

  toCBORValue(): unknown {
    const val = [this.keyDataLength, this.protected.toBytes()]
    if (this.other != null) {
      val.push(this.other)
    }
    return val
  }
}

export class KDFContext {
  algorithmID: number // bits
  partyUInfo: PartyInfo
  partyVInfo: PartyInfo
  suppPubInfo: SuppPubInfo
  suppPrivInfo: Uint8Array | null

  static fromBytes(data: Uint8Array): KDFContext {
    if (data.length === 0) {
      throw new Error('invalid KDFContext data length')
    }

    const v = decodeCBOR(data) as [
      number,
      unknown,
      unknown,
      unknown,
    ] | [
      number,
      unknown,
      unknown,
      unknown,
      Uint8Array
    ]

    assertEqual(Array.isArray(v), true, 'not an array')

    if (v.length === 4) {
      return new KDFContext(v[0], PartyInfo.fromCBORValue(v[1]), PartyInfo.fromCBORValue(v[2]), SuppPubInfo.fromCBORValue(v[3]))
    } else if (v.length === 5) {
      return new KDFContext(v[0], PartyInfo.fromCBORValue(v[1]), PartyInfo.fromCBORValue(v[2]), SuppPubInfo.fromCBORValue(v[3]), v[4])
    } else {
      throw new Error('invalid SuppPubInfo data length')
    }
  }

  constructor(algorithmID: number, partyUInfo: PartyInfo, partyVInfo: PartyInfo, suppPubInfo: SuppPubInfo, suppPrivInfo: Uint8Array | null = null) {
    this.algorithmID = algorithmID
    this.partyUInfo = partyUInfo
    this.partyVInfo = partyVInfo
    this.suppPubInfo = suppPubInfo
    this.suppPrivInfo = suppPrivInfo
  }

  toBytes(): Uint8Array {
    const val = [this.algorithmID, this.partyUInfo.toCBORValue(), this.partyVInfo.toCBORValue(), this.suppPubInfo.toCBORValue()]
    if (this.suppPrivInfo != null) {
      val.push(this.suppPrivInfo)
    }
    return encodeCBOR(val)
  }
}
