// cwtPrefix represents the fixed prefix of CWT CBOR tag.
// https://www.iana.org/assignments/cbor-tags/cbor-tags.xhtml#tags
export const CwtPrefix = new Uint8Array([
  0xd8,
  0x3d, // #6.61
])

// sign1MessagePrefix represents the fixed prefix of COSE_Sign1_Tagged.
export const Sign1MessagePrefix = new Uint8Array([
  0xd2, // #6.18
  0x84, // array of length 4
])

// signMessagePrefix represents the fixed prefix of COSE_Sign_Tagged.
export const SignMessagePrefix = new Uint8Array([
  0xd8,
  0x62, // #6.98
  0x84, // Array of length 4
])

// mac0MessagePrefix represents the fixed prefix of COSE_Mac0_Tagged.
export const Mac0MessagePrefix = new Uint8Array([
  0xd1, // #6.17
  0x84, // array of length 4
])

// macMessagePrefix represents the fixed prefix of COSE_Mac_Tagged.
export const MacMessagePrefix = new Uint8Array([
  0xd8,
  0x61, // #6.97
  0x85, // array of length 5
])

// encrypt0MessagePrefix represents the fixed prefix of COSE_Encrypt0_Tagged.
export const Encrypt0MessagePrefix = new Uint8Array([
  0xd0, // #6.16
  0x83, // array of length 3
])

// encryptMessagePrefix represents the fixed prefix of COSE_Encrypt_Tagged.
export const EncryptMessagePrefix = new Uint8Array([
  0xd8,
  0x60, // #6.96
  0x84, // array of length 4
])

export function skipTag(data: Uint8Array, tag: Uint8Array): Uint8Array {
  if (data.length < tag.length) {
    return data
  }

  for (let i = 0; i < tag.length; i++) {
    if (data[i] !== tag[i]) {
      return data
    }
  }

  return data.slice(tag.length - 1)
}
