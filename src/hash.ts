import { sha256, sha384, sha512 } from '@noble/hashes/sha2'
import { CHash } from '@noble/hashes/utils'
import * as iana from './iana'

export { hmac } from '@noble/hashes/hmac'
export { sha256, sha384, sha512 } from '@noble/hashes/sha2'
export { sha3_256, sha3_384, sha3_512 } from '@noble/hashes/sha3'

export function getHash(alg: number): CHash {
  switch (alg) {
    case iana.AlgorithmES256:
    case iana.AlgorithmHMAC_256_64:
    case iana.AlgorithmHMAC_256_256:
      return sha256
    case iana.AlgorithmES384:
    case iana.AlgorithmHMAC_384_384:
      return sha384
    case iana.AlgorithmES512:
    case iana.AlgorithmHMAC_512_512:
      return sha512
    default:
      throw new Error(`unsupported hash algorithm ${alg}`)
  }
}
