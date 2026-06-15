import { HMACKey } from '@ldclabs/cose-ts/hmac'
import * as iana from '@ldclabs/cose-ts/iana'
import { Mac0Message } from '@ldclabs/cose-ts/mac0'
import { utf8ToBytes } from '@ldclabs/cose-ts/utils'

const decoder = new TextDecoder()

export function runMac0HmacExample() {
  const macKey = HMACKey.generate(iana.AlgorithmHMAC_256_256, 'mac-key-1')
  const externalData = utf8ToBytes('profile:mac0:v1')

  const cose = Mac0Message.withTag(
    new Mac0Message(utf8ToBytes('authenticated content')).toBytes(
      macKey,
      externalData
    )
  )

  const verified = Mac0Message.fromBytes(macKey, cose, externalData)

  return {
    cose,
    payload: decoder.decode(verified.payload)
  }
}
