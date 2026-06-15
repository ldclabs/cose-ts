import { AesGcmKey } from '@ldclabs/cose-ts/aesgcm'
import { AesKwKey } from '@ldclabs/cose-ts/aeskw'
import { EncryptMessage } from '@ldclabs/cose-ts/encrypt'
import * as iana from '@ldclabs/cose-ts/iana'
import { Recipient } from '@ldclabs/cose-ts/recipient'
import { utf8ToBytes } from '@ldclabs/cose-ts/utils'

const decoder = new TextDecoder()

export async function runEncryptAesKwExample() {
  const contentKey = AesGcmKey.generate(iana.AlgorithmA256GCM)
  const recipientKey = AesKwKey.generate(iana.AlgorithmA256KW, 'recipient-1')
  const externalData = utf8ToBytes('profile:encrypt:v1')

  const cose = EncryptMessage.withTag(
    await new EncryptMessage(
      utf8ToBytes('wrapped-key secret'),
      undefined,
      undefined,
      [Recipient.keyWrap(recipientKey)]
    ).toBytes(contentKey, externalData)
  )

  const decrypted = await EncryptMessage.fromBytes(
    [recipientKey],
    cose,
    externalData
  )

  return {
    cose,
    payload: decoder.decode(decrypted.payload)
  }
}
