import { AesGcmKey } from '@ldclabs/cose-ts/aesgcm'
import { Encrypt0Message } from '@ldclabs/cose-ts/encrypt0'
import * as iana from '@ldclabs/cose-ts/iana'
import { utf8ToBytes } from '@ldclabs/cose-ts/utils'

const decoder = new TextDecoder()

export async function runEncrypt0AesGcmExample() {
  const contentKey = AesGcmKey.generate(iana.AlgorithmA128GCM, 'content-key-1')
  const externalData = utf8ToBytes('profile:encrypt0:v1')

  const cose = Encrypt0Message.withTag(
    await new Encrypt0Message(utf8ToBytes('shared-key secret')).toBytes(
      contentKey,
      externalData
    )
  )

  const decrypted = await Encrypt0Message.fromBytes(
    contentKey,
    cose,
    externalData
  )

  return {
    cose,
    payload: decoder.decode(decrypted.payload)
  }
}
