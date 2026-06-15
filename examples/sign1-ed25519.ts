import { Ed25519Key } from '@ldclabs/cose-ts/ed25519'
import { Sign1Message } from '@ldclabs/cose-ts/sign1'
import { utf8ToBytes } from '@ldclabs/cose-ts/utils'

const decoder = new TextDecoder()

export function runSign1Ed25519Example() {
  const signingKey = Ed25519Key.generate('signing-key-1')
  const externalData = utf8ToBytes('profile:sign1:v1')

  const cose = Sign1Message.withTag(
    new Sign1Message(utf8ToBytes('hello cose')).toBytes(
      signingKey,
      externalData
    )
  )

  const verified = Sign1Message.fromBytes(
    signingKey.public(),
    cose,
    externalData
  )

  return {
    cose,
    payload: decoder.decode(verified.payload),
    publicKey: signingKey.public()
  }
}
