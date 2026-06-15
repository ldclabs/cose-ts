import { fileURLToPath } from 'node:url'
import { defineConfig } from 'vitest/config'

const sourceModule = (name: string): string =>
  fileURLToPath(new URL(`./src/${name}.ts`, import.meta.url))

const modules = [
  'aesgcm',
  'aeskw',
  'chacha20poly1305',
  'cwt',
  'ecdh',
  'ecdsa',
  'ed25519',
  'encrypt',
  'encrypt0',
  'hash',
  'header',
  'hkdf',
  'hmac',
  'iana',
  'kdfcontext',
  'key',
  'keyset',
  'mac',
  'mac0',
  'map',
  'recipient',
  'sign',
  'sign1',
  'tag',
  'utils'
]

export default defineConfig({
  resolve: {
    alias: [
      ...modules.map((name) => ({
        find: `@ldclabs/cose-ts/${name}`,
        replacement: sourceModule(name)
      })),
      {
        find: '@ldclabs/cose-ts',
        replacement: sourceModule('index')
      }
    ]
  }
})
