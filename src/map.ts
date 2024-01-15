// (c) 2023-present, LDC Labs. All rights reserved.
// See the file LICENSE for licensing terms.

import { encode, decode } from './utils'

export type Label = number | string

export type Value = number | string | Uint8Array | boolean | Value[]

export type RawMap = Map<Label, Value>

export type AssertFn<T> = (value: unknown, name: string) => T

export function assertText(value: unknown, name: string): string {
  if (typeof value === 'string') {
    return value
  }

  throw new TypeError(`${name} must be a string`)
}

export function assertInt(value: unknown, name: string): number {
  if (Number.isSafeInteger(value)) {
    return value as number
  }

  throw new TypeError(`${name} must be a integer`)
}

export function assertIntOrText(value: unknown, name: string): number | string {
  if (typeof value === 'string') {
    return value
  }

  if (Number.isSafeInteger(value)) {
    return value as number
  }

  throw new TypeError(`${name} must be a integer or string`)
}

export function assertBytes(value: unknown, name: string): Uint8Array {
  if (value instanceof Uint8Array) {
    return value
  }

  throw new TypeError(`${name} must be a Uint8Array`)
}

export function assertBool(value: unknown, name: string): boolean {
  if (typeof value === 'boolean') {
    return value
  }

  throw new TypeError(`${name} must be a Boolean`)
}

export class KVMap {
  private raw: RawMap

  static fromBytes(data: Uint8Array): KVMap {
    return new KVMap(decode(data))
  }

  constructor(kv: RawMap = new Map()) {
    if (!(kv instanceof Map)) {
      throw new TypeError('key/value must be a Map')
    }

    this.raw = kv
  }

  has(key: Label): boolean {
    return this.raw.has(key)
  }

  getInt(key: Label, name?: string): number {
    return assertInt(this.raw.get(key), name ?? String(key))
  }

  getText(key: Label, name?: string): string {
    return assertText(this.raw.get(key), name ?? String(key))
  }

  getBytes(key: Label, name?: string): Uint8Array {
    return assertBytes(this.raw.get(key), name ?? String(key))
  }

  getBool(key: Label, name?: string): boolean {
    return assertBool(this.raw.get(key), name ?? String(key))
  }

  getType<T>(key: Label, assertFn: AssertFn<T>, name?: string): T {
    return assertFn(this.raw.get(key), name ?? String(key))
  }

  getArray<T>(key: Label, assertFn: AssertFn<T>, name?: string): T[] {
    const na = name ? name : String(key)
    const arr = this.raw.get(key) as T[]

    if (!Array.isArray(arr)) {
      throw new TypeError(`${na} must be an array`)
    }

    for (const item of arr) {
      assertFn(item, na)
    }

    return arr
  }

  getParam<T>(key: Label): T | undefined {
    return this.raw.get(key) as T
  }

  setParam(key: Label, value: Value): this {
    this.raw.set(key, value)
    return this
  }

  toRaw(): RawMap {
    return this.raw
  }

  toBytes(): Uint8Array {
    return encode(this.raw)
  }
}
