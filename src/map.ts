// (c) 2023-present, LDC Labs. All rights reserved.
// See the file LICENSE for licensing terms.

import { encodeCBOR, decodeCBOR } from './utils'

export type Label = number | string

export type Value = number | string | Uint8Array | boolean | Value[] | RawMap

export type RawMap = Map<Label, Value>

export type AssertFn<T> = (value: unknown, name: string) => T

export function assertText(value: unknown, name: string): string {
  if (typeof value === 'string') {
    return value
  }

  throw new TypeError(`${name} must be a string, but got ${String(value)}`)
}

export function assertInt(value: unknown, name: string): number {
  if (Number.isSafeInteger(value)) {
    return value as number
  }

  throw new TypeError(`${name} must be a integer, but got ${String(value)}`)
}

export function assertIntOrText(value: unknown, name: string): number | string {
  if (typeof value === 'string') {
    return value
  }

  if (Number.isSafeInteger(value)) {
    return value as number
  }

  throw new TypeError(
    `${name} must be a integer or string, but got ${String(value)}`
  )
}

export function assertBytes(value: unknown, name: string): Uint8Array {
  if (value instanceof Uint8Array) {
    return value
  }

  throw new TypeError(`${name} must be a Uint8Array, but got ${String(value)}`)
}

export function assertBool(value: unknown, name: string): boolean {
  if (typeof value === 'boolean') {
    return value
  }

  throw new TypeError(`${name} must be a Boolean, but got ${String(value)}`)
}

export function assertMap(value: unknown, name: string): RawMap {
  if (value instanceof Map) {
    return value as RawMap
  }

  throw new TypeError(`${name} must be a Map, but got ${String(value)}`)
}

export class KVMap {
  private _raw: RawMap

  static fromBytes(data: Uint8Array): KVMap {
    return new KVMap(decodeCBOR(data))
  }

  constructor(kv: RawMap = new Map()) {
    if (!(kv instanceof Map)) {
      throw new TypeError('key/value must be a Map')
    }

    this._raw = kv
  }

  has(key: Label): boolean {
    return this._raw.has(key)
  }

  delete(key: Label): boolean {
    return this._raw.delete(key)
  }

  getInt(key: Label, name?: string): number {
    return assertInt(this._raw.get(key), name ?? String(key))
  }

  getText(key: Label, name?: string): string {
    return assertText(this._raw.get(key), name ?? String(key))
  }

  getBytes(key: Label, name?: string): Uint8Array {
    return assertBytes(this._raw.get(key), name ?? String(key))
  }

  getBool(key: Label, name?: string): boolean {
    return assertBool(this._raw.get(key), name ?? String(key))
  }

  getType<T>(key: Label, assertFn: AssertFn<T>, name?: string): T {
    return assertFn(this._raw.get(key), name ?? String(key))
  }

  getArray<T>(key: Label, assertFn: AssertFn<T>, name?: string): T[] {
    const na = name ? name : String(key)
    const arr = this._raw.get(key) as T[]

    if (!Array.isArray(arr)) {
      throw new TypeError(`${na} must be an array, but got ${String(arr)}`)
    }

    for (const item of arr) {
      assertFn(item, na)
    }

    return arr
  }

  getParam<T>(key: Label): T | undefined {
    return this._raw.get(key) as T
  }

  setParam(key: Label, value: Value): this {
    this._raw.set(key, value)
    return this
  }

  getCBORParam<T>(key: Label): T | undefined {
    return this._raw.has(key)
      ? decodeCBOR(assertBytes(this._raw.get(key), String(key)))
      : undefined
  }

  setCBORParam<T>(key: Label, value: T): this {
    this._raw.set(key, encodeCBOR(value))
    return this
  }

  clone(): RawMap {
    return new Map(this._raw)
  }

  toRaw(): RawMap {
    return this._raw
  }

  toBytes(): Uint8Array {
    return encodeCBOR(this._raw)
  }
}
