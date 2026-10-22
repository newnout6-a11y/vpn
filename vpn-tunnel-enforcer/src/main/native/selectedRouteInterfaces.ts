// AT-06-003 / AT-02-002: a malformed or partial host reply cannot prove route selection.
import { callNativeHost } from './nativeHost'

export async function nativeOwnedTunIndex(alias: string, guid: string): Promise<number | null> {
  const index = await callNativeHost<unknown>('owned-tun-index', { alias, guid })
  if (index === null) return null
  if (typeof index !== 'number' || !Number.isSafeInteger(index) || index <= 0 || index > 0xffffffff) {
    throw new Error('Native owned TUN interface response is invalid')
  }
  return index
}

export async function nativeSelectedIpv4Interfaces(): Promise<number[]> {
  const indexes = await callNativeHost<unknown>('selected-route-interfaces')
  if (!Array.isArray(indexes) || indexes.length !== 3 ||
      ![...indexes].every(index => typeof index === 'number' && Number.isSafeInteger(index) && index > 0 && index <= 0xffffffff)) {
    throw new Error('Native selected route interfaces response is invalid')
  }
  return indexes
}
