// AT-07-009 / F-081: never round uint64 OS counters before subtracting samples.
import { IF_ROW2_OFFSETS, IF_ROW2_SIZE } from './koffiTypes'

export interface NativeTrafficCounters {
  found: boolean
  name: string
  identity: string | null
  receivedBytes: string
  sentBytes: string
}

export function validateTrafficAdapterName(value: unknown): string {
  if (typeof value !== 'string' || !value.trim() || value.length > 256 || /[\x00-\x1f]/.test(value)) {
    throw new Error('traffic counters: invalid adapter name')
  }
  return value
}

export function decodeTrafficCounterTable(raw: Buffer, adapterName: string): NativeTrafficCounters {
  validateTrafficAdapterName(adapterName)
  if (raw.length < 8) throw new Error('traffic counters: truncated table')
  const count = raw.readUInt32LE(0)
  if (count < 1 || count > 4096 || raw.length !== 8 + count * IF_ROW2_SIZE) throw new Error('traffic counters: invalid table size')
  let result: NativeTrafficCounters | null = null
  for (let i = 0; i < count; i++) {
    const offset = 8 + i * IF_ROW2_SIZE
    const aliasBytes = raw.subarray(offset + 28, offset + 28 + 514)
    let end = 0
    while (end < aliasBytes.length && aliasBytes.readUInt16LE(end) !== 0) end += 2
    if (end === aliasBytes.length) throw new Error('traffic counters: unterminated adapter name')
    const name = aliasBytes.subarray(0, end).toString('utf16le')
    if (name.toLowerCase() !== adapterName.toLowerCase()) continue
    if (result) throw new Error('traffic counters: ambiguous adapter name')
    result = {
      found: true, name,
      identity: raw.subarray(offset + 12, offset + 28).toString('hex'),
      receivedBytes: raw.readBigUInt64LE(offset + IF_ROW2_OFFSETS.inOctets).toString(),
      sentBytes: raw.readBigUInt64LE(offset + IF_ROW2_OFFSETS.outOctets).toString()
    }
  }
  return result ?? { found: false, name: adapterName, identity: null, receivedBytes: '0', sentBytes: '0' }
}
