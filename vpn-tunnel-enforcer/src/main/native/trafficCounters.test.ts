// AT-07-009: real ABI layout plus raw uint64 fixtures, no system networking calls.
import { describe, expect, it } from 'vitest'
import { decodeTrafficCounterTable, validateTrafficAdapterName } from './trafficCounters'
import { assertIfRow2Layout, IF_ROW2_OFFSETS, IF_ROW2_SIZE } from './koffiTypes'

function table(names: string[], received = 0xffffffffffffffffn, sent = 9007199254740993n): Buffer {
  const bytes = Buffer.alloc(8 + names.length * IF_ROW2_SIZE)
  bytes.writeUInt32LE(names.length)
  names.forEach((name, i) => {
    const offset = 8 + i * IF_ROW2_SIZE
    bytes.write(name, offset + 28, 512, 'utf16le')
    bytes.fill(i + 1, offset + 12, offset + 28)
    bytes.writeBigUInt64LE(received, offset + 1208)
    bytes.writeBigUInt64LE(sent, offset + 1280)
  })
  return bytes
}

describe('native traffic counter decoding', () => {
  it('matches the installed FFI struct ABI at both counter offsets', () => {
    assertIfRow2Layout(require('koffi'))
    expect(IF_ROW2_OFFSETS).toMatchObject({ inOctets: 1208, outOctets: 1280 })
  })
  it('returns full uint64 decimal strings with exact alias matching', () => {
    expect(decodeTrafficCounterTable(table(['Other', 'VPNTE-TUN']), 'vpnte-tun')).toEqual({ found: true, name: 'VPNTE-TUN', identity: '02'.repeat(16), receivedBytes: '18446744073709551615', sentBytes: '9007199254740993' })
    expect(decodeTrafficCounterTable(table(['Other']), 'VPNTE-TUN')).toMatchObject({ found: false, identity: null, receivedBytes: '0', sentBytes: '0' })
  })
  it('refuses duplicate aliases, truncated rows, implausible counts and unterminated names', () => {
    expect(() => decodeTrafficCounterTable(table(['VPNTE-TUN', 'vpnte-tun']), 'VPNTE-TUN')).toThrow('ambiguous')
    expect(() => decodeTrafficCounterTable(table(['VPNTE-TUN']).subarray(0, -1), 'VPNTE-TUN')).toThrow('table size')
    const empty = Buffer.alloc(8)
    expect(() => decodeTrafficCounterTable(empty, 'VPNTE-TUN')).toThrow('table size')
    const invalid = table(['VPNTE-TUN'])
    invalid.fill(1, 8 + 28, 8 + 28 + 514)
    expect(() => decodeTrafficCounterTable(invalid, 'VPNTE-TUN')).toThrow('unterminated')
  })
  it.each(['', 'a\0b', '\n', 'a'.repeat(257)])('refuses invalid aliases before native access', name => {
    expect(() => validateTrafficAdapterName(name)).toThrow('invalid adapter name')
  })
})
