// AT-06-003 / AT-00-003 / AT-02-002: fresh Windows-selected routes, without forcing a TUN index.
import { assertKoffiAllowedHere, defineStruct, FORWARD_ROW2_SIZE } from './koffiTypes'

export type BestRouteQuery = (destination: Buffer, route: Buffer, source: Buffer) => number
const destinations = [[1, 1, 1, 1], [8, 8, 8, 8], [208, 67, 222, 222]] as const
let cached: BestRouteQuery | undefined
// SOCKADDR_INET is a 28-byte, DWORD-aligned union. Model its storage without
// named union types so a failed/retried binding can safely redeclare the layout.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function assertSelectedRouteLayout(koffi: any): void {
  const address = koffi.array('uint32_t', 7)
  const prefix = defineStruct(koffi, 'VPNTE_IP_ADDRESS_PREFIX', { Prefix: address, PrefixLength: 'uint8_t' })
  const row = defineStruct(koffi, 'VPNTE_SELECTED_FORWARD_ROW2', {
    InterfaceLuid: 'uint64_t', InterfaceIndex: 'uint32_t', DestinationPrefix: prefix, NextHop: address,
    SitePrefixLength: 'uint8_t', ValidLifetime: 'uint32_t', PreferredLifetime: 'uint32_t', Metric: 'uint32_t', Protocol: 'uint32_t',
    Loopback: 'uint8_t', AutoconfigureAddress: 'uint8_t', Publish: 'uint8_t', Immortal: 'uint8_t', Age: 'uint32_t', Origin: 'uint32_t'
  })
  if (koffi.sizeof(address) !== 28 || koffi.sizeof(prefix) !== 32 || koffi.offsetof(prefix, 'Prefix') !== 0
      || koffi.offsetof(prefix, 'PrefixLength') !== 28 || koffi.sizeof(row) !== FORWARD_ROW2_SIZE
      || koffi.offsetof(row, 'InterfaceIndex') !== 8 || koffi.offsetof(row, 'DestinationPrefix') !== 12) {
    throw new Error('selected routes: unsupported MIB_IPFORWARD_ROW2 layout')
  }
}

function getQuery(): BestRouteQuery {
  assertKoffiAllowedHere('selected routes')
  if (process.platform !== 'win32' || !['x64', 'arm64'].includes(process.arch)) throw new Error('selected routes: unsupported platform')
  if (cached) return cached
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const koffi = require('koffi')
  assertSelectedRouteLayout(koffi)
  const best = koffi.load('iphlpapi.dll').func('uint32_t __stdcall GetBestRoute2(const uint64_t *luid, uint32_t index, const uint8_t *source, const uint8_t *destination, uint32_t options, _Out_ uint8_t *route, _Out_ uint8_t *bestSource)')
  cached = (destination, route, source) => best(null, 0, null, destination, 0, route, source)
  return cached
}

/** SOCKADDR_INET is 28 bytes; MIB_IPFORWARD_ROW2 has InterfaceIndex at 8 and prefix family at 12. */
export function readSelectedIpv4InterfacesInProcess(supplied?: BestRouteQuery): number[] {
  const query = supplied ?? getQuery()
  return destinations.map(address => {
    const destination = Buffer.alloc(28), route = Buffer.alloc(FORWARD_ROW2_SIZE), source = Buffer.alloc(28)
    destination.writeUInt16LE(2) // AF_INET
    destination.set(address, 4)
    const rc = query(destination, route, source), index = route.readUInt32LE(8)
    if (rc !== 0 || !index || route.readUInt16LE(12) !== 2 || source.readUInt16LE(0) !== 2) {
      throw new Error('selected routes: complete IPv4 route selection unavailable')
    }
    return index
  })
}
