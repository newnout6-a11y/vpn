/**
 * AT-03-005/006/010: native (iphlpapi via koffi) READ path for the physical adapter snapshot.
 *
 * Produces the same JSON text as PHYSICAL_ADAPTER_SNAPSHOT_SCRIPT (field names, order, casing,
 * single-object-vs-array shape of ConvertTo-Json). Fail closed: any load error, unexpected struct
 * size, API failure, parse inconsistency or an empty adapter set THROWS, so the caller falls back
 * to the PowerShell path. It never returns an empty list that could read as "no adapters".
 * Read-only: no DNS/adapter/firewall write is performed here.
 */
import { ALL_KNOWN_ALIASES } from '../tunAdapter'
import { ADAPTER_EXCLUSION_PATTERN } from '../physicalAdapterSnapshot'
import { fetchNetworkProfiles } from './networkProfiles'
import {
  AF_INET, AF_INET6, AF_UNSPEC, assertIfRow2Layout, defineStruct, ERROR_BUFFER_OVERFLOW, FORWARD_ROW2_SIZE, GAA_FLAGS,
  IF_ROW2_OFFSETS, IF_ROW2_SIZE
} from './koffiTypes'
import { readNdisCharacteristicsByGuid } from './ipHelperReads'

export interface NativeAdapterInfo {
  ifIndex: number
  interfaceGuid: string
  alias: string
  description: string
  ipv6Enabled: boolean
  ifType: number
  ipv4Dns: string[]
  /** MIB_IF_ROW2.PermanentPhysicalAddress (trimmed to PhysicalAddressLength) as hex, '' if none. */
  permanentAddressHex: string
  filterInterface: boolean
  /** NDIS Characteristics; NCF_HIDDEN (0x8) adapters are skipped like PowerShell's Hidden. null/undefined = no class-key entry. */
  characteristics?: number | null
  mediaType: number
  physicalMediumType: number
}

export interface NativeDefaultRoute { ifIndex: number; family: 4 | 6; nextHop: string }

export interface NativeAdapterSource {
  /** Up (IfOperStatus == 1) adapters only. */
  listUpAdapters(): NativeAdapterInfo[]
  /** Active-store default routes (prefix length 0, all-zero destination), both families. */
  listDefaultRoutes(): NativeDefaultRoute[]
  /** HKLM Tcpip\Parameters\Interfaces\{guid}\NameServer; null when value absent. */
  readNameServer(interfaceGuid: string): string | null
  /** Connection profile names keyed by InterfaceIndex (as Get-NetConnectionProfile reports them). Supplied from outside: no COM in-process. */
  listNetworkProfiles(): Map<number, string[]>
}

export interface PhysicalAdapterRow {
  ifIndex: number
  interfaceGuid: string
  alias: string
  description: string
  ipv6Enabled: boolean
  ipv4Dns: string[]
  gateways: string[]
  networkProfiles: string[]
  ipv4DnsSource: 'dhcp' | 'static'
  isCellularOrTethering: boolean
}

const exclusionRe = new RegExp(ADAPTER_EXCLUSION_PATTERN, 'i')
const knownAliases = new Set(ALL_KNOWN_ALIASES.map(a => a.toLowerCase()))
// .NET \b is Unicode-aware; emulate with lookarounds so Cyrillic neighbours do not create a boundary.
const B = '(?<![\\p{L}\\p{N}_])'
const E = '(?![\\p{L}\\p{N}_])'
const descMobileRe = new RegExp(`${B}(rndis|cellular|mobile|wwan|lte|[345]g|modem|tether|tethering)${E}|remote ndis|apple mobile device`, 'iu')
const nameMobileRe = new RegExp(`${B}(cellular|mobile|wwan|lte|[345]g|modem|tether|tethering)${E}`, 'iu')
const hotspotRe = /^192\.168\.(43|137|225|8)\.|^172\.20\.10\./

const NCF_HIDDEN = 0x8
const IF_TYPE_WWANPP = 243
const IF_TYPE_WWANPP2 = 244
const NDIS_MEDIUM_WIRELESS_WAN = 2
const NDIS_PHYSICAL_MEDIUM_WIRELESS_WAN = 8

/** Pure transformation: same selection and classification as the PowerShell CIM branch. */
export function buildPhysicalAdapterRows(source: NativeAdapterSource): PhysicalAdapterRow[] {
  const adapters = source.listUpAdapters()
  const routes = source.listDefaultRoutes()
  const profiles = source.listNetworkProfiles()
  const rows: PhysicalAdapterRow[] = []
  for (const a of adapters) {
    if (a.filterInterface) continue
    if (a.characteristics != null && (a.characteristics & NCF_HIDDEN) !== 0) continue
    if (knownAliases.has(a.alias.toLowerCase())) continue
    if (exclusionRe.test(a.description)) continue
    if (!a.permanentAddressHex || /^0+$/.test(a.permanentAddressHex)) continue

    const own = routes.filter(r => r.ifIndex === a.ifIndex)
    const routes4 = own.filter(r => r.family === 4)
    const gateways = routes4.map(r => r.nextHop).filter(h => h && h !== '0.0.0.0')
    const hasV6Default = own.some(r => r.family === 6)

    const nameServer = source.readNameServer(a.interfaceGuid)
    const networkProfiles = [...(profiles.get(a.ifIndex) ?? [])]

    const isHotspotSubnet = a.ipv4Dns.some(d => hotspotRe.test(d)) || gateways.some(g => hotspotRe.test(g))
    const hasClatOrIpv6Only = hasV6Default && routes4.length === 0
    const isWwan = a.ifType === IF_TYPE_WWANPP || a.ifType === IF_TYPE_WWANPP2 ||
      a.mediaType === NDIS_MEDIUM_WIRELESS_WAN || a.physicalMediumType === NDIS_PHYSICAL_MEDIUM_WIRELESS_WAN
    const isCellularOrTethering = descMobileRe.test(a.description) || nameMobileRe.test(a.alias) ||
      isWwan || isHotspotSubnet || hasClatOrIpv6Only

    rows.push({
      ifIndex: a.ifIndex,
      interfaceGuid: a.interfaceGuid,
      alias: a.alias,
      description: a.description,
      ipv6Enabled: a.ipv6Enabled,
      ipv4Dns: a.ipv4Dns,
      gateways,
      networkProfiles,
      ipv4DnsSource: nameServer !== null && nameServer.trim() !== '' ? 'static' : 'dhcp',
      isCellularOrTethering
    })
  }
  return rows
}

/** ConvertTo-Json -Compress shape: one row => bare object, several => array. Empty is refused. */
export function serializeRows(rows: PhysicalAdapterRow[]): string {
  if (rows.length === 0) throw new Error('native adapter snapshot: no physical adapters (refusing empty result)')
  return JSON.stringify(rows.length === 1 ? rows[0] : rows)
}

export function snapshotFromSource(source: NativeAdapterSource): string {
  return serializeRows(buildPhysicalAdapterRows(source))
}

// ───────────────────────── FFI layer ─────────────────────────

const ERROR_FILE_NOT_FOUND = 2
const ERROR_MORE_DATA = 234
const GAA_MIN_LENGTH = 276 // through TunnelType in IP_ADAPTER_ADDRESSES_LH (x64)
const HKLM = -2147483646n // 0xFFFFFFFF80000002 as signed 64-bit
const RRF_RT_STRINGS = 0x2 | 0x4 // REG_SZ | REG_EXPAND_SZ

function ipv4At(buf: Buffer, off: number): string {
  return `${buf[off]}.${buf[off + 1]}.${buf[off + 2]}.${buf[off + 3]}`
}


type SourceFactory = (profiles: Map<number, string[]>) => NativeAdapterSource
let sourceFactory: SourceFactory | null = null

/** koffi types and functions are declared once per process; each snapshot only binds fresh profile names. */
export function createKoffiSource(profiles: Map<number, string[]>): NativeAdapterSource {
  sourceFactory ??= buildSourceFactory()
  return sourceFactory(profiles)
}

/** Test seam: forget the cached bindings. */
export function resetKoffiSourceForTests(): void { sourceFactory = null }

function buildSourceFactory(): SourceFactory {
  if (process.platform !== 'win32') throw new Error('native adapter snapshot: win32 only')
  if (process.arch !== 'x64' && process.arch !== 'arm64') throw new Error('native adapter snapshot: unsupported architecture')
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const koffi = require('koffi')
  const ip = koffi.load('iphlpapi.dll')
  const adv = koffi.load('advapi32.dll')

  // Layout guards: wrong size => refuse (fail closed).
  assertIfRow2Layout(koffi)
  const sockaddrInet = defineStruct(koffi, 'VPNTE_SOCKADDR_INET', { raw: koffi.array('uint8_t', 28) })
  const fwdRow = defineStruct(koffi, 'VPNTE_MIB_IPFORWARD_ROW2', {
    InterfaceLuid: 'uint64_t', InterfaceIndex: 'uint32_t', DestAddr: sockaddrInet, DestPrefixLength: 'uint8_t',
    NextHop: sockaddrInet, SitePrefixLength: 'uint8_t', ValidLifetime: 'uint32_t', PreferredLifetime: 'uint32_t',
    Metric: 'uint32_t', Protocol: 'uint32_t', Loopback: 'uint8_t', AutoconfigureAddress: 'uint8_t', Publish: 'uint8_t',
    Immortal: 'uint8_t', Age: 'uint32_t', Origin: 'uint32_t'
  })
  if (koffi.sizeof(fwdRow) !== FORWARD_ROW2_SIZE) throw new Error(`native adapter snapshot: MIB_IPFORWARD_ROW2 size ${koffi.sizeof(fwdRow)} != ${FORWARD_ROW2_SIZE}`)

  const GetAdaptersAddresses = ip.func('uint32_t __stdcall GetAdaptersAddresses(uint32_t family, uint32_t flags, void *reserved, _Out_ uint8_t *buf, _Inout_ uint32_t *size)')
  const GetIfEntry2 = ip.func('uint32_t __stdcall GetIfEntry2(_Inout_ uint8_t *row)')
  const GetIpForwardTable2 = ip.func('uint32_t __stdcall GetIpForwardTable2(uint16_t family, _Out_ void **table)')
  const FreeMibTable = ip.func('void __stdcall FreeMibTable(void *mem)')
  const RegGetValueW = adv.func('int32_t __stdcall RegGetValueW(int64_t hkey, str16 subKey, str16 value, uint32_t flags, _Out_ uint32_t *type, _Out_ uint8_t *data, _Inout_ uint32_t *len)')

  const utf16z = (buf: Buffer, start: number, maxBytes: number): string => {
    let end = start
    while (end + 1 < start + maxBytes && (buf[end] !== 0 || buf[end + 1] !== 0)) end += 2
    return buf.toString('utf16le', start, end)
  }

  const regString = (subKey: string, value: string): string | null => {
    const len = [0]
    let rc = RegGetValueW(HKLM, subKey, value, RRF_RT_STRINGS, null, null, len)
    if (rc === ERROR_FILE_NOT_FOUND) return null
    if (rc !== 0 && rc !== ERROR_MORE_DATA) throw new Error(`native adapter snapshot: RegGetValueW(${value}) rc=${rc}`)
    for (let attempt = 0; attempt < 3; attempt++) {
      const data = Buffer.alloc(len[0] + 2)
      len[0] = data.length - 2
      rc = RegGetValueW(HKLM, subKey, value, RRF_RT_STRINGS, null, data, len)
      if (rc === ERROR_FILE_NOT_FOUND) return null
      if (rc === ERROR_MORE_DATA) continue
      if (rc !== 0) throw new Error(`native adapter snapshot: RegGetValueW(${value}) rc=${rc}`)
      return utf16z(data, 0, len[0])
    }
    throw new Error('native adapter snapshot: registry value kept growing')
  }

  return profiles => ({
    listUpAdapters() {
      const characteristics = readNdisCharacteristicsByGuid()
      const size = [0]
      let rc = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAGS, null, null, size)
      let buf: Buffer | null = null
      for (let attempt = 0; attempt < 4 && (rc === ERROR_BUFFER_OVERFLOW || (rc === 0 && !buf)); attempt++) {
        buf = Buffer.alloc(size[0] + 4096)
        size[0] = buf.length
        rc = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAGS, null, buf, size)
      }
      if (rc !== 0 || !buf) throw new Error(`native adapter snapshot: GetAdaptersAddresses rc=${rc}`)
      const base = BigInt(koffi.address(buf))
      const toOff = (p: bigint): number => {
        const o = p - base
        if (o < 0n || o >= BigInt(buf!.length)) throw new Error('native adapter snapshot: pointer outside buffer')
        return Number(o)
      }
      const dnsOf = (head: bigint): string[] => {
        const out: string[] = []
        let n = head
        for (let guard = 0; n !== 0n; guard++) {
          if (guard > 64) throw new Error('native adapter snapshot: DNS list loop')
          const o = toOff(n)
          const sa = buf!.readBigUInt64LE(o + 16)
          if (sa !== 0n) {
            const so = toOff(sa)
            if (buf!.readUInt16LE(so) === AF_INET) out.push(ipv4At(buf!, so + 4))
          }
          n = buf!.readBigUInt64LE(o + 8)
        }
        return out
      }
      const result: NativeAdapterInfo[] = []
      let cur = base
      let sawAny = false
      for (let guard = 0; ; guard++) {
        if (guard > 512) throw new Error('native adapter snapshot: adapter list loop')
        const o = toOff(cur)
        const length = buf.readUInt32LE(o)
        if (length < GAA_MIN_LENGTH) throw new Error(`native adapter snapshot: IP_ADAPTER_ADDRESSES length ${length}`)
        sawAny = true
        const operStatus = buf.readUInt32LE(o + 104)
        if (operStatus === 1) {
          const ifIndex = buf.readUInt32LE(o + 4)
          const nameAddr = buf.readBigUInt64LE(o + 16)
          const descAddr = buf.readBigUInt64LE(o + 64)
          const friendlyAddr = buf.readBigUInt64LE(o + 72)
          if (nameAddr === 0n || descAddr === 0n || friendlyAddr === 0n) throw new Error('native adapter snapshot: null adapter string')
          const no = toOff(nameAddr)
          let ne = no
          while (buf[ne] !== 0) { if (++ne >= buf.length) throw new Error('native adapter snapshot: unterminated name') }
          const guid = buf.toString('latin1', no, ne).toUpperCase()
          if (!/^\{[0-9A-F]{8}-([0-9A-F]{4}-){3}[0-9A-F]{12}\}$/.test(guid)) throw new Error('native adapter snapshot: unexpected adapter GUID')
          const flags = buf.readUInt32LE(o + 92)

          const row = Buffer.alloc(IF_ROW2_SIZE)
          row.writeUInt32LE(ifIndex, 8)
          const rr = GetIfEntry2(row)
          if (rr !== 0) throw new Error(`native adapter snapshot: GetIfEntry2(${ifIndex}) rc=${rr}`)
          const permLen = row.readUInt32LE(1056)
          // A length beyond the 32-byte buffer is a decode problem, not something to clamp (fail closed).
          if (permLen > 32) throw new Error(`native adapter snapshot: implausible PhysicalAddressLength ${permLen}`)
          result.push({
            ifIndex,
            interfaceGuid: guid,
            alias: utf16z(buf, toOff(friendlyAddr), buf.length - toOff(friendlyAddr)),
            description: utf16z(buf, toOff(descAddr), buf.length - toOff(descAddr)),
            ipv6Enabled: (flags & 0x100) !== 0,
            ifType: buf.readUInt32LE(o + 100),
            ipv4Dns: dnsOf(buf.readBigUInt64LE(o + 48)),
            permanentAddressHex: row.subarray(IF_ROW2_OFFSETS.permanentPhysicalAddress, IF_ROW2_OFFSETS.permanentPhysicalAddress + permLen).toString('hex'),
            filterInterface: (row[IF_ROW2_OFFSETS.interfaceAndOperStatusFlags] & 0x2) !== 0,
            characteristics: characteristics.get(guid.toLowerCase()) ?? null,
            mediaType: row.readUInt32LE(IF_ROW2_OFFSETS.mediaType),
            physicalMediumType: row.readUInt32LE(IF_ROW2_OFFSETS.physicalMediumType)
          })
        }
        const next = buf.readBigUInt64LE(o + 8)
        if (next === 0n) break
        cur = next
      }
      if (!sawAny) throw new Error('native adapter snapshot: GetAdaptersAddresses returned no adapters')
      return result
    },

    listDefaultRoutes() {
      const out: [unknown] = [null]
      const rc = GetIpForwardTable2(AF_UNSPEC, out)
      if (rc !== 0 || !out[0]) throw new Error(`native adapter snapshot: GetIpForwardTable2 rc=${rc}`)
      try {
        const head = Buffer.from(koffi.view(out[0], 8))
        const count = head.readUInt32LE(0)
        if (count > 100000) throw new Error('native adapter snapshot: implausible route count')
        const table = Buffer.from(koffi.view(out[0], 8 + count * FORWARD_ROW2_SIZE))
        const routes: NativeDefaultRoute[] = []
        for (let i = 0; i < count; i++) {
          const r = 8 + i * FORWARD_ROW2_SIZE
          const destFamily = table.readUInt16LE(r + 12)
          const prefixLen = table[r + 12 + 28]
          if (prefixLen !== 0) continue
          if (destFamily === AF_INET) {
            if (table.readUInt32LE(r + 12 + 4) !== 0) continue
            routes.push({ ifIndex: table.readUInt32LE(r + 8), family: 4, nextHop: ipv4At(table, r + 44 + 4) })
          } else if (destFamily === AF_INET6) {
            if (!table.subarray(r + 12 + 8, r + 12 + 24).every(b => b === 0)) continue
            routes.push({ ifIndex: table.readUInt32LE(r + 8), family: 6, nextHop: '::' })
          }
        }
        return routes
      } finally {
        FreeMibTable(out[0])
      }
    },

    readNameServer(interfaceGuid) {
      return regString(`SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\${interfaceGuid}`, 'NameServer')
    },

    listNetworkProfiles() {
      return profiles
    }
  })
}

/** JSON text equivalent to PHYSICAL_ADAPTER_SNAPSHOT_SCRIPT stdout. Throws on anything unexpected. */
export async function readPhysicalAdaptersNative(source?: NativeAdapterSource): Promise<string> {
  return snapshotFromSource(source ?? createKoffiSource(await fetchNetworkProfiles()))
}
