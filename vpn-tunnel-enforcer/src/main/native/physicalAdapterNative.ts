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
  /** Network Location Awareness: connection AdapterId ({GUID}, upper case) -> network names. Throws on any COM failure. */
  listNetworkProfiles(): Map<string, string[]>
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
    if (knownAliases.has(a.alias.toLowerCase())) continue
    if (exclusionRe.test(a.description)) continue
    if (!a.permanentAddressHex || /^0+$/.test(a.permanentAddressHex)) continue

    const own = routes.filter(r => r.ifIndex === a.ifIndex)
    const routes4 = own.filter(r => r.family === 4)
    const gateways = routes4.map(r => r.nextHop).filter(h => h && h !== '0.0.0.0')
    const hasV6Default = own.some(r => r.family === 6)

    const nameServer = source.readNameServer(a.interfaceGuid)
    const networkProfiles = [...(profiles.get(a.interfaceGuid.toUpperCase()) ?? [])]

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

const AF_UNSPEC = 0
const AF_INET = 2
const AF_INET6 = 23
const GAA_FLAGS = 0x2 | 0x4 | 0x80 // SKIP_ANYCAST | SKIP_MULTICAST | INCLUDE_GATEWAYS (kept for layout; gateways unused)
const ERROR_BUFFER_OVERFLOW = 111
const ERROR_FILE_NOT_FOUND = 2
const ERROR_MORE_DATA = 234
const IF_ROW2_SIZE = 1352
const FORWARD_ROW2_SIZE = 104
const GAA_MIN_LENGTH = 276 // through TunnelType in IP_ADAPTER_ADDRESSES_LH (x64)
const HKLM = -2147483646n // 0xFFFFFFFF80000002 as signed 64-bit
const RRF_RT_STRINGS = 0x2 | 0x4 // REG_SZ | REG_EXPAND_SZ

function ipv4At(buf: Buffer, off: number): string {
  return `${buf[off]}.${buf[off + 1]}.${buf[off + 2]}.${buf[off + 3]}`
}

const COINIT_APARTMENTTHREADED = 2
const RPC_E_CHANGED_MODE = -2147417850
const CLSCTX_INPROC_LOCAL = 0x1 | 0x4

function guidFromBytes(b: Buffer): string {
  const d4 = b.subarray(8, 16).toString('hex').toUpperCase()
  const h = (n: number, w: number) => n.toString(16).toUpperCase().padStart(w, '0')
  return `{${h(b.readUInt32LE(0), 8)}-${h(b.readUInt16LE(4), 4)}-${h(b.readUInt16LE(6), 4)}-${d4.slice(0, 4)}-${d4.slice(4)}}`
}

/**
 * INetworkListManager enumeration (read-only). Vtable slots (IDispatch-derived, 7 inherited):
 * INetworkListManager 9 GetNetworkConnections; IEnumNetworkConnections 8 Next;
 * INetworkConnection 7 GetNetwork, 12 GetAdapterId; INetwork 7 GetName.
 */
function listNlaProfiles(koffi: any): Map<string, string[]> {
  const ole = koffi.load('ole32.dll')
  const oleaut = koffi.load('oleaut32.dll')
  const Guid = koffi.struct('VPNTE_GUID', { d1: 'uint32_t', d2: 'uint16_t', d3: 'uint16_t', d4: koffi.array('uint8_t', 8) })
  const CoInitializeEx = ole.func('int32_t __stdcall CoInitializeEx(void *reserved, uint32_t flags)')
  const CoCreateInstance = ole.func('int32_t __stdcall CoCreateInstance(VPNTE_GUID *clsid, void *outer, uint32_t ctx, VPNTE_GUID *iid, _Out_ void **ppv)')
  const SysFreeString = oleaut.func('void __stdcall SysFreeString(void *bstr)')
  const pOut = koffi.proto('int32_t __stdcall VPNTE_COM_Out(void *self, _Out_ void **out)')
  const pNext = koffi.proto('int32_t __stdcall VPNTE_COM_Next(void *self, uint32_t celt, _Out_ void **items, _Out_ uint32_t *fetched)')
  const pGuid = koffi.proto('int32_t __stdcall VPNTE_COM_Guid(void *self, _Out_ uint8_t *guid)')
  const pRelease = koffi.proto('uint32_t __stdcall VPNTE_COM_Release(void *self)')
  const vcall = (obj: unknown, slot: number, proto: unknown, ...args: unknown[]): number => {
    const vtbl = koffi.decode(obj, 'void *')
    const fn = koffi.decode(vtbl, slot * 8, 'void *')
    return koffi.call(fn, proto, obj, ...args)
  }
  const release = (obj: unknown) => { if (obj) vcall(obj, 2, pRelease) }
  const check = (hr: number, what: string) => { if (hr < 0) throw new Error(`native adapter snapshot: ${what} hr=0x${(hr >>> 0).toString(16)}`) }

  void Guid
  const initHr = CoInitializeEx(null, COINIT_APARTMENTTHREADED)
  if (initHr < 0 && initHr !== RPC_E_CHANGED_MODE) throw new Error(`native adapter snapshot: CoInitializeEx hr=0x${(initHr >>> 0).toString(16)}`)
  const clsid = { d1: 0xDCB00C01, d2: 0x570F, d3: 0x4A9B, d4: [0x8D, 0x69, 0x19, 0x9F, 0xDB, 0xA5, 0x72, 0x3B] }
  const iid = { d1: 0xDCB00000, d2: 0x570F, d3: 0x4A9B, d4: [0x8D, 0x69, 0x19, 0x9F, 0xDB, 0xA5, 0x72, 0x3B] }
  const mgrOut: unknown[] = [null]
  check(CoCreateInstance(clsid, null, CLSCTX_INPROC_LOCAL, iid, mgrOut), 'CoCreateInstance(NetworkListManager)')
  const mgr = mgrOut[0]
  if (!mgr) throw new Error('native adapter snapshot: NetworkListManager null')
  const result = new Map<string, string[]>()
  let enumerator: unknown = null
  try {
    const enumOut: unknown[] = [null]
    check(vcall(mgr, 9, pOut, enumOut), 'GetNetworkConnections')
    enumerator = enumOut[0]
    if (!enumerator) throw new Error('native adapter snapshot: connection enumerator null')
    for (let guard = 0; ; guard++) {
      if (guard > 256) throw new Error('native adapter snapshot: connection enumeration loop')
      const items: unknown[] = [null]
      const fetched = [0]
      const hr = vcall(enumerator, 8, pNext, 1, items, fetched)
      check(hr, 'IEnumNetworkConnections::Next')
      if (hr !== 0 || fetched[0] !== 1 || !items[0]) break
      const conn = items[0]
      let network: unknown = null
      try {
        const g = Buffer.alloc(16)
        check(vcall(conn, 12, pGuid, g), 'GetAdapterId')
        const netOut: unknown[] = [null]
        check(vcall(conn, 7, pOut, netOut), 'INetworkConnection::GetNetwork')
        network = netOut[0]
        if (!network) throw new Error('native adapter snapshot: network null')
        const bstrOut: unknown[] = [null]
        check(vcall(network, 7, pOut, bstrOut), 'INetwork::GetName')
        const bstr = bstrOut[0]
        if (!bstr) throw new Error('native adapter snapshot: network name null')
        const name = koffi.decode(bstr, 'char16_t', -1) as string
        SysFreeString(bstr)
        const key = guidFromBytes(g)
        const list = result.get(key) ?? []
        if (name && !list.includes(name)) list.push(name)
        result.set(key, list)
      } finally { release(network); release(conn) }
    }
  } finally { release(enumerator); release(mgr) }
  return result
}

export function createKoffiSource(): NativeAdapterSource {
  if (process.platform !== 'win32') throw new Error('native adapter snapshot: win32 only')
  if (process.arch !== 'x64' && process.arch !== 'arm64') throw new Error('native adapter snapshot: unsupported architecture')
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const koffi = require('koffi')
  const ip = koffi.load('iphlpapi.dll')
  const adv = koffi.load('advapi32.dll')

  // Layout guards: wrong size => refuse (fail closed).
  const ifRow = koffi.struct('VPNTE_MIB_IF_ROW2', {
    InterfaceLuid: 'uint64_t', InterfaceIndex: 'uint32_t', InterfaceGuid: koffi.array('uint8_t', 16),
    Alias: koffi.array('uint16_t', 257), Description: koffi.array('uint16_t', 257),
    PhysicalAddressLength: 'uint32_t', PhysicalAddress: koffi.array('uint8_t', 32), PermanentPhysicalAddress: koffi.array('uint8_t', 32),
    Mtu: 'uint32_t', Type: 'uint32_t', TunnelType: 'uint32_t', MediaType: 'uint32_t', PhysicalMediumType: 'uint32_t',
    AccessType: 'uint32_t', DirectionType: 'uint32_t', InterfaceAndOperStatusFlags: 'uint8_t', OperStatus: 'uint32_t',
    AdminStatus: 'uint32_t', MediaConnectState: 'uint32_t', NetworkGuid: koffi.array('uint8_t', 16), ConnectionType: 'uint32_t',
    TransmitLinkSpeed: 'uint64_t', ReceiveLinkSpeed: 'uint64_t', InOctets: 'uint64_t', InUcastPkts: 'uint64_t',
    InNUcastPkts: 'uint64_t', InDiscards: 'uint64_t', InErrors: 'uint64_t', InUnknownProtos: 'uint64_t',
    InUcastOctets: 'uint64_t', InMulticastOctets: 'uint64_t', InBroadcastOctets: 'uint64_t', OutOctets: 'uint64_t',
    OutUcastPkts: 'uint64_t', OutNUcastPkts: 'uint64_t', OutDiscards: 'uint64_t', OutErrors: 'uint64_t',
    OutUcastOctets: 'uint64_t', OutMulticastOctets: 'uint64_t', OutBroadcastOctets: 'uint64_t', OutQLen: 'uint64_t'
  })
  if (koffi.sizeof(ifRow) !== IF_ROW2_SIZE) throw new Error(`native adapter snapshot: MIB_IF_ROW2 size ${koffi.sizeof(ifRow)} != ${IF_ROW2_SIZE}`)
  const sockaddrInet = koffi.struct('VPNTE_SOCKADDR_INET', { raw: koffi.array('uint8_t', 28) })
  const fwdRow = koffi.struct('VPNTE_MIB_IPFORWARD_ROW2', {
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

  return {
    listUpAdapters() {
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
          const permLen = Math.min(row.readUInt32LE(1056), 32)
          result.push({
            ifIndex,
            interfaceGuid: guid,
            alias: utf16z(buf, toOff(friendlyAddr), buf.length - toOff(friendlyAddr)),
            description: utf16z(buf, toOff(descAddr), buf.length - toOff(descAddr)),
            ipv6Enabled: (flags & 0x100) !== 0,
            ifType: buf.readUInt32LE(o + 100),
            ipv4Dns: dnsOf(buf.readBigUInt64LE(o + 48)),
            permanentAddressHex: row.subarray(1092, 1092 + permLen).toString('hex'),
            filterInterface: (row[1152] & 0x2) !== 0,
            mediaType: row.readUInt32LE(1136),
            physicalMediumType: row.readUInt32LE(1140)
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
      return listNlaProfiles(koffi)
    }
  }
}

/** JSON text equivalent to PHYSICAL_ADAPTER_SNAPSHOT_SCRIPT stdout. Throws on anything unexpected. */
export function readPhysicalAdaptersNative(source: NativeAdapterSource = createKoffiSource()): string {
  return snapshotFromSource(source)
}
