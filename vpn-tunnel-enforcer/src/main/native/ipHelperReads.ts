/**
 * AT-07-002 / AT-07-012 / AT-08-007: read-only iphlpapi/advapi32 bindings (koffi).
 *
 * Replaces cold `powershell.exe` spawns (Get-NetAdapter ~, Get-NetIPConfiguration
 * ~3100 ms, Get-NetRoute ~550 ms) with in-process Win32 calls. Strictly read-only.
 *
 * Contract: every exported function either returns a complete, plausible read
 * or THROWS. Nothing here returns an "empty but fine" result on failure, so a
 * caller can always fall back to its PowerShell path on an exception.
 * koffi is loaded lazily so non-Windows hosts and unit tests that mock this
 * module never touch the native library. x64/arm64 only (struct offsets below
 * are the 64-bit layouts).
 */
import { defineStruct } from './koffiTypes'
import {
  assertEnumerationPlausible, formatIpv4, formatIpv6,
  type RawAdapter, type RawIfConfig, type RawRoute, type RawUnicast
} from './ipHelperTransforms'

const AF_UNSPEC = 0
const AF_INET = 2
const AF_INET6 = 23
const ERROR_BUFFER_OVERFLOW = 111
const GAA_FLAGS = 0x2 | 0x4 | 0x80 // skip anycast, skip multicast, include gateways

const IF_ROW2_SIZE = 1352
const FORWARD_ROW2_SIZE = 104

let api: any = null

function load(): any {
  if (api) return api
  if (process.platform !== 'win32') throw new Error('native network reads are Windows-only')
  if (process.arch !== 'x64' && process.arch !== 'arm64') throw new Error(`unsupported architecture ${process.arch}`)
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const koffi = require('koffi')
  const ip = koffi.load('iphlpapi.dll')
  const adv = koffi.load('advapi32.dll')
  const SockAddr = defineStruct(koffi, 'VPNTE_SOCKET_ADDRESS', { lpSockaddr: 'void *', iSockaddrLength: 'int32_t' })
  const Unicast = defineStruct(koffi, 'VPNTE_IP_ADAPTER_UNICAST_ADDRESS', {
    Length: 'uint32_t', Flags: 'uint32_t', Next: 'void *', Address: SockAddr,
    PrefixOrigin: 'uint32_t', SuffixOrigin: 'uint32_t', DadState: 'uint32_t',
    ValidLifetime: 'uint32_t', PreferredLifetime: 'uint32_t', LeaseLifetime: 'uint32_t', OnLinkPrefixLength: 'uint8_t'
  })
  const AddrNode = defineStruct(koffi, 'VPNTE_IP_ADAPTER_ADDRESS_NODE', {
    Length: 'uint32_t', Reserved: 'uint32_t', Next: 'void *', Address: SockAddr
  })
  const Adapter = defineStruct(koffi, 'VPNTE_IP_ADAPTER_ADDRESSES', {
    Length: 'uint32_t', IfIndex: 'uint32_t', Next: 'void *', AdapterName: 'void *',
    FirstUnicastAddress: 'void *', FirstAnycastAddress: 'void *', FirstMulticastAddress: 'void *',
    FirstDnsServerAddress: 'void *', DnsSuffix: 'void *', Description: 'void *', FriendlyName: 'void *',
    PhysicalAddress: koffi.array('uint8_t', 8), PhysicalAddressLength: 'uint32_t', Flags: 'uint32_t',
    Mtu: 'uint32_t', IfType: 'uint32_t', OperStatus: 'uint32_t', Ipv6IfIndex: 'uint32_t',
    ZoneIndices: koffi.array('uint32_t', 16), FirstPrefix: 'void *',
    TransmitLinkSpeed: 'uint64_t', ReceiveLinkSpeed: 'uint64_t',
    FirstWinsServerAddress: 'void *', FirstGatewayAddress: 'void *'
  })
  api = {
    koffi, Unicast, AddrNode, Adapter,
    GetAdaptersAddresses: ip.func('uint32_t __stdcall GetAdaptersAddresses(uint32_t Family, uint32_t Flags, void *Reserved, _Inout_ uint8_t *Addrs, _Inout_ uint32_t *Size)'),
    GetIfTable2: ip.func('uint32_t __stdcall GetIfTable2(_Out_ void **Table)'),
    GetIpForwardTable2: ip.func('uint32_t __stdcall GetIpForwardTable2(uint16_t Family, _Out_ void **Table)'),
    FreeMibTable: ip.func('void __stdcall FreeMibTable(void *Memory)'),
    RegOpenKeyExW: adv.func('int32_t __stdcall RegOpenKeyExW(uintptr_t hKey, const char16_t *sub, uint32_t opts, uint32_t sam, _Out_ uintptr_t *res)'),
    RegEnumKeyExW: adv.func('int32_t __stdcall RegEnumKeyExW(uintptr_t hKey, uint32_t idx, _Out_ uint8_t *name, _Inout_ uint32_t *cch, void *reserved, void *cls, void *clsLen, void *ft)'),
    RegQueryValueExW: adv.func('int32_t __stdcall RegQueryValueExW(uintptr_t hKey, const char16_t *name, void *reserved, _Out_ uint32_t *type, _Out_ uint8_t *data, _Inout_ uint32_t *cb)'),
    RegCloseKey: adv.func('int32_t __stdcall RegCloseKey(uintptr_t hKey)')
  }
  return api
}

function sockaddrText(a: any, sock: { lpSockaddr: unknown; iSockaddrLength: number }): { family: 4 | 6; text: string } {
  const bytes = Buffer.from(a.koffi.decode(sock.lpSockaddr, 'uint8_t', sock.iSockaddrLength))
  const family = bytes.readUInt16LE(0)
  if (family === AF_INET && bytes.length >= 8) return { family: 4, text: formatIpv4(bytes.subarray(4, 8)) }
  if (family === AF_INET6 && bytes.length >= 24) return { family: 6, text: formatIpv6(bytes.subarray(8, 24)) }
  throw new Error(`unexpected sockaddr family ${family}`)
}

function guidText(b: Buffer, o: number): string {
  const h = (s: number, e: number) => b.subarray(s, e).toString('hex')
  const d1 = b.readUInt32LE(o).toString(16).padStart(8, '0')
  const d2 = b.readUInt16LE(o + 4).toString(16).padStart(4, '0')
  const d3 = b.readUInt16LE(o + 6).toString(16).padStart(4, '0')
  return `{${d1}-${d2}-${d3}-${h(o + 8, o + 10)}-${h(o + 10, o + 16)}}`
}

function utf16z(b: Buffer, o: number, maxChars: number): string {
  let end = o
  const limit = o + maxChars * 2
  while (end < limit && (b[end] !== 0 || b[end + 1] !== 0)) end += 2
  return b.subarray(o, end).toString('utf16le')
}

/** NDIS Characteristics by NetCfgInstanceId (lower-case GUID with braces). */
function readNdisCharacteristics(a: any): Map<string, number> {
  const HKLM = 0x80000002
  const KEY = 'SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e972-e325-11ce-bfc1-08002be10318}'
  const SAM = 0x20019 | 0x100 // KEY_READ | KEY_WOW64_64KEY
  const root = [0]
  const rc = a.RegOpenKeyExW(HKLM, KEY, 0, SAM, root)
  if (rc !== 0) throw new Error(`RegOpenKeyExW(class) failed: ${rc}`)
  const out = new Map<string, number>()
  try {
    for (let idx = 0; ; idx++) {
      const name = Buffer.alloc(512)
      const cch = [256]
      const erc = a.RegEnumKeyExW(root[0], idx, name, cch, null, null, null, null)
      if (erc === 259) break // ERROR_NO_MORE_ITEMS
      if (erc !== 0) throw new Error(`RegEnumKeyExW failed: ${erc}`)
      const sub = name.subarray(0, cch[0] * 2).toString('utf16le')
      if (!/^\d{4}$/.test(sub)) continue
      const k = [0]
      if (a.RegOpenKeyExW(root[0], sub, 0, SAM, k) !== 0) continue // access-denied instance: no entry -> not hidden info
      try {
        const type = [0]
        const buf = Buffer.alloc(256)
        const cb = [256]
        if (a.RegQueryValueExW(k[0], 'NetCfgInstanceId', null, type, buf, cb) !== 0) continue
        const id = buf.subarray(0, cb[0]).toString('utf16le').replace(/\0+$/, '').toLowerCase()
        const t2 = [0]
        const dw = Buffer.alloc(4)
        const cb2 = [4]
        if (a.RegQueryValueExW(k[0], 'Characteristics', null, t2, dw, cb2) !== 0 || cb2[0] !== 4) continue
        out.set(id, dw.readUInt32LE(0))
      } finally {
        a.RegCloseKey(k[0])
      }
    }
  } finally {
    a.RegCloseKey(root[0])
  }
  return out
}

/** All interfaces (including hidden/filter/loopback) from GetIfTable2 + NDIS hidden flag. */
/** NDIS Characteristics by NetCfgInstanceId (lower-case GUID with braces). Throws on registry failure. */
export function readNdisCharacteristicsByGuid(): Map<string, number> {
  return readNdisCharacteristics(load())
}

export function readRawAdapters(): RawAdapter[] {
  const a = load()
  const out = [null as unknown]
  const rc = a.GetIfTable2(out)
  if (rc !== 0) throw new Error(`GetIfTable2 failed: ${rc}`)
  let rows: RawAdapter[]
  try {
    const n = a.koffi.decode(out[0], 'uint32_t') as number
    if (!Number.isInteger(n) || n < 0 || n > 4096) throw new Error(`implausible interface count ${n}`)
    const raw = Buffer.from(a.koffi.decode(out[0], 'uint8_t', 8 + n * IF_ROW2_SIZE))
    const chars = readNdisCharacteristics(a)
    rows = []
    for (let i = 0; i < n; i++) {
      const o = 8 + i * IF_ROW2_SIZE
      const physLen = raw.readUInt32LE(o + 1056)
      if (physLen > 32) throw new Error(`implausible hardware address length ${physLen}`)
      const guid = guidText(raw, o + 12)
      rows.push({
        ifIndex: raw.readUInt32LE(o + 8),
        guid,
        alias: utf16z(raw, o + 28, 257),
        description: utf16z(raw, o + 542, 257),
        mac: [...raw.subarray(o + 1060, o + 1060 + physLen)],
        ifType: raw.readUInt32LE(o + 1128),
        filterInterface: (raw[o + 1152] & 0x02) !== 0,
        operStatus: raw.readUInt32LE(o + 1156),
        mediaConnectState: raw.readUInt32LE(o + 1164),
        linkSpeedBps: Number(raw.readBigUInt64LE(o + 1192)),
        characteristics: chars.has(guid.toLowerCase()) ? chars.get(guid.toLowerCase())! : null
      })
    }
  } finally {
    a.FreeMibTable(out[0])
  }
  assertEnumerationPlausible(rows)
  return rows
}

/** Unicast addresses, gateways and DNS servers per interface (GetAdaptersAddresses). */
export function readRawIfConfigs(): RawIfConfig[] {
  const a = load()
  const size = [32768]
  let buf: Buffer = Buffer.alloc(size[0])
  let rc = 0
  for (let attempt = 0; attempt < 6; attempt++) {
    buf = Buffer.alloc(size[0])
    rc = a.GetAdaptersAddresses(AF_UNSPEC, GAA_FLAGS, null, buf, size)
    if (rc !== ERROR_BUFFER_OVERFLOW) break
  }
  if (rc !== 0) throw new Error(`GetAdaptersAddresses failed: ${rc}`)

  const result: RawIfConfig[] = []
  let cur: any = a.koffi.decode(buf, a.Adapter)
  for (let guard = 0; guard < 4096; guard++) {
    const unicast: RawUnicast[] = []
    for (let u: any = cur.FirstUnicastAddress, g = 0; u && g < 1024; g++) {
      const r: any = a.koffi.decode(u, a.Unicast)
      const s = sockaddrText(a, r.Address)
      unicast.push({ ifIndex: cur.IfIndex, family: s.family, address: s.text, dadState: r.DadState, suffixOrigin: r.SuffixOrigin })
      u = r.Next
    }
    const walk = (head: any): string[] => {
      const list: string[] = []
      for (let p: any = head, g = 0; p && g < 256; g++) {
        const r: any = a.koffi.decode(p, a.AddrNode)
        list.push(sockaddrText(a, r.Address).text)
        p = r.Next
      }
      return list
    }
    result.push({
      ifIndex: cur.IfIndex,
      ipv6IfIndex: cur.Ipv6IfIndex,
      unicast,
      gateways: walk(cur.FirstGatewayAddress),
      dns: walk(cur.FirstDnsServerAddress)
    })
    if (!cur.Next) break
    cur = a.koffi.decode(cur.Next, a.Adapter)
  }
  if (result.length === 0) throw new Error('GetAdaptersAddresses returned no adapters')
  return result
}

/** Active routing table for one family (GetIpForwardTable2). */
export function readRawRoutes(family: 4 | 6): RawRoute[] {
  const a = load()
  const out = [null as unknown]
  const rc = a.GetIpForwardTable2(family === 4 ? AF_INET : AF_INET6, out)
  if (rc !== 0) throw new Error(`GetIpForwardTable2 failed: ${rc}`)
  try {
    const n = a.koffi.decode(out[0], 'uint32_t') as number
    if (!Number.isInteger(n) || n < 0 || n > 200000) throw new Error(`implausible route count ${n}`)
    const raw = Buffer.from(a.koffi.decode(out[0], 'uint8_t', 8 + n * FORWARD_ROW2_SIZE))
    const routes: RawRoute[] = []
    const text = (o: number): string => {
      const fam = raw.readUInt16LE(o)
      if (fam === AF_INET) return formatIpv4(raw.subarray(o + 4, o + 8))
      if (fam === AF_INET6) return formatIpv6(raw.subarray(o + 8, o + 24))
      // An unspecified next hop is all-zero memory (family 0): render as the family's "any".
      if (fam === 0) return family === 4 ? '0.0.0.0' : '::'
      throw new Error(`unexpected route sockaddr family ${fam}`)
    }
    for (let i = 0; i < n; i++) {
      const o = 8 + i * FORWARD_ROW2_SIZE
      const prefixFamily = raw.readUInt16LE(o + 12)
      // Zero-family prefix = 0.0.0.0 / :: with length 0 would be a decode bug, not a route.
      if (prefixFamily !== (family === 4 ? AF_INET : AF_INET6)) throw new Error(`route row ${i}: prefix family ${prefixFamily}`)
      routes.push({
        family,
        ifIndex: raw.readUInt32LE(o + 8),
        prefix: text(o + 12),
        prefixLength: raw[o + 40],
        nextHop: text(o + 44),
        metric: raw.readUInt32LE(o + 84),
        protocol: raw.readUInt32LE(o + 88)
      })
    }
    return routes
  } finally {
    a.FreeMibTable(out[0])
  }
}
