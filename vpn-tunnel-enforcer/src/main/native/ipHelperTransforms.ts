/**
 * AT-07-002 / AT-07-012 / AT-08-007: pure transforms for the native (iphlpapi) network reads.
 *
 * No koffi / no I/O here: everything takes the raw rows produced by
 * `ipHelperReads.ts` and renders them in the exact shapes the old PowerShell
 * scripts emitted (Get-NetAdapter / Get-NetIPConfiguration / Get-NetRoute).
 * Every function either returns a trustworthy result or throws - callers treat
 * a throw as "native path unavailable" and fall back to PowerShell. An empty
 * enumeration is never accepted as a result (see `assertEnumerationPlausible`).
 */

export interface RawAdapter {
  ifIndex: number
  alias: string
  description: string
  guid: string
  /** MIB_IF_ROW2.OperStatus (1 = up, 2 = down, 6 = not present ...) */
  operStatus: number
  /** MIB_IF_ROW2.MediaConnectState (1 = connected, 2 = disconnected) */
  mediaConnectState: number
  /** MIB_IF_ROW2.Type (IANAifType): 24 = loopback, 131 = tunnel */
  ifType: number
  /** Raw hardware address bytes (0 .. 32 bytes). */
  mac: number[]
  linkSpeedBps: number
  /** FilterInterface flag of InterfaceAndOperStatusFlags (NDIS lightweight filter). */
  filterInterface: boolean
  /** NDIS Characteristics & NCF_HIDDEN (0x8); null = adapter has no class-key entry. */
  characteristics: number | null
}

export interface RawUnicast {
  ifIndex: number
  family: 4 | 6
  address: string
  /** NL_DAD_STATE: 0 invalid, 1 tentative, 2 duplicate, 3 deprecated, 4 preferred */
  dadState: number
  /** NL_SUFFIX_ORIGIN: 5 = random (temporary IPv6 address) */
  suffixOrigin: number
}

export interface RawIfConfig {
  ifIndex: number
  ipv6IfIndex: number
  unicast: RawUnicast[]
  gateways: string[]
  dns: string[]
}

export interface RawRoute {
  family: 4 | 6
  ifIndex: number
  prefix: string
  prefixLength: number
  nextHop: string
  metric: number
  protocol: number
}

export interface NativeAdapterRow {
  Name: string
  InterfaceDescription: string
  Status: string
  LinkSpeed: string
  ifIndex: number
}

export interface NativeIpConfigRow {
  InterfaceAlias: string
  IPv4: string
  IPv6: string
  Gateway: string
  DNS: string
}

export interface NativeRouteRow {
  DestinationPrefix: string
  InterfaceAlias: string
  NextHop: string
  RouteMetric: number
  Protocol: string
}

export interface NativePhysicalSource {
  alias: string
  ipv4: string
}

export interface NativeTunnelRow {
  name: string
  description: string
  address: string
  isVpnte: boolean
}

const NCF_HIDDEN = 0x8
const IF_TYPE_LOOPBACK = 24
const IF_TYPE_TUNNEL = 131
const OPER_UP = 1

const ROUTE_PROTOCOL_NAMES: Record<number, string> = {
  1: 'Other', 2: 'Local', 3: 'NetMgmt', 4: 'Icmp', 5: 'Egp', 6: 'Ggp', 7: 'Hello', 8: 'Rip', 9: 'IsIs',
  10: 'EsIs', 11: 'Cisco', 12: 'Bbn', 13: 'Ospf', 14: 'Bgp', 15: 'Idpr', 16: 'Eigrp', 17: 'Dvmrp', 18: 'Rpl', 19: 'Dhcp'
}

/**
 * An enumeration that is empty (or only loopback) can only mean "the read
 * failed", never "this machine has no network" - reject it so the caller falls
 * back to PowerShell instead of reporting a clean/empty result.
 */
export function assertEnumerationPlausible(adapters: RawAdapter[]): void {
  if (!Array.isArray(adapters) || adapters.length === 0) throw new Error('native adapter enumeration returned no interfaces')
  if (!adapters.some(a => a.ifType !== IF_TYPE_LOOPBACK)) throw new Error('native adapter enumeration returned only loopback')
}

/**
 * Equivalent of Get-NetAdapter's default (non -IncludeHidden) listing:
 * NDIS lightweight filters, NCF_HIDDEN adapters (WAN miniports, Wi-Fi Direct,
 * kernel debug ...), loopback and pseudo tunnel interfaces are not listed.
 */
export function visibleAdapters(adapters: RawAdapter[]): RawAdapter[] {
  return adapters.filter(a =>
    !a.filterInterface &&
    a.ifType !== IF_TYPE_LOOPBACK &&
    a.ifType !== IF_TYPE_TUNNEL &&
    !(a.characteristics !== null && (a.characteristics & NCF_HIDDEN) !== 0)
  )
}

export function formatMac(mac: number[]): string {
  return mac.map(b => b.toString(16).padStart(2, '0').toUpperCase()).join('-')
}

export function formatLinkSpeed(bps: number): string {
  if (!Number.isFinite(bps) || bps <= 0 || bps >= 0xffffffffffff) return '0 bps'
  const trim = (v: number) => String(Math.round(v * 10) / 10)
  if (bps >= 1e9) return `${trim(bps / 1e9)} Gbps`
  if (bps >= 1e6) return `${trim(bps / 1e6)} Mbps`
  if (bps >= 1e3) return `${trim(bps / 1e3)} Kbps`
  return `${bps} bps`
}

export function adapterStatus(a: RawAdapter): string {
  if (a.operStatus === OPER_UP) return 'Up'
  if (a.operStatus === 6) return 'Not Present'
  if (a.operStatus === 2 && a.mediaConnectState === 2) return 'Disconnected'
  return 'Disabled'
}

export function toAdapterRows(adapters: RawAdapter[]): NativeAdapterRow[] {
  assertEnumerationPlausible(adapters)
  return visibleAdapters(adapters).map(a => ({
    Name: a.alias,
    InterfaceDescription: a.description,
    Status: adapterStatus(a),
    LinkSpeed: formatLinkSpeed(a.linkSpeedBps),
    ifIndex: a.ifIndex
  }))
}

function isLinkLocalV6(addr: string): boolean {
  return /^fe[89ab][0-9a-f]:/i.test(addr)
}

/** Equivalent of the Get-NetIPConfiguration projection used by systemDiagnostics. */
export function toIpConfigRows(adapters: RawAdapter[], configs: RawIfConfig[]): NativeIpConfigRow[] {
  assertEnumerationPlausible(adapters)
  const byIndex = new Map(configs.map(c => [c.ifIndex, c]))
  const rows: NativeIpConfigRow[] = []
  for (const a of visibleAdapters(adapters)) {
    const cfg = byIndex.get(a.ifIndex)
    // Get-NetIPConfiguration lists only interfaces with an IP binding.
    if (!cfg) continue
    const usable = cfg.unicast.filter(u => u.dadState !== 0 && u.dadState !== 2)
    rows.push({
      InterfaceAlias: a.alias,
      IPv4: usable.filter(u => u.family === 4).map(u => u.address).join(','),
      IPv6: usable.filter(u => u.family === 6 && !isLinkLocalV6(u.address) && u.suffixOrigin !== 5).map(u => u.address).join(','),
      Gateway: cfg.gateways.filter(g => /^\d+\.\d+\.\d+\.\d+$/.test(g)).join(','),
      DNS: cfg.dns.join(',')
    })
  }
  return rows
}

function prefixText(r: RawRoute): string {
  return `${r.prefix}/${r.prefixLength}`
}

/** Equivalent of `Get-NetRoute | ? DestinationPrefix -in $prefixes | Sort AddressFamily,DestinationPrefix,RouteMetric`. */
export function toRouteRows(adapters: RawAdapter[], routes: RawRoute[], prefixes: string[]): NativeRouteRow[] {
  assertEnumerationPlausible(adapters)
  const alias = new Map(adapters.map(a => [a.ifIndex, a.alias]))
  const wanted = new Set(prefixes)
  const picked = routes.filter(r => wanted.has(prefixText(r)))
  picked.sort((a, b) =>
    a.family - b.family ||
    (prefixText(a) < prefixText(b) ? -1 : prefixText(a) > prefixText(b) ? 1 : 0) ||
    a.metric - b.metric
  )
  return picked.map(r => {
    const name = alias.get(r.ifIndex)
    // A route on an interface we cannot name would be invisible to the
    // "is it VPNTE?" check: treat as a failed read, not as "not VPNTE".
    if (name === undefined) throw new Error(`native route table references unknown interface ${r.ifIndex}`)
    return {
      DestinationPrefix: prefixText(r),
      InterfaceAlias: name,
      NextHop: r.nextHop,
      RouteMetric: r.metric,
      Protocol: ROUTE_PROTOCOL_NAMES[r.protocol] ?? String(r.protocol)
    }
  })
}

export const PHYSICAL_EXCLUSION_RX = /Wintun|TAP-Windows|Tailscale|WireGuard|Hyper-V|Loopback|vEthernet|VPN|VirtualBox|VMware|Bluetooth/i

/**
 * Mirror of the legacy leakSelfTest/serverPicker PowerShell filter
 * (Up, description not virtual, real MAC, IPv4 not link-local). The filter is
 * intentionally copied as-is, including the absence of a known-alias
 * exclusion (physicalAdapterSnapshot.ts uses a stricter list).
 */
export function toPhysicalIpv4Sources(adapters: RawAdapter[], configs: RawIfConfig[]): NativePhysicalSource[] {
  assertEnumerationPlausible(adapters)
  const byIndex = new Map(configs.map(c => [c.ifIndex, c]))
  const out: NativePhysicalSource[] = []
  for (const a of visibleAdapters(adapters)) {
    if (a.operStatus !== OPER_UP) continue
    if (PHYSICAL_EXCLUSION_RX.test(a.description)) continue
    const mac = formatMac(a.mac)
    if (!mac || mac === '00-00-00-00-00-00') continue
    const cfg = byIndex.get(a.ifIndex)
    if (!cfg) continue
    for (const u of cfg.unicast) {
      if (u.family !== 4 || u.dadState === 0 || u.dadState === 2) continue
      if (!u.address || u.address.startsWith('169.254.')) continue
      out.push({ alias: a.alias, ipv4: u.address })
    }
  }
  return out
}

export const TUNNEL_RX = /wintun|\btun\b|wireguard|openvpn|tap-windows|happ|hiddify|singbox|sing-tun|v2ray|xray|vpn/i

/** Equivalent of connectionPlanner's Get-NetAdapter | Get-NetIPAddress tunnel probe. */
export function toActiveTunnels(
  adapters: RawAdapter[],
  configs: RawIfConfig[],
  opts: { vpnteAlias: string; vpnteIpv4Prefix: string }
): NativeTunnelRow[] {
  assertEnumerationPlausible(adapters)
  const byIndex = new Map(configs.map(c => [c.ifIndex, c]))
  const out: NativeTunnelRow[] = []
  for (const a of visibleAdapters(adapters)) {
    if (a.operStatus !== OPER_UP) continue
    if (!(TUNNEL_RX.test(a.alias) || TUNNEL_RX.test(a.description))) continue
    const ips = (byIndex.get(a.ifIndex)?.unicast ?? [])
      .filter(u => u.family === 4 && u.address && u.dadState !== 0 && u.dadState !== 2)
      .map(u => u.address)
    out.push({
      name: a.alias,
      description: a.description,
      address: ips.join(', '),
      isVpnte: a.alias === opts.vpnteAlias || ips.join(',').startsWith(opts.vpnteIpv4Prefix)
    })
  }
  return out
}

/** RFC 5952 text form of 16 raw IPv6 bytes. */
export function formatIpv6(bytes: ArrayLike<number>): string {
  const groups: number[] = []
  for (let i = 0; i < 16; i += 2) groups.push(((bytes[i] << 8) | bytes[i + 1]) >>> 0)
  let bestStart = -1
  let bestLen = 0
  for (let i = 0; i < 8;) {
    if (groups[i] !== 0) { i++; continue }
    let j = i
    while (j < 8 && groups[j] === 0) j++
    if (j - i > bestLen) { bestStart = i; bestLen = j - i }
    i = j
  }
  if (bestLen < 2) return groups.map(g => g.toString(16)).join(':')
  const head = groups.slice(0, bestStart).map(g => g.toString(16)).join(':')
  const tail = groups.slice(bestStart + bestLen).map(g => g.toString(16)).join(':')
  return `${head}::${tail}`
}

export function formatIpv4(bytes: ArrayLike<number>): string {
  return `${bytes[0]}.${bytes[1]}.${bytes[2]}.${bytes[3]}`
}
