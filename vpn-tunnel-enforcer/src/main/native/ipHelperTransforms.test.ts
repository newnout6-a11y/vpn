// AT-07-002 / AT-07-012 / AT-08-007: pure transforms keep the PowerShell output shapes and fail closed.
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import {
  assertEnumerationPlausible, formatIpv6, formatLinkSpeed, formatMac, toActiveTunnels, toAdapterRows,
  toIpConfigRows, toPhysicalIpv4Sources, toRouteRows,
  type RawAdapter, type RawIfConfig, type RawRoute
} from './ipHelperTransforms'

const adapter = (over: Partial<RawAdapter>): RawAdapter => ({
  ifIndex: 1, alias: 'Ethernet', description: 'Intel(R) Ethernet', guid: '{x}', operStatus: 1, mediaConnectState: 1,
  ifType: 6, mac: [0x5c, 0xc3, 0x36, 0xf5, 0xa6, 0x0a], linkSpeedBps: 1_000_000_000, filterInterface: false,
  characteristics: 1, ...over
})
const cfg = (ifIndex: number, over: Partial<RawIfConfig> = {}): RawIfConfig => ({
  ifIndex, ipv6IfIndex: ifIndex, gateways: [], dns: [], unicast: [], ...over
})
const v4 = (ifIndex: number, address: string, dadState = 4) => ({ ifIndex, family: 4 as const, address, dadState, suffixOrigin: 3 })
const v6 = (ifIndex: number, address: string, suffixOrigin = 3) => ({ ifIndex, family: 6 as const, address, dadState: 4, suffixOrigin })

const wifi = adapter({ ifIndex: 17, alias: 'Беспроводная сеть', description: 'MediaTek Wi-Fi 6E' })
const loop = adapter({ ifIndex: 1, alias: 'Loopback Pseudo-Interface 1', description: 'Software Loopback Interface 1', ifType: 24, mac: [] })

describe('enumeration plausibility (fail closed)', () => {
  it('rejects an empty or loopback-only enumeration', () => {
    expect(() => assertEnumerationPlausible([])).toThrow()
    expect(() => assertEnumerationPlausible([loop])).toThrow()
    expect(() => toPhysicalIpv4Sources([], [])).toThrow()
    expect(() => toActiveTunnels([loop], [], { vpnteAlias: 'x', vpnteIpv4Prefix: '1.' })).toThrow()
    expect(() => toAdapterRows([])).toThrow()
    expect(() => toIpConfigRows([], [])).toThrow()
    expect(() => toRouteRows([], [], [])).toThrow()
  })

  it('accepts a normal enumeration whose filtered result is legitimately empty', () => {
    expect(toActiveTunnels([wifi, loop], [cfg(17, { unicast: [v4(17, '192.168.0.2')] })], { vpnteAlias: 'VPNTE', vpnteIpv4Prefix: '192.168.250.' })).toEqual([])
  })
})

describe('adapter rows', () => {
  it('hides filter, NCF_HIDDEN, loopback and tunnel pseudo interfaces like Get-NetAdapter', () => {
    const rows = toAdapterRows([
      wifi, loop,
      adapter({ ifIndex: 50, alias: 'Wi-Fi-WFP Native MAC Layer LightWeight Filter-0000', filterInterface: true }),
      adapter({ ifIndex: 10, alias: 'WAN Miniport', characteristics: 41 }),
      adapter({ ifIndex: 14, alias: 'Teredo', ifType: 131, characteristics: null })
    ])
    expect(rows.map(r => r.ifIndex)).toEqual([17])
    expect(rows[0]).toEqual({ Name: 'Беспроводная сеть', InterfaceDescription: 'MediaTek Wi-Fi 6E', Status: 'Up', LinkSpeed: '1 Gbps', ifIndex: 17 })
  })

  it('maps oper status and formats speed/MAC', () => {
    const rows = toAdapterRows([wifi, adapter({ ifIndex: 9, operStatus: 2, mediaConnectState: 2 }), adapter({ ifIndex: 21, operStatus: 6, linkSpeedBps: 0 })])
    expect(rows.map(r => r.Status)).toEqual(['Up', 'Disconnected', 'Not Present'])
    expect(formatLinkSpeed(866_700_000)).toBe('866.7 Mbps')
    expect(formatLinkSpeed(0)).toBe('0 bps')
    expect(formatMac([0, 0x15, 0x5d, 1, 0x44, 0])).toBe('00-15-5D-01-44-00')
  })
})

describe('IP configuration rows', () => {
  it('matches the Get-NetIPConfiguration projection (no link-local/temporary IPv6, IPv4 gateway only)', () => {
    const rows = toIpConfigRows([wifi, loop], [
      cfg(17, {
        unicast: [v4(17, '192.168.0.192'), v4(17, '169.254.1.2', 1), v6(17, 'fe80::1'), v6(17, '2001:db8::5'), v6(17, '2001:db8::bad', 5)],
        gateways: ['192.168.0.1', 'fe80::ffff'], dns: ['77.88.8.7', '77.88.8.3']
      }),
      cfg(1, { unicast: [v4(1, '127.0.0.1')] })
    ])
    expect(rows).toEqual([{
      InterfaceAlias: 'Беспроводная сеть', IPv4: '192.168.0.192,169.254.1.2', IPv6: '2001:db8::5',
      Gateway: '192.168.0.1', DNS: '77.88.8.7,77.88.8.3'
    }])
  })

  it('skips adapters without an IP binding and duplicate/invalid addresses', () => {
    const rows = toIpConfigRows([wifi, adapter({ ifIndex: 21, alias: 'NoIp' })], [cfg(17, { unicast: [v4(17, '10.0.0.2', 2), v4(17, '10.0.0.3', 0)] })])
    expect(rows).toEqual([{ InterfaceAlias: 'Беспроводная сеть', IPv4: '', IPv6: '', Gateway: '', DNS: '' }])
  })
})

describe('route rows', () => {
  const route = (over: Partial<RawRoute>): RawRoute => ({ family: 4, ifIndex: 17, prefix: '0.0.0.0', prefixLength: 0, nextHop: '192.168.0.1', metric: 0, protocol: 3, ...over })
  const prefixes = ['0.0.0.0/0', '::/0', '0.0.0.0/1', '128.0.0.0/1']

  it('filters to the wanted prefixes, names the interface and sorts by family/prefix/metric', () => {
    const rows = toRouteRows([wifi, adapter({ ifIndex: 18, alias: 'VPNTE-TUN' })], [
      route({ prefix: '128.0.0.0', prefixLength: 1, ifIndex: 18, nextHop: '192.168.250.254' }),
      route({ family: 6, prefix: '::', nextHop: '::', ifIndex: 17, protocol: 2 }),
      route({ prefix: '10.0.0.0', prefixLength: 8 }),
      route({ metric: 25 }),
      route({ prefix: '0.0.0.0', prefixLength: 0, metric: 5, ifIndex: 18, nextHop: '0.0.0.0' })
    ], prefixes)
    expect(rows.map(r => `${r.DestinationPrefix}@${r.InterfaceAlias}#${r.RouteMetric}`)).toEqual([
      '0.0.0.0/0@VPNTE-TUN#5', '0.0.0.0/0@Беспроводная сеть#25', '128.0.0.0/1@VPNTE-TUN#0', '::/0@Беспроводная сеть#0'
    ])
    expect(rows[3].Protocol).toBe('Local')
  })

  it('throws when a wanted route points at an interface that cannot be named', () => {
    expect(() => toRouteRows([wifi], [route({ ifIndex: 999 })], prefixes)).toThrow(/unknown interface/)
  })
})

describe('physical IPv4 sources', () => {
  it('mirrors the legacy leak-test filter', () => {
    const rows = toPhysicalIpv4Sources([
      wifi,
      adapter({ ifIndex: 18, alias: 'Ethernet 5', description: 'sing-tun Tunnel', mac: [] }),
      adapter({ ifIndex: 25, alias: 'Ethernet 2', description: 'VirtualBox Host-Only Ethernet Adapter' }),
      adapter({ ifIndex: 49, alias: 'vEthernet (Default Switch)', description: 'Hyper-V Virtual Ethernet Adapter' }),
      adapter({ ifIndex: 9, alias: 'Down', operStatus: 2 }),
      adapter({ ifIndex: 8, alias: 'NoMac', mac: [0, 0, 0, 0, 0, 0] }),
      loop
    ], [
      cfg(17, { unicast: [v4(17, '192.168.0.192'), v4(17, '169.254.9.9')] }),
      cfg(18, { unicast: [v4(18, '192.168.250.253')] }),
      cfg(25, { unicast: [v4(25, '192.168.77.1')] }),
      cfg(9, { unicast: [v4(9, '10.9.9.9')] }),
      cfg(8, { unicast: [v4(8, '10.8.8.8')] })
    ])
    expect(rows).toEqual([{ alias: 'Беспроводная сеть', ipv4: '192.168.0.192' }])
  })
})

describe('active tunnels', () => {
  it('detects VPN-like Up adapters and marks the VPNTE one by alias or address prefix', () => {
    const rows = toActiveTunnels([
      wifi,
      adapter({ ifIndex: 18, alias: 'VPNTE-TUN', description: 'sing-tun Tunnel', mac: [] }),
      adapter({ ifIndex: 30, alias: 'Corp', description: 'WireGuard Tunnel' }),
      adapter({ ifIndex: 31, alias: 'Down VPN', description: 'OpenVPN', operStatus: 2 })
    ], [
      cfg(18, { unicast: [v4(18, '192.168.250.253')] }), cfg(30, { unicast: [v4(30, '10.8.0.2')] })
    ], { vpnteAlias: 'VPNTE-TUN', vpnteIpv4Prefix: '192.168.250.' })
    expect(rows).toEqual([
      { name: 'VPNTE-TUN', description: 'sing-tun Tunnel', address: '192.168.250.253', isVpnte: true },
      { name: 'Corp', description: 'WireGuard Tunnel', address: '10.8.0.2', isVpnte: false }
    ])
  })
})

describe('address formatting', () => {
  it('compresses IPv6 per RFC 5952', () => {
    const b = (...g: number[]) => g.flatMap(x => [x >> 8, x & 255])
    expect(formatIpv6(b(0, 0, 0, 0, 0, 0, 0, 0))).toBe('::')
    expect(formatIpv6(b(0, 0, 0, 0, 0, 0, 0, 1))).toBe('::1')
    expect(formatIpv6(b(0xfe80, 0, 0, 0, 0xfe25, 0xd0db, 0x9892, 0x425c))).toBe('fe80::fe25:d0db:9892:425c')
    expect(formatIpv6(b(0x8000, 0, 0, 0, 0, 0, 0, 0))).toBe('8000::')
    expect(formatIpv6(b(1, 0, 2, 0, 3, 0, 4, 0))).toBe('1:0:2:0:3:0:4:0')
  })
})

describe('caller wiring', () => {
  it('serverPicker tries the native read before its PowerShell fallback', () => {
    const src = readFileSync(join(process.cwd(), 'src/main/serverPicker.ts'), 'utf8')
    expect(src.indexOf('nativePhysicalIpv4Sources()')).toBeGreaterThan(src.indexOf('const fast = getFastPhysicalIpv4Sources()'))
    expect(src.indexOf('nativePhysicalIpv4Sources()')).toBeLessThan(src.indexOf("'powershell.exe'"))
  })
})
