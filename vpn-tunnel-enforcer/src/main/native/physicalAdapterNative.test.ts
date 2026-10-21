// AT-03-005/006/010: native physical adapter read path keeps the PowerShell JSON contract and fails closed.
import { describe, expect, it, vi } from 'vitest'
import { buildPhysicalAdapterRows, createKoffiSource, readPhysicalAdaptersNative, serializeRows, snapshotFromSource } from './physicalAdapterNative'
import type { NativeAdapterInfo, NativeAdapterSource, NativeDefaultRoute } from './physicalAdapterNative'

const wifi: NativeAdapterInfo = {
  ifIndex: 17, interfaceGuid: '{999D65FE-A8C4-4DB3-9F7E-11EDD6482144}', alias: 'Беспроводная сеть',
  description: 'MediaTek Wi-Fi 6E MT7922 160MHz Wireless LAN Card', ipv6Enabled: true, ifType: 71,
  ipv4Dns: ['1.1.1.1'], permanentAddressHex: '5cc336f5a60a',
  filterInterface: false, hardwareInterface: true, ipv4Enabled: true, mediaType: 0, physicalMediumType: 9
}
function source(over: Partial<NativeAdapterSource> & { adapters?: NativeAdapterInfo[]; routes?: NativeDefaultRoute[] } = {}): NativeAdapterSource {
  return {
    listUpAdapters: () => over.adapters ?? [wifi],
    listDefaultRoutes: () => over.routes ?? [{ ifIndex: 17, family: 4, nextHop: '10.0.0.1' }],
    readNameServer: () => null,
    listNetworkProfiles: () => new Map([[17, ['Office']]]),
    ...over
  }
}
const KEYS = ['ifIndex', 'interfaceGuid', 'alias', 'description', 'ipv6Enabled', 'ipv4Dns', 'gateways', 'networkProfiles', 'ipv4DnsSource', 'isCellularOrTethering']

describe('native physical adapter snapshot: PowerShell JSON contract', () => {
  it('emits a bare object with the exact field order for a single adapter', () => {
    const text = snapshotFromSource(source())
    expect(text.startsWith('{')).toBe(true)
    expect(Object.keys(JSON.parse(text))).toEqual(KEYS)
    expect(JSON.parse(text)).toEqual({
      ifIndex: 17, interfaceGuid: '{999D65FE-A8C4-4DB3-9F7E-11EDD6482144}', alias: 'Беспроводная сеть',
      description: 'MediaTek Wi-Fi 6E MT7922 160MHz Wireless LAN Card', ipv6Enabled: true, ipv4Dns: ['1.1.1.1'],
      gateways: ['10.0.0.1'], networkProfiles: ['Office'], ipv4DnsSource: 'dhcp', isCellularOrTethering: false
    })
  })
  it('emits an array for several adapters', () => {
    const eth = { ...wifi, ifIndex: 5, alias: 'Ethernet', description: 'Intel I225-V', interfaceGuid: '{BBBBBBBB-0000-0000-0000-000000000005}' }
    const text = snapshotFromSource(source({ adapters: [wifi, eth], routes: [{ ifIndex: 17, family: 4, nextHop: '10.0.0.1' }, { ifIndex: 5, family: 4, nextHop: '192.168.1.1' }] }))
    const parsed = JSON.parse(text)
    expect(Array.isArray(parsed)).toBe(true)
    expect(parsed.map((r: any) => r.ifIndex)).toEqual([17, 5])
    expect(parsed[1].networkProfiles).toEqual([])
  })
  it('classifies static DNS from the registry NameServer value', () => {
    expect(buildPhysicalAdapterRows(source({ readNameServer: () => '8.8.8.8' }))[0].ipv4DnsSource).toBe('static')
    expect(buildPhysicalAdapterRows(source({ readNameServer: () => '  ' }))[0].ipv4DnsSource).toBe('dhcp')
  })
  it('applies the PowerShell selection filters', () => {
    const adapters = [
      { ...wifi, ifIndex: 1, description: 'VirtualBox Host-Only Ethernet Adapter' },
      { ...wifi, ifIndex: 2, description: 'Hyper-V Virtual Ethernet Adapter', hardwareInterface: false },
      { ...wifi, ifIndex: 3, alias: 'vpnte-tun' },
      { ...wifi, ifIndex: 4, permanentAddressHex: '000000000000' },
      { ...wifi, ifIndex: 6, permanentAddressHex: '' },
      { ...wifi, ifIndex: 7, filterInterface: true },
      { ...wifi, ifIndex: 8 }
    ]
    expect(buildPhysicalAdapterRows(source({ adapters })).map(r => r.ifIndex)).toEqual([8])
  })
  it('keeps the IP-bound hardware Hyper-V uplink and excludes its virtual switch (AT-03-005/006)', () => {
    const uplink = { ...wifi, ifIndex: 18, description: 'Microsoft Hyper-V Network Adapter' }
    const internal = { ...uplink, ifIndex: 19, hardwareInterface: false }
    expect(buildPhysicalAdapterRows(source({ adapters: [internal, uplink] })).map(r => r.ifIndex)).toEqual([18])
  })
  it('excludes an unbound VF but retains bound adapters without an address, DNS or default route (AT-03-006)', () => {
    const bound = { ...wifi, ipv4Dns: [], ipv6Enabled: false }
    const vf = { ...bound, ifIndex: 20, description: 'SR-IOV VF', ipv4Enabled: false }
    expect(buildPhysicalAdapterRows(source({ adapters: [vf, bound], routes: [] })).map(r => r.ifIndex)).toEqual([17])
    expect(buildPhysicalAdapterRows(source({ adapters: [{ ...bound, ipv4Enabled: false, ipv6Enabled: true }], routes: [] }))).toHaveLength(1)
    expect(() => snapshotFromSource(source({ adapters: [vf] }))).toThrow(/refusing empty/)
  })
  it('flags tethering by device name, hotspot subnet, WWAN media and IPv6-only default route', () => {
    const run = (a: Partial<NativeAdapterInfo>, routes: NativeDefaultRoute[]) =>
      buildPhysicalAdapterRows(source({ adapters: [{ ...wifi, ...a }], routes }))[0].isCellularOrTethering
    const v4 = [{ ifIndex: 17, family: 4 as const, nextHop: '10.0.0.1' }]
    expect(run({}, v4)).toBe(false)
    expect(run({ description: 'Remote NDIS based Internet Sharing Device' }, v4)).toBe(true)
    expect(run({ alias: 'Cellular 2' }, v4)).toBe(true)
    expect(run({}, [{ ifIndex: 17, family: 4, nextHop: '172.20.10.1' }])).toBe(true)
    expect(run({ ipv4Dns: ['192.168.43.1'] }, v4)).toBe(true)
    expect(run({ ifType: 243 }, v4)).toBe(true)
    expect(run({}, [{ ifIndex: 17, family: 6, nextHop: '::' }])).toBe(true)
    expect(run({}, [...v4, { ifIndex: 17, family: 6, nextHop: '::' }])).toBe(false)
    // On-link IPv4 default (0.0.0.0) is not a gateway but still suppresses the IPv6-only rule.
    expect(run({}, [{ ifIndex: 17, family: 4, nextHop: '0.0.0.0' }, { ifIndex: 17, family: 6, nextHop: '::' }])).toBe(false)
    // .NET \b is Unicode aware: a Cyrillic neighbour is not a word boundary.
    expect(run({ alias: 'сетьlte' }, v4)).toBe(false)
  })
  it('excludes on-link zero next hop from gateways', () => {
    const rows = buildPhysicalAdapterRows(source({ routes: [{ ifIndex: 17, family: 4, nextHop: '0.0.0.0' }, { ifIndex: 17, family: 4, nextHop: '10.0.0.1' }] }))
    expect(rows[0].gateways).toEqual(['10.0.0.1'])
  })
})

describe('native physical adapter snapshot: fail closed', () => {
  it('refuses an empty result instead of reporting "no adapters"', () => {
    expect(() => serializeRows([])).toThrow(/refusing empty/)
    expect(() => snapshotFromSource(source({ adapters: [] }))).toThrow()
    expect(() => snapshotFromSource(source({ adapters: [{ ...wifi, description: 'VMware Virtual Ethernet' }] }))).toThrow()
  })
  it('propagates source failures and unreadable profiles', () => {
    expect(() => snapshotFromSource(source({ listUpAdapters: () => { throw new Error('GetAdaptersAddresses rc=87') } }))).toThrow(/rc=87/)
    expect(() => snapshotFromSource(source({ listDefaultRoutes: () => { throw new Error('GetIpForwardTable2 rc=5') } }))).toThrow(/rc=5/)
    expect(() => snapshotFromSource(source({ readNameServer: () => { throw new Error('RegGetValueW rc=5') } }))).toThrow(/rc=5/)
    expect(() => snapshotFromSource(source({ listNetworkProfiles: () => { throw new Error('network profiles: elevated helper is not running') } }))).toThrow(/helper/)
    expect(JSON.parse(snapshotFromSource(source({ listNetworkProfiles: () => new Map() }))).networkProfiles).toEqual([])
  })
  it('skips NCF_HIDDEN adapters like PowerShell Hidden, keeps ones without a class-key entry', () => {
    const hidden = { ...wifi, ifIndex: 30, characteristics: 0x8 | 0x1 }
    const visible = { ...wifi, ifIndex: 31, characteristics: 0x1 }
    const unknown = { ...wifi, ifIndex: 32, characteristics: null }
    expect(buildPhysicalAdapterRows(source({ adapters: [hidden, visible, unknown] })).map(r => r.ifIndex)).toEqual([31, 32])
  })

  it('refuses a non-Windows platform and an empty adapter set', async () => {
    vi.resetModules()
    if (process.platform !== 'win32') expect(() => createKoffiSource(new Map())).toThrow(/win32/)
    await expect(readPhysicalAdaptersNative(source({ adapters: [] }))).rejects.toThrow()
  })
})

describe('lockdown hook falls back to PowerShell', () => {
  it('uses the PowerShell worker when native throws, and native output when it succeeds', async () => {
    const native = vi.fn()
    vi.resetModules()
    vi.doMock('electron', () => ({ app: { getPath: () => 'C:\\fixture' } }))
    vi.doMock('../appLogger', () => ({ logEvent: vi.fn() }))
    vi.doMock('../admin', () => ({ execElevated: vi.fn() }))
    vi.doMock('../runtimeDirSecurity', () => ({ ensureElevatedRuntimeDirHardened: vi.fn() }))
    vi.doMock('../recoveryManifest', () => ({ recoveryManifestPath: () => 'C:\\fixture\\m.json', readRecoveryManifest: vi.fn(async () => null), writeRecoveryManifest: vi.fn(), removeRecoveryManifest: vi.fn() }))
    vi.doMock('../elevatedPsHelper', () => ({ isElevatedPsHelperRunning: () => true, execElevatedPs: vi.fn() }))
    const psRow = JSON.stringify({ ...JSON.parse(snapshotFromSource(source())), alias: 'FromPS' })
    const adapter = vi.fn(async () => psRow)
    vi.doMock('../recoveryPsWorker', () => ({ executeRecoveryOperation: vi.fn(), executeAdapterInspection: adapter, RecoveryWorkerError: class extends Error { constructor(public code: string, m: string) { super(m) } } }))
    vi.doMock('./physicalAdapterNative', () => ({ readPhysicalAdaptersNative: native }))
    const prev = process.env.VPNTE_DISABLE_NATIVE_NET
    delete process.env.VPNTE_DISABLE_NATIVE_NET
    try {
      native.mockRejectedValueOnce(new Error('boom'))
      const lock = await import('../physicalAdapterLockdown')
      lock.clearPhysicalAdaptersSnapshotCache()
      // Native fails: the snapshot the hook publishes comes from the PowerShell worker.
      expect((await lock.snapshotPhysicalAdapters()).map(a => a.alias)).toEqual(['FromPS'])
      native.mockResolvedValueOnce(snapshotFromSource(source()))
      adapter.mockClear()
      lock.clearPhysicalAdaptersSnapshotCache()
      // Native succeeds: its rows are published and the worker is not consulted.
      expect((await lock.snapshotPhysicalAdapters()).map(a => a.alias)).toEqual([wifi.alias])
    } finally {
      if (prev === undefined) delete process.env.VPNTE_DISABLE_NATIVE_NET; else process.env.VPNTE_DISABLE_NATIVE_NET = prev
      vi.doUnmock('./physicalAdapterNative')
    }
  })
})
