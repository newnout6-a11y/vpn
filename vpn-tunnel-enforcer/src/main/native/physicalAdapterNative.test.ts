// AT-03-005/006/010: native physical adapter read path keeps the PowerShell JSON contract and fails closed.
import { describe, expect, it, vi } from 'vitest'
import { execFileSync } from 'child_process'
import { buildPhysicalAdapterRows, createKoffiSource, readPhysicalAdaptersNative, serializeRows, snapshotFromSource } from './physicalAdapterNative'
import type { NativeAdapterInfo, NativeAdapterSource, NativeDefaultRoute } from './physicalAdapterNative'
import { PHYSICAL_ADAPTER_SNAPSHOT_SCRIPT } from '../physicalAdapterSnapshot'

const wifi: NativeAdapterInfo = {
  ifIndex: 17, interfaceGuid: '{999D65FE-A8C4-4DB3-9F7E-11EDD6482144}', alias: 'Беспроводная сеть',
  description: 'MediaTek Wi-Fi 6E MT7922 160MHz Wireless LAN Card', ipv6Enabled: true, ifType: 71,
  ipv4Dns: ['1.1.1.1'], permanentAddressHex: '5cc336f5a60a',
  filterInterface: false, mediaType: 0, physicalMediumType: 9
}
function source(over: Partial<NativeAdapterSource> & { adapters?: NativeAdapterInfo[]; routes?: NativeDefaultRoute[] } = {}): NativeAdapterSource {
  return {
    listUpAdapters: () => over.adapters ?? [wifi],
    listDefaultRoutes: () => over.routes ?? [{ ifIndex: 17, family: 4, nextHop: '10.0.0.1' }],
    readNameServer: () => null,
    listNetworkProfiles: () => new Map([['{999D65FE-A8C4-4DB3-9F7E-11EDD6482144}', ['Office']]]),
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
      { ...wifi, ifIndex: 2, description: 'Hyper-V Virtual Ethernet Adapter' },
      { ...wifi, ifIndex: 3, alias: 'vpnte-tun' },
      { ...wifi, ifIndex: 4, permanentAddressHex: '000000000000' },
      { ...wifi, ifIndex: 6, permanentAddressHex: '' },
      { ...wifi, ifIndex: 7, filterInterface: true },
      { ...wifi, ifIndex: 8 }
    ]
    expect(buildPhysicalAdapterRows(source({ adapters })).map(r => r.ifIndex)).toEqual([8])
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
    expect(() => snapshotFromSource(source({ listNetworkProfiles: () => { throw new Error('CoCreateInstance hr=0x80070005') } }))).toThrow(/hr=/)
    expect(JSON.parse(snapshotFromSource(source({ listNetworkProfiles: () => new Map() }))).networkProfiles).toEqual([])
  })
  it('throws when koffi cannot load', () => {
    vi.resetModules()
    if (process.platform !== 'win32') expect(() => createKoffiSource()).toThrow(/win32/)
    expect(() => readPhysicalAdaptersNative(source({ adapters: [] }))).toThrow()
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
    const prev = process.env.VPNTE_NATIVE_ADAPTERS
    process.env.VPNTE_NATIVE_ADAPTERS = '1'
    try {
      native.mockImplementationOnce(() => { throw new Error('boom') })
      const lock = await import('../physicalAdapterLockdown') as any
      const snap = lock.__snapshotForTest ?? null
      // The hook is private; drive it through the exported warm-up which snapshots adapters.
      lock.clearPhysicalAdaptersSnapshotCache()
      await lock.warmPhysicalAdaptersSnapshot()
      expect(native).toHaveBeenCalledTimes(1)
      expect(adapter).toHaveBeenCalledWith('inspect-physical-adapters', expect.any(Number))
      void snap
      native.mockReturnValueOnce(snapshotFromSource(source()))
      adapter.mockClear()
      lock.clearPhysicalAdaptersSnapshotCache()
      await lock.warmPhysicalAdaptersSnapshot()
      expect(adapter).not.toHaveBeenCalled()
    } finally {
      if (prev === undefined) delete process.env.VPNTE_NATIVE_ADAPTERS; else process.env.VPNTE_NATIVE_ADAPTERS = prev
      vi.doUnmock('./physicalAdapterNative')
    }
  })
})

function psSnapshot(): any[] {
  const ps = `[Console]::OutputEncoding=[Text.Encoding]::UTF8\n${PHYSICAL_ADAPTER_SNAPSHOT_SCRIPT}`
  const out = execFileSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-EncodedCommand', Buffer.from(ps, 'utf16le').toString('base64')], { encoding: 'utf8', timeout: 60000 }).trim()
  if (!out) return []
  const parsed = JSON.parse(out)
  return Array.isArray(parsed) ? parsed : [parsed]
}

describe.skipIf(process.platform !== 'win32' || process.env.VPNTE_SKIP_REAL_ADAPTER_TEST === '1')('native vs PowerShell on this machine', () => {
  it('returns the same adapters and fields as the PowerShell snapshot', () => {
    const native = JSON.parse(readPhysicalAdaptersNative())
    const nativeRows: any[] = Array.isArray(native) ? native : [native]
    for (const r of nativeRows) expect(Object.keys(r)).toEqual(KEYS)
    const ps = psSnapshot()
    const byIdx = (rows: any[]) => Object.fromEntries(rows.map(r => [r.ifIndex, r]))
    const norm = (r: any) => ({ ...r, ipv4Dns: [...r.ipv4Dns].sort(), gateways: [...r.gateways].sort() })
    expect(Object.keys(byIdx(nativeRows)).sort()).toEqual(Object.keys(byIdx(ps)).sort())
    for (const row of ps) expect(norm(byIdx(nativeRows)[row.ifIndex])).toEqual(norm(row))
  }, 90000)
})
