// AT-03-006: actual snapshot -> pending ownership -> mutation script path.
import { beforeEach, describe, expect, it, vi } from 'vitest'
const fixture = vi.hoisted(() => ({ profile: 'Galaxy S24 Ultra F4E5 2', v6: true, ps: vi.fn(), persist: vi.fn() }))
vi.mock('electron', () => ({ app: { getPath: () => 'C:\\fixture' } }))
vi.mock('./admin', () => ({ execElevated: vi.fn() }))
vi.mock('./appLogger', () => ({ logEvent: vi.fn() }))
vi.mock('./runtimeDirSecurity', () => ({ ensureElevatedRuntimeDirHardened: vi.fn() }))
vi.mock('fs/promises', () => {
  const api = { writeFile: vi.fn(async () => {}), readFile: vi.fn(), unlink: vi.fn(), rename: vi.fn(), mkdir: vi.fn() }
  return { ...api, default: api }
})
vi.mock('./recoveryManifest', () => ({ recoveryManifestPath: () => 'C:\\fixture\\manifest.json', readRecoveryManifest: vi.fn(async () => null), writeRecoveryManifest: fixture.persist, removeRecoveryManifest: vi.fn() }))
vi.mock('./recoveryPsWorker', () => ({
  RecoveryWorkerError: class extends Error {},
  executeRecoveryOperation: vi.fn(async ({op}: {op: string}) => op === 'inspect-physical-adapters' ? JSON.stringify({
    ifIndex: 17, interfaceGuid: '11111111-1111-1111-1111-111111111111', alias: 'Беспроводная сеть',
    description: 'MediaTek Wi-Fi', ipv6Enabled: fixture.v6, ipv4Dns: ['77.88.8.7'], ipv4DnsSource: 'static',
    gateways: ['10.253.112.13'], networkProfiles: [fixture.profile], isCellularOrTethering: false
  }) : JSON.stringify(['smartNameResolution', 'parallelAandAAAA'].map(tag => ({ tag, exists: false, type: null, data: null }))))
}))
vi.mock('./elevatedPsHelper', () => ({ isElevatedPsHelperRunning: () => true, execElevatedPs: fixture.ps }))

beforeEach(() => {
  vi.resetModules(); vi.clearAllMocks()
  fixture.ps.mockImplementation(async (script: string) => {
    if (script.includes('Get-NetConnectionProfile')) return { stdout: JSON.stringify({
      ifIndex: 17, interfaceGuid: '11111111-1111-1111-1111-111111111111', alias: 'Беспроводная сеть',
      description: 'MediaTek Wi-Fi', ipv6Enabled: fixture.v6, ipv4Dns: ['77.88.8.7'], ipv4DnsSource: 'static',
      gateways: ['10.253.112.13'], networkProfiles: [fixture.profile], isCellularOrTethering: false
    }) }
    if (script.includes('netsh interface teredo show state')) return { stdout: '{}' }
    return { stdout: (fixture.profile.startsWith('Galaxy') ? 'A0_ipv6:skip\nA0_dns:skip' : 'A0_ipv6:off\nA0_dns:skip') + '\nDNS_SMNR:off\nDNS_PARALLEL:off' }
  })
})
describe('hotspot snapshot integration', () => {
  it.each([true, false])('keeps existing IPv6=%s and never disables it for a modern Galaxy hotspot', async v6 => {
    fixture.profile = 'Galaxy S24 Ultra F4E5 2'; fixture.v6 = v6
    const { applyPhysicalAdapterLockdown } = await import('./physicalAdapterLockdown')
    expect(await applyPhysicalAdapterLockdown('192.168.250.254', { forceDns: false })).toMatchObject({ applied: true, warnings: [] })
    const pending = fixture.persist.mock.calls[0][1]
    expect(pending.adapters[0]).toMatchObject({ ipv6Enabled: v6, isCellularOrTethering: true, forcedIpv6Off: false, forcedDnsTo: null })
    const mutation = fixture.ps.mock.calls.map(call => call[0]).find(script => script.includes('$ownedAdapter ='))!
    expect(mutation).toContain('A0_ipv6:skip')
    expect(mutation).not.toContain('Disable-NetAdapterBinding')
    expect(JSON.stringify(fixture.persist.mock.calls)).not.toContain('Galaxy')
  })
  it('continues ordinary Wi-Fi lockdown for the same 10/8 gateway', async () => {
    fixture.profile = 'Office'; fixture.v6 = true
    const { applyPhysicalAdapterLockdown } = await import('./physicalAdapterLockdown')
    await applyPhysicalAdapterLockdown('192.168.250.254', { forceDns: false })
    expect(fixture.persist.mock.calls[0][1].adapters[0]).toMatchObject({ isCellularOrTethering: false, forcedIpv6Off: true })
    const mutation = fixture.ps.mock.calls.map(call => call[0]).find(script => script.includes('$ownedAdapter ='))!
    expect(mutation).toContain('Disable-NetAdapterBinding')
  })
})
