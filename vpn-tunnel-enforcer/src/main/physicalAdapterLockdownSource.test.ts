import { readFileSync } from 'fs'
import { join } from 'path'
import { describe, expect, it } from 'vitest'

const source = () => readFileSync(join(process.cwd(), 'src', 'main', 'physicalAdapterLockdown.ts'), 'utf8')

describe('physicalAdapterLockdown source regressions', () => {
  it('snapshots and restores pre-existing DNS registry policy values', () => {
    const s = source()

    expect(s).toContain('interface DnsRegistryPolicySnapshot')
    expect(s).toContain('snapshotDnsRegistryPolicy()')
    expect(s).toContain('dnsRegistryPolicy')
    expect(s).toContain('registryRestoreLine')
    expect(s).toContain("registryRestoreLine('DNS_SMNR'")
    expect(s).toContain("registryRestoreLine('DNS_PARALLEL'")
    expect(s).toContain('DNS_SMNR:restore|DNS_SMNR:delete')
    expect(s).toContain('DNS_PARALLEL:restore|DNS_PARALLEL:delete')
  })

  it('does not treat stale forceDns or resolver manifests as idempotent', () => {
    const s = source()
    const existing = s.indexOf('let existing = await readManifest()')
    const mismatch = s.indexOf('existing.tunDnsIpv4 !== tunDnsIpv4', existing)
    const rollback = s.indexOf("rollbackPhysicalAdapterLockdownIfApplied('lockdown options changed before reapply')", mismatch)
    const idempotent = s.indexOf('lockdown already applied', rollback)

    expect(existing).toBeGreaterThan(0)
    expect(mismatch).toBeGreaterThan(existing)
    expect(rollback).toBeGreaterThan(mismatch)
    expect(idempotent).toBeGreaterThan(rollback)
  })

  it('surfaces DNS registry hardening script errors as warnings', () => {
    const s = source()

    expect(s).toContain('/DNS_.*_err/')
    expect(s).toContain('warnings.push(line)')
    expect(s).toContain('partial DNS registry policy rollback')
  })

  it('detects cellular/RNDIS/tethering adapters and avoids disabling ms_tcpip6', async () => {
    const s = source()

    expect(s).toContain('export function isCellularOrTetheringAdapter')
    expect(s).toContain('isCellularOrTethering')
    expect(s).toContain('forcedIpv6Off: a.isCellularOrTethering ? false : a.ipv6Enabled')
    expect(s).toContain('a.isCellularOrTethering')
    expect(s).toContain('Write-Output "A${i}_ipv6:skip"')

    const { isCellularOrTetheringAdapter, isTetheringSubnetIp } = await import('./physicalAdapterLockdown')
    expect(isCellularOrTetheringAdapter('Cellular')).toBe(true)
    expect(isCellularOrTetheringAdapter('Ethernet 2', 'Remote NDIS based Internet Sharing Device')).toBe(true)
    expect(isCellularOrTetheringAdapter('Ethernet 3', 'Apple Mobile Device Ethernet')).toBe(true)
    expect(isCellularOrTetheringAdapter('Wi-Fi', 'Intel(R) Wi-Fi 6 AX200 160MHz')).toBe(false)
    expect(isCellularOrTetheringAdapter('Ethernet', 'Realtek Gaming GbE Family Controller')).toBe(false)

    // Mobile hotspot detection by DNS / Gateway IP
    expect(isCellularOrTetheringAdapter('Wi-Fi', 'Intel(R) Wi-Fi 6 AX200 160MHz', ['192.168.43.1'])).toBe(true)
    expect(isCellularOrTetheringAdapter('Wi-Fi', 'Intel(R) Wi-Fi 6 AX200 160MHz', ['172.20.10.1'])).toBe(true)
    expect(isCellularOrTetheringAdapter('Wi-Fi', 'Intel(R) Wi-Fi 6 AX200 160MHz', [], ['192.168.137.1'])).toBe(true)
    expect(isTetheringSubnetIp('192.168.43.1')).toBe(true)
    expect(isTetheringSubnetIp('172.20.10.1')).toBe(true)
    expect(isTetheringSubnetIp('192.168.1.1')).toBe(false)
  })

  it('persists lockdown manifest to both ProgramData and userData for boot recovery access', () => {
    const s = source()

    expect(s).toContain('export function getLockdownManifestPaths')
    expect(s).toContain('const programDataDir = recoveryManifestPath(MANIFEST_BASENAME)')
    expect(s).toContain('userData: join(app.getPath(\'userData\'), MANIFEST_BASENAME)')
    expect(s).toContain('writeRecoveryManifest(MANIFEST_BASENAME')
    expect(s).toContain('readRecoveryManifest(MANIFEST_BASENAME')
    expect(s).toContain('[string]$_.InterfaceGuid -eq')
  })
  it('recognizes modern phone Wi-Fi profiles without treating all private networks as tethering (AT-03-006)', async () => {
    const { isCellularOrTetheringAdapter, isTetheringSubnetIp } = await import('./physicalAdapterLockdown')
    for (const name of ['Galaxy S24 Ultra F4E5 2', 'iPhone (Владимир)', 'Pixel 9', 'Redmi Note 13', 'Mobile Hotspot']) {
      expect(isCellularOrTetheringAdapter('Беспроводная сеть', 'MediaTek Wi-Fi', ['77.88.8.7'], ['10.253.112.13'], [name])).toBe(true)
    }
    expect(isCellularOrTetheringAdapter('Wi-Fi', 'MediaTek', [], ['10.253.112.13'], ['Office'])).toBe(false)
    expect(isCellularOrTetheringAdapter('Wi-Fi', 'MediaTek', [], ['192.168.1.1'], ['Home'])).toBe(false)
    expect(isTetheringSubnetIp('192.168.43.999')).toBe(false)
    expect(isTetheringSubnetIp('192.168.43.evil')).toBe(false)
    expect(source()).toContain('Get-NetConnectionProfile -InterfaceIndex $a.ifIndex')
    expect(source()).toContain('isCellularOrTetheringAdapter(alias, description, dnsServers, gateways)')
  })
  it('rejects injected/ambiguous adapter, transition and registry snapshots (AT-03-012)', async () => {
    const { validateLockdownManifest } = await import('./physicalAdapterLockdown')
    const fixture = {
      schemaVersion: 1, owner: 'VPNTE', appliedAt: Date.now(), tunDnsIpv4: '192.168.250.254',
      adapters: [{ ifIndex: 1, interfaceGuid: '22222222-2222-2222-2222-222222222222', alias: 'Ethernet', ipv6Enabled: true, ipv4DnsServers: ['1.1.1.1'], ipv4DnsSource: 'static', forcedDnsTo: ['192.168.250.254'], forcedIpv6Off: true }],
      transitionAdapters: { teredoType: 'client', sixToFourState: null, isatapState: null },
      dnsRegistryPolicy: { smartNameResolution: { exists: false }, parallelAandAAAA: { exists: true, type: 'REG_DWORD', data: '0x0' } }
    }
    expect(validateLockdownManifest(fixture).adapters).toHaveLength(1)
    expect(() => validateLockdownManifest({ ...fixture, adapters: [{ ...fixture.adapters[0], interfaceGuid: undefined }] })).toThrow()
    expect(() => validateLockdownManifest({ ...fixture, transitionAdapters: { ...fixture.transitionAdapters, teredoType: "client; Invoke-Expression evil" } })).toThrow()
    expect(() => validateLockdownManifest({ ...fixture, dnsRegistryPolicy: { ...fixture.dnsRegistryPolicy, smartNameResolution: { exists: true, type: 'REG_DWORD', data: "0 & evil" } } })).toThrow()
    expect(() => validateLockdownManifest({ ...fixture, dnsRegistryPolicy: undefined })).toThrow()
  })

})
