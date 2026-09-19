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
    expect(s).toContain('programData: join(programDataDir, MANIFEST_BASENAME)')
    expect(s).toContain('userData: join(app.getPath(\'userData\'), MANIFEST_BASENAME)')
    expect(s).toContain('pdTarget = programDataManifestPath()')
  })
})
