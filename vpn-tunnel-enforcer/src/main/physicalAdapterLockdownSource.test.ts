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
})
