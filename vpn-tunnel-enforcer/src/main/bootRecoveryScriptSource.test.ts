import { readFileSync } from 'fs'
import { join } from 'path'
import { describe, expect, it } from 'vitest'

const scriptSource = () => readFileSync(join(process.cwd(), 'resources', 'vpnte-recover.ps1'), 'utf8')

describe('boot recovery script source regressions', () => {
  it('uses the adapter lockdown manifest before restoring adapter state', () => {
    const script = scriptSource()

    expect(script).toContain('latest-physical-adapter-lockdown.json')
    expect(script).toContain('Get-ManifestAdapter')
    expect(script).toContain('$manifestAdapter.forcedDnsTo')
    expect(script).toContain('$manifestAdapter.forcedIpv6Off -eq $true')
    expect(script).not.toContain('$ipv6Binding.Enabled -eq $false')
    expect(script).not.toContain('netsh interface teredo set state type=default')
  })

  it('restores DNS registry policy from manifest when available', () => {
    const script = scriptSource()

    expect(script).toContain('Restore-RegValue')
    expect(script).toContain('$adapterManifest.dnsRegistryPolicy.smartNameResolution')
    expect(script).toContain('$adapterManifest.dnsRegistryPolicy.parallelAandAAAA')
  })
})
