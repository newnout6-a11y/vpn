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

  it('searches ProgramData and all user profiles for lockdown manifest', () => {
    const script = scriptSource()

    expect(script).toContain("Join-Path $programData 'VPN-Tunnel-Enforcer\\latest-physical-adapter-lockdown.json'")
    expect(script).toContain('Get-ChildItem \'C:\\Users\\*\\AppData\\Roaming\\vpn-tunnel-enforcer\\latest-physical-adapter-lockdown.json\'')
    expect(script).toContain('foreach ($cp in $candidatePaths)')
  })

  it('preserves third-party DNS policies when no manifest and no VPNTE rules exist', () => {
    const script = scriptSource()

    expect(script).toContain('preserved DNS policy keys (no manifest and no orphaned VPNTE rules detected)')
    expect(script).toContain('elseif ($vpnteRules -gt 0)')
  })

  it('only removes orphaned local VPNTE proxy env vars and preserves corporate proxies', () => {
    const script = scriptSource()

    expect(script).toContain('Clean-VpnteProxyEnv')
    expect(script).toContain('^(https?|socks5h?)://(127\\.0\\.0\\.1|localhost)(:\\d+)?/?$')
    expect(script).toContain('localhost,127.0.0.1,::1')
    expect(script).toContain('preserving non-VPNTE $key=$val')
    expect(script).toContain('Registry::HKEY_USERS')
  })

  it('preserves adapter manifest if recovery finishes with warnings or errors', () => {
    const script = scriptSource()

    expect(script).toContain('if ($adapterManifest -and -not $hasWarnings -and -not $script:hasWarnings)')
    expect(script).toContain('Adapter lockdown manifest: preserved because recovery finished with warnings')
    expect(script).toContain('Remove-Item $cp -Force -ErrorAction Stop')
  })

  it('propagates failure exit codes from netsh and reg delete to warnings', () => {
    const script = scriptSource()

    expect(script).toContain('Transition adapters: failed to restore teredo state (exit code $LASTEXITCODE)')
    expect(script).toContain('$hasWarnings = $true')
    expect(script).toContain('$script:hasWarnings = $true')
  })
})
