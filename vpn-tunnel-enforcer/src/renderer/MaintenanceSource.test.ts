import { readFileSync } from 'fs'
import { join } from 'path'
import { describe, expect, it } from 'vitest'

const maintenanceSource = () => readFileSync(join(process.cwd(), 'src', 'renderer', 'pages', 'Maintenance.tsx'), 'utf8')

describe('Maintenance source regressions', () => {
  it('keeps legacy Store and privacy repairs out of the VPN repair screen', () => {
    const source = maintenanceSource()

    expect(source).not.toContain('runStoreRepair')
    expect(source).not.toContain('runStoreDiagnostics')
    expect(source).not.toContain('getLocationPrivacy')
    expect(source).not.toContain('applyLocationPrivacy')
    expect(source).not.toContain('rollbackLocationPrivacy')
  })

  it('uses targeted VPNTE firewall repair before the emergency full reset', () => {
    const source = maintenanceSource()

    expect(source).toContain('firewallRepairVpnteRules')
    expect(source).toContain('firewallRepairHealth')
    expect(source).toContain('firewallNuclearReset')
    expect(source.indexOf('firewallRepairVpnteRules')).toBeLessThan(source.indexOf('firewallNuclearReset'))
  })

  it('does not let hidden Store diagnostics drive the visible VPN repair summary', () => {
    const source = maintenanceSource()

    expect(source).toContain('function maintenanceSystemSummary')
    expect(source).toContain("new Set(['App', 'TUN', 'Proxy', 'Network', 'Internet', 'Routing'])")
    expect(source).not.toContain("systemDiagnostics?.summary")
  })

  it('passes an explicit token for the emergency full firewall reset', () => {
    const source = maintenanceSource()

    expect(source).toContain("firewallNuclearReset('RESET_WINDOWS_FIREWALL_CONFIRMED')")
  })

  it('keeps repair health and step results in the global store across tab switches', () => {
    const source = maintenanceSource()

    expect(source).not.toContain('useState')
    expect(source).toContain('maintenanceFirewallHealth')
    expect(source).toContain('setMaintenanceFirewallHealth')
    expect(source).toContain('maintenanceRepairSteps')
    expect(source).toContain('setMaintenanceRepairSteps')
  })
})
