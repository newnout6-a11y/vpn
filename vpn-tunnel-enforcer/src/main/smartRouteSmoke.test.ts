import { describe, it, expect, vi } from 'vitest'
import { writeFileSync, mkdtempSync, existsSync } from 'fs'
import { tmpdir } from 'os'
import { join } from 'path'
import { execFileSync } from 'child_process'

vi.mock('electron', () => ({
  app: { getPath: () => '/tmp/vpnte-test', getAppPath: () => '/tmp/vpnte-test/app', isPackaged: false }
}))
vi.mock('electron-store', () => ({
  default: class MockStore {
    private d: Record<string, any> = {}
    get(k?: string) { return k ? this.d[k] : { settings: {} } }
    set(k: string, v: any) { this.d[k] = v }
  }
}))
vi.mock('sudo-prompt', () => ({ default: { exec: vi.fn() }, exec: vi.fn() }))
vi.mock('./appLogger', () => ({ logEvent: vi.fn() }))
vi.mock('./notifications', () => ({ notify: vi.fn() }))
vi.mock('./admin', () => ({ execElevated: vi.fn(), isProcessElevated: vi.fn().mockResolvedValue(false) }))
vi.mock('./firewallKillSwitch', () => ({
  enableKillSwitch: vi.fn(), disableKillSwitch: vi.fn(), disableKillSwitchIfActive: vi.fn(),
  isKillSwitchActive: vi.fn().mockResolvedValue(false)
}))
vi.mock('./physicalAdapterLockdown', () => ({
  applyPhysicalAdapterLockdown: vi.fn(),
  getPhysicalAdapterDnsSources: vi.fn().mockResolvedValue([]),
  isPhysicalAdapterLockdownApplied: vi.fn().mockResolvedValue(false),
  repairOrphanedPhysicalAdapterDns: vi.fn(),
  rollbackPhysicalAdapterLockdownIfApplied: vi.fn()
}))
vi.mock('./systemNetwork', () => ({ rollbackTunNetworkBaselineIfApplied: vi.fn().mockResolvedValue({ success: true }) }))
vi.mock('./ipMonitor', () => ({ ipMonitor: { suspend: vi.fn(), resume: vi.fn(), getStatus: vi.fn() } }))
vi.mock('./leakSelfTest', () => ({ cancelLeakSelfTest: vi.fn() }))
vi.mock('./competingTunDetector', () => ({ startCompetingTunWatch: vi.fn(), stopCompetingTunWatch: vi.fn() }))
vi.mock('./dnsProfiles', () => ({ dnsProfiles: { getActiveDnsProfile: () => null } }))
vi.mock('./domainRouting', () => ({ generateDomainRouteRules: () => [] }))

import { generateSingboxConfig } from './tunController'

describe('smart-route runtime smoke', () => {
  it('passes bundled sing-box check with local rule-sets and direct DNS overrides', () => {
    const exe = join(process.cwd(), 'resources', 'sing-box.exe')
    expect(existsSync(exe)).toBe(true)
    const ruleSetDir = join(process.cwd(), 'resources')
    expect(existsSync(join(ruleSetDir, 'geoip-ru.srs'))).toBe(true)
    expect(existsSync(join(ruleSetDir, 'geosite-category-gov-ru.srs'))).toBe(true)

    const cfg = generateSingboxConfig(
      {
        outbound: {
          type: 'vless',
          server: 'ex.com',
          server_port: 443,
          uuid: 'u',
          tls: { enabled: true, server_name: 'ex.com' }
        }
      },
      'socks5',
      [],
      {
        smartRuSplit: true,
        smartRuMapsDirect: true,
        smartRuRuleSetDir: ruleSetDir,
        smartRuDirectDnsSources: [
          { ifIndex: 7, alias: 'Wi-Fi', ipv4DnsServers: ['77.88.8.7', '77.88.8.3'] }
        ],
        directProxyPortOverride: 23458,
        clashPortOverride: 23459
      }
    ) as any

    const dir = mkdtempSync(join(tmpdir(), 'vpnte-cfg-smoke-'))
    const f = join(dir, 'sing-box.json')
    writeFileSync(f, JSON.stringify(cfg, null, 2))
    const out = execFileSync(exe, ['check', '-c', f], { encoding: 'utf8' })
    expect(typeof out).toBe('string')
  })
})
