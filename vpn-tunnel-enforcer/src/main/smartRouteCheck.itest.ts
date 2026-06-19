/**
 * Integration check: the REAL generateSingboxConfig output (smart-route ON)
 * must pass the bundled `sing-box.exe check`. Reuses the same module mocks as
 * tunControllerConfig.test.ts so the generator loads under vitest, then writes
 * the produced config and shells out to sing-box.
 *
 * Named *.itest.ts and skipped unless RUN_SINGBOX_CHECK=1, because it depends
 * on resources/sing-box.exe being present (CI without it would fail). Run
 * locally with: RUN_SINGBOX_CHECK=1 npx vitest --run smartRouteCheck
 */

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
  applyPhysicalAdapterLockdown: vi.fn(), getPhysicalAdapterDnsSources: vi.fn().mockResolvedValue([]), isPhysicalAdapterLockdownApplied: vi.fn().mockResolvedValue(false),
  repairOrphanedPhysicalAdapterDns: vi.fn(), rollbackPhysicalAdapterLockdownIfApplied: vi.fn()
}))
vi.mock('./systemNetwork', () => ({ rollbackTunNetworkBaselineIfApplied: vi.fn().mockResolvedValue({ success: true }) }))
vi.mock('./ipMonitor', () => ({ ipMonitor: { suspend: vi.fn(), resume: vi.fn(), getStatus: vi.fn() } }))
vi.mock('./leakSelfTest', () => ({ cancelLeakSelfTest: vi.fn() }))
vi.mock('./competingTunDetector', () => ({ startCompetingTunWatch: vi.fn(), stopCompetingTunWatch: vi.fn() }))
vi.mock('./dnsProfiles', () => ({ dnsProfiles: { getActiveDnsProfile: () => null } }))
vi.mock('./domainRouting', () => ({ generateDomainRouteRules: () => [] }))

import { generateSingboxConfig } from './tunController'

const RUN = process.env.RUN_SINGBOX_CHECK === '1'

describe.skipIf(!RUN)('smart-route config passes sing-box check', () => {
  it('validates the real generated config', () => {
    const cfg = generateSingboxConfig(
      { outbound: { type: 'vless', server: 'ex.com', server_port: 443, uuid: 'u', tls: { enabled: true, server_name: 'ex.com' } } },
      'socks5',
      [],
      { smartRuSplit: true, smartRuMapsDirect: true, directProxyPortOverride: 23456, clashPortOverride: 23457 }
    )
    const dir = mkdtempSync(join(tmpdir(), 'vpnte-cfg-'))
    const f = join(dir, 'sing-box.json')
    writeFileSync(f, JSON.stringify(cfg, null, 2))
    const exe = join(process.cwd(), 'resources', 'sing-box.exe')
    expect(existsSync(exe)).toBe(true)
    // Throws (failing the test) if sing-box rejects the config.
    const out = execFileSync(exe, ['check', '-c', f], { encoding: 'utf8' })
    expect(typeof out).toBe('string')
  })

  it('validates the LOCAL rule-set config against the bundled .srs files', () => {
    // Point ruleSetDir at the resources folder where the real .srs live, so
    // sing-box `check` actually parses the bundled binary rule-sets (catches a
    // corrupt/incompatible .srs format at build time, not at the user's first
    // connect). This is the IP-leak fix path (finding F8).
    const ruleSetDir = join(process.cwd(), 'resources')
    expect(existsSync(join(ruleSetDir, 'geoip-ru.srs'))).toBe(true)
    expect(existsSync(join(ruleSetDir, 'geosite-category-gov-ru.srs'))).toBe(true)
    const cfg = generateSingboxConfig(
      { outbound: { type: 'vless', server: 'ex.com', server_port: 443, uuid: 'u', tls: { enabled: true, server_name: 'ex.com' } } },
      'socks5',
      [],
      { smartRuSplit: true, smartRuMapsDirect: true, smartRuRuleSetDir: ruleSetDir, directProxyPortOverride: 23458, clashPortOverride: 23459 }
    ) as any
    // Sanity: rule-sets must be local (no network), pointing at the .srs.
    for (const rs of cfg.route.rule_set) {
      expect(rs.type).toBe('local')
      expect(String(rs.path)).toMatch(/\.srs$/)
    }
    const dir = mkdtempSync(join(tmpdir(), 'vpnte-cfg-local-'))
    const f = join(dir, 'sing-box.json')
    writeFileSync(f, JSON.stringify(cfg, null, 2))
    const exe = join(process.cwd(), 'resources', 'sing-box.exe')
    const out = execFileSync(exe, ['check', '-c', f], { encoding: 'utf8' })
    expect(typeof out).toBe('string')
  })
})
