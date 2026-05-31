/**
 * Tests for the pure sing-box-log classifiers used by the route-diagnostics
 * card. These pin down the false-positive fixes from finding F9:
 *   - RU public IPs going direct-out under smart-RU split are EXPECTED, not a
 *     leak (geoip-ru / geosite-category-gov-ru matches).
 *   - "block-out: operation not permitted" (UDP/QUIC on a tcp-only Reality
 *     outbound) is benign noise, not a real error.
 *
 * The module imports tunController (which imports electron) so we mock electron
 * the same way tunControllerConfig.test.ts does — the helpers under test are
 * pure and don't touch any of it.
 */

import { describe, it, expect, vi } from 'vitest'

vi.mock('electron', () => ({
  app: { getPath: () => '/tmp/vpnte-test', getAppPath: () => '/tmp/vpnte-test/app', isPackaged: false }
}))
vi.mock('electron-store', () => ({
  default: class MockStore {
    private d: Record<string, any> = {}
    get(k?: string) { return k ? this.d[k] : {} }
    set(k: string, v: any) { this.d[k] = v }
  }
}))
vi.mock('sudo-prompt', () => ({ default: { exec: vi.fn() }, exec: vi.fn() }))
vi.mock('./appLogger', () => ({ logEvent: vi.fn() }))

import { classifyDirectPublic, isBenignBlockLine, extractRealErrors } from './leakDiagnostics'

// Real-shaped excerpt from the user's 16-20 diagnostic: Yandex/VK going direct
// via geoip-ru, and a benign block-out UDP error.
const SMART_RU_LOG = [
  '+0300 2026-05-31 19:19:08 INFO [1368113086 178ms] dns: exchanged A api.passport.yandex.ru. 159 IN A 77.88.21.24',
  '+0300 2026-05-31 19:19:08 DEBUG [2303884170 0ms] router: match[6] rule_set=geoip-ru => route(direct-out)',
  '+0300 2026-05-31 19:19:08 INFO [2303884170 0ms] outbound/direct[direct-out]: outbound connection to 77.88.21.24:443',
  '+0300 2026-05-31 19:19:09 DEBUG [3091168918 0ms] router: match[6] rule_set=geoip-ru => route(direct-out)',
  '+0300 2026-05-31 19:19:09 INFO [3091168918 0ms] outbound/direct[direct-out]: outbound connection to 95.213.56.2:443',
  '+0300 2026-05-31 19:19:15 DEBUG [2149439147 0ms] router: match[4] rule_set=geosite-category-gov-ru => route(direct-out)',
  '+0300 2026-05-31 19:19:15 INFO [2149439147 0ms] outbound/direct[direct-out]: outbound connection to 109.207.1.118:443'
].join('\n')

describe('classifyDirectPublic', () => {
  it('classifies RU geoip/gov-ru direct-out as smart-RU, NOT a leak', () => {
    const r = classifyDirectPublic(SMART_RU_LOG)
    expect(r.leakedCount).toBe(0)
    expect(r.smartRuCount).toBe(3)
    expect(r.smartRuExamples).toContain('77.88.21.24')
    expect(r.smartRuExamples).toContain('95.213.56.2')
    expect(r.smartRuExamples).toContain('109.207.1.118')
  })

  it('flags an unexplained public direct-out as a leak', () => {
    const log = [
      '+0300 x INFO [555 0ms] outbound/direct[direct-out]: outbound connection to 8.8.8.8:443'
    ].join('\n')
    const r = classifyDirectPublic(log)
    expect(r.leakedCount).toBe(1)
    expect(r.smartRuCount).toBe(0)
    expect(r.leakedExamples).toContain('8.8.8.8')
  })

  it('counts a VPN-core process_name exclusion as allowed, not leaked', () => {
    const log = [
      '+0300 x DEBUG [777 0ms] router: match[1] process_name=[Happ.exe] => route(direct-out)',
      '+0300 x INFO [777 0ms] outbound/direct[direct-out]: outbound connection to 1.2.3.4:443'
    ].join('\n')
    const r = classifyDirectPublic(log)
    expect(r.leakedCount).toBe(0)
    expect(r.allowedCoreCount).toBe(1)
  })

  it('ignores private/LAN direct-out IPs entirely', () => {
    const log = [
      '+0300 x INFO [888 0ms] outbound/direct[direct-out]: outbound connection to 192.168.1.1:443',
      '+0300 x INFO [889 0ms] outbound/direct[direct-out]: outbound connection to 10.0.0.5:53'
    ].join('\n')
    const r = classifyDirectPublic(log)
    expect(r.leakedCount).toBe(0)
    expect(r.smartRuCount).toBe(0)
    expect(r.allowedCoreCount).toBe(0)
  })
})

describe('isBenignBlockLine / extractRealErrors', () => {
  it('treats block-out UDP "operation not permitted" as benign', () => {
    const line = '+0300 2026-05-31 19:19:22 ERROR [1729147022 0ms] connection: listen packet connection using  using outbound/block[block-out]: operation not permitted'
    expect(isBenignBlockLine(line)).toBe(true)
  })

  it('treats "blocked packet connection" info as benign', () => {
    const line = '+0300 2026-05-31 19:19:22 INFO [1729147022 0ms] outbound/block[block-out]: blocked packet connection to 74.125.250.129:19302'
    expect(isBenignBlockLine(line)).toBe(true)
  })

  it('excludes benign block noise from the error summary but keeps real errors', () => {
    const log = [
      '+0300 x ERROR [1 0ms] connection: listen packet connection using  using outbound/block[block-out]: operation not permitted',
      '+0300 x INFO [2 0ms] outbound/block[block-out]: blocked packet connection to 74.125.250.129:19302',
      '+0300 x ERROR [3 0ms] outbound/vless[proxy-out]: connection to server failed: i/o timeout'
    ].join('\n')
    const errors = extractRealErrors(log)
    expect(errors.length).toBe(1)
    expect(errors[0]).toMatch(/i\/o timeout/)
  })

  it('returns [] for a clean log', () => {
    const log = [
      '+0300 x INFO [1 0ms] outbound/direct[direct-out]: outbound connection to 77.88.21.24:443'
    ].join('\n')
    expect(extractRealErrors(log)).toEqual([])
  })
})
