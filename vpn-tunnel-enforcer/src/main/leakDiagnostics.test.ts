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

import { beforeEach, describe, it, expect, vi } from 'vitest'
import axios from 'axios'
import { exec as childExec } from 'child_process'

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
vi.mock('axios', () => ({
  default: { get: vi.fn(async () => ({ data: { ip: '198.51.100.1' } })) },
  get: vi.fn(async () => ({ data: { ip: '198.51.100.1' } }))
}))
vi.mock('child_process', () => {
  const exec = vi.fn((_cmd: string, _opts: any, cb: Function) => {
    if (cb) cb(null, '[]', '')
    return {} as any
  })
  ;(exec as any)[Symbol.for('nodejs.util.promisify.custom')] = (cmd: string, opts: any) =>
    new Promise((resolve, reject) => {
      exec(cmd, opts, (err: any, stdout: string, stderr: string) => {
        if (err) {
          err.stderr = stderr
          reject(err)
          return
        }
        resolve({ stdout, stderr })
      })
    })
  return { default: { exec }, exec }
})
vi.mock('fs/promises', () => ({
  default: { readFile: vi.fn(async () => '') },
  readFile: vi.fn(async () => '')
}))
vi.mock('sudo-prompt', () => ({ default: { exec: vi.fn() }, exec: vi.fn() }))
vi.mock('./appLogger', () => ({ logEvent: vi.fn() }))
vi.mock('./tunController', () => ({
  detectForeignTun: vi.fn(() => null),
  getTunRuntimeDir: vi.fn(() => '/tmp/vpnte-test/tun-runtime'),
  parseProxyAddress: vi.fn((value: string) => {
    const [host, port] = value.split(':')
    return { host, port: Number(port) }
  }),
  probeTcp: vi.fn(async () => false)
}))

import { classifyDirectPublic, isBenignBlockLine, extractRealErrors, summarizeSingboxLog, dnsTypeName, getPublicIpV4, getPublicIpV6, runLeakCheck } from './leakDiagnostics'

beforeEach(() => {
  vi.mocked(axios.get).mockReset()
  vi.mocked(axios.get).mockResolvedValue({ data: { ip: '198.51.100.1' } })
  vi.mocked(childExec).mockReset()
  vi.mocked(childExec).mockImplementation((_cmd: string, _opts: any, cb: Function) => {
    if (cb) cb(null, '[]', '')
    return {} as any
  })
})

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

  it('reports unparsed direct-out lines so log format drift is not silently green', () => {
    const log = [
      '+0300 x INFO [999 0ms] outbound/direct[direct-out]: dial tcp example.com:443'
    ].join('\n')
    const r = classifyDirectPublic(log)
    expect(r.leakedCount).toBe(0)
    expect(r.unparsedDirectCount).toBe(1)
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

  it('excludes benign upload-close noise from the error summary', () => {
    const log = [
      '+0300 2026-07-05 18:29:24 ERROR [1097614137 171ms] connection: connection upload closed: raw-read tcp4 192.168.250.253:59761->192.168.250.254:10030: An existing connection was forcibly closed by the remote host.',
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

  it('does not treat plain INFO text containing timeout/failed as a real error', () => {
    const log = [
      '+0300 x INFO [1 0ms] health: last timeout was recovered',
      '+0300 x INFO [2 0ms] route: failed probes from previous session ignored'
    ].join('\n')
    expect(extractRealErrors(log)).toEqual([])
  })
})

describe('summarizeSingboxLog', () => {
  it('counts ANY proxy-out outbound type, not just socks/http (Direct VPN/VLESS fix)', () => {
    // Real directVpn sessions egress via vless[proxy-out]; the old regex only
    // matched socks|http and reported a misleading "proxy-out: 0".
    const log = [
      '+0300 x INFO [1 0ms] outbound/vless[proxy-out]: outbound connection to ex.com:443',
      '+0300 x INFO [2 0ms] outbound/vless[proxy-out]: outbound connection to ex.com:443',
      '+0300 x INFO [3 0ms] outbound/direct[direct-out]: outbound connection to 77.88.21.24:443',
      '+0300 x DEBUG [4 0ms] dns: exchanged example.com NOERROR 5'
    ].join('\n')
    const summary = summarizeSingboxLog(log)
    expect(summary).toContain('proxy-out: 2')
    expect(summary).toContain('direct-out: 1')
  })

  it('also counts socks/http/trojan/hysteria2 outbounds', () => {
    const log = [
      '+0300 x INFO [1 0ms] outbound/socks[proxy-out]: outbound connection to ex.com:443',
      '+0300 x INFO [2 0ms] outbound/trojan[proxy-out]: outbound connection to ex.com:443',
      '+0300 x INFO [3 0ms] outbound/hysteria2[proxy-out]: outbound connection to ex.com:443'
    ].join('\n')
    expect(summarizeSingboxLog(log)).toContain('proxy-out: 3')
  })

  it('does not count block-out as proxy-out', () => {
    const log = [
      '+0300 x INFO [1 0ms] outbound/block[block-out]: blocked packet connection to 8.8.8.8:443'
    ].join('\n')
    expect(summarizeSingboxLog(log)).toContain('proxy-out: 0')
  })
})

describe('dnsTypeName', () => {
  it('maps numeric Resolve-DnsName record types to names', () => {
    expect(dnsTypeName(1)).toBe('A')
    expect(dnsTypeName(28)).toBe('AAAA')
    expect(dnsTypeName(5)).toBe('CNAME')
    expect(dnsTypeName(65)).toBe('HTTPS')
  })

  it('passes through values that are already names', () => {
    expect(dnsTypeName('A')).toBe('A')
    expect(dnsTypeName('AAAA')).toBe('AAAA')
  })

  it('falls back to "type N" for unknown numeric codes', () => {
    expect(dnsTypeName(999)).toBe('type 999')
  })
})

describe('getPublicIpV6', () => {
  it('falls back to the next IPv6 endpoint when api6.ipify is blocked', async () => {
    vi.mocked(axios.get)
      .mockRejectedValueOnce(new Error('blocked'))
      .mockResolvedValueOnce({ data: { address: '2001:db8::42' } })

    await expect(getPublicIpV6()).resolves.toBe('2001:db8::42')
  })
})

describe('getPublicIpV4', () => {
  it('falls back to PowerShell Invoke-RestMethod when axios and curl fail', async () => {
    vi.mocked(axios.get).mockRejectedValue(new Error('blocked'))
    vi.mocked(childExec).mockImplementation((cmd: string, _opts: any, cb: Function) => {
      if (String(cmd).toLowerCase().includes('powershell')) {
        cb(null, '198.51.100.77\n', '')
        return {} as any
      }
      cb(new Error('curl missing'), '', 'curl missing')
      return {} as any
    })

    const ip = await getPublicIpV4()
    const commands = vi.mocked(childExec).mock.calls.map(([cmd]) => String(cmd))
    expect(commands).toEqual(
      expect.arrayContaining([
        expect.stringContaining('curl.exe'),
        expect.stringContaining('powershell')
      ])
    )
    expect(ip).toBe('198.51.100.77')
  })
})

describe('runLeakCheck', () => {
  it('does not flag a stale local proxy as failed in directVpn mode', async () => {
    const result = await runLeakCheck({
      connectionMode: 'directVpn',
      proxyAddr: '127.0.0.1:10808',
      proxyType: 'socks5',
      tunRunning: true
    })

    const proxyItem = result.items.find(item => item.id === 'proxy')
    expect(proxyItem?.status).toBe('info')
    expect(proxyItem?.value).toBe('Direct VPN (sing-box)')
    expect(proxyItem?.details).toMatch(/локальный proxy не используется/i)
  })
})
