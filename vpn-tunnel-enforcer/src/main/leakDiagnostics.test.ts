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
import { exec as childExec, execFile as childExecFile } from 'child_process'

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

  const execFile = vi.fn((_file: string, _args: any, _opts: any, cb: Function) => {
    const callback = typeof _opts === 'function' ? _opts : cb
    if (callback) callback(null, '[]', '')
    return {} as any
  })
  ;(execFile as any)[Symbol.for('nodejs.util.promisify.custom')] = (file: string, args: any, opts: any) =>
    new Promise((resolve, reject) => {
      execFile(file, args, opts, (err: any, stdout: string, stderr: string) => {
        if (err) {
          err.stderr = stderr
          reject(err)
          return
        }
        resolve({ stdout, stderr })
      })
    })

  return { default: { exec, execFile }, exec, execFile }
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

import { classifyDirectPublic, isBenignBlockLine, isBenignProcessSearchLine, isVpnCoreProcessPath, isRuHostname, extractRealErrors, summarizeSingboxLog, dnsTypeName, getPublicIpV4, getPublicIpV6, runLeakCheck } from './leakDiagnostics'

beforeEach(() => {
  vi.mocked(axios.get).mockReset()
  vi.mocked(axios.get).mockResolvedValue({ data: { ip: '198.51.100.1' } })
  vi.mocked(childExec).mockReset()
  vi.mocked(childExec).mockImplementation((_cmd: string, _opts: any, cb: any) => {
    if (cb) cb(null, '[]', '')
    return {} as any
  })
  vi.mocked(childExecFile).mockReset()
  vi.mocked(childExecFile).mockImplementation((_file: string, _args: any, _opts: any, cb: any) => {
    const callback = typeof _opts === 'function' ? _opts : cb
    if (callback) callback(null, '[]', '')
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
  it('classifies RU geoip/gov-ru direct-out as smart-RU, NOT a leak (DEBUG log)', () => {
    const r = classifyDirectPublic(SMART_RU_LOG, { smartRuSplit: true })
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

  it('counts a VPN-core process_name exclusion as allowed, not leaked (DEBUG log)', () => {
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

  // ── INFO-level classification (the real production log shape) ──────────
  // The tunnel runs sing-box at INFO, so there are NO `router: match[i]
  // rule_set=...` / `process_name=[...]` DEBUG lines. Classification must
  // work off `found process path`, the mixed-direct-in inbound and the DNS
  // exchange lines. These are real-shaped lines from the user's 2026-09-25
  // session.

  it('treats a VPN-core process found via process path as allowed (INFO log)', () => {
    const log = [
      '+0300 x INFO [101 0ms] inbound/tun[tun-in]: inbound connection to 1.2.3.4:443',
      '+0300 x INFO [101 0ms] router: found process path: C:\\Program Files\\Happ\\Happ.exe',
      '+0300 x INFO [101 0ms] outbound/direct[direct-out]: outbound connection to 1.2.3.4:443'
    ].join('\n')
    const r = classifyDirectPublic(log)
    expect(r.leakedCount).toBe(0)
    expect(r.allowedCoreCount).toBe(1)
  })

  it('treats the app self-probe via mixed-direct-in as allowed (INFO log)', () => {
    const log = [
      '+0300 x INFO [202 0ms] inbound/mixed[mixed-direct-in]: inbound connection from 127.0.0.1:50189',
      '+0300 x INFO [202 1ms] inbound/mixed[mixed-direct-in]: inbound connection to se.savethis.cloud:443',
      '+0300 x INFO [202 2ms] router: found process path: C:\\Program Files\\VPN Tunnel Enforcer\\VPN Tunnel Enforcer.exe',
      '+0300 x INFO [202 2ms] outbound/direct[direct-out]: outbound connection to 1.2.3.4:443'
    ].join('\n')
    const r = classifyDirectPublic(log)
    expect(r.leakedCount).toBe(0)
    expect(r.allowedCoreCount).toBe(1)
  })

  it('attributes a RU-hostname IP to smart-RU when split is ON (INFO log)', () => {
    // Yandex Browser → yandex.ru resolved to a RU IP, then direct-out. This
    // is the exact false-positive from the user's diagnostic.
    const log = [
      '+0300 x INFO [303 5ms] dns: exchanged A yandex.ru. 7 IN A 213.180.193.56',
      '+0300 x INFO [404 0ms] inbound/tun[tun-in]: inbound connection to 213.180.193.56:443',
      '+0300 x INFO [404 0ms] router: found process path: C:\\Users\\Redmi\\AppData\\Local\\Yandex\\YandexBrowser\\Application\\browser.exe',
      '+0300 x INFO [404 0ms] outbound/direct[direct-out]: outbound connection to 213.180.193.56:443'
    ].join('\n')
    const r = classifyDirectPublic(log, { smartRuSplit: true })
    expect(r.leakedCount).toBe(0)
    expect(r.smartRuCount).toBe(1)
    expect(r.smartRuExamples).toContain('213.180.193.56')
  })

  it('attributes a RU-hostname IPv6 (AAAA) direct-out to smart-RU when split is ON', () => {
    // AAAA exchanges must feed the hostname→IP map just like A records —
    // otherwise IPv6 direct-out egress of a RU host reads as a leak.
    const log = [
      '+0300 x INFO [303 5ms] dns: exchanged AAAA yandex.ru. 7 IN AAAA 2a02:6b8::2:242',
      '+0300 x INFO [404 0ms] inbound/tun[tun-in]: inbound connection to 2a02:6b8::2:242:443',
      '+0300 x INFO [404 0ms] router: found process path: C:\\Users\\Redmi\\AppData\\Local\\Yandex\\YandexBrowser\\Application\\browser.exe',
      '+0300 x INFO [404 0ms] outbound/direct[direct-out]: outbound connection to 2a02:6b8::2:242:443'
    ].join('\n')
    const r = classifyDirectPublic(log, { smartRuSplit: true })
    expect(r.leakedCount).toBe(0)
    expect(r.smartRuCount).toBe(1)
  })

  it('flags the same RU-IP direct-out as a leak when smart-RU split is OFF', () => {
    const log = [
      '+0300 x INFO [303 5ms] dns: exchanged A yandex.ru. 7 IN A 213.180.193.56',
      '+0300 x INFO [404 0ms] inbound/tun[tun-in]: inbound connection to 213.180.193.56:443',
      '+0300 x INFO [404 0ms] router: found process path: C:\\Users\\Redmi\\AppData\\Local\\Yandex\\YandexBrowser\\Application\\browser.exe',
      '+0300 x INFO [404 0ms] outbound/direct[direct-out]: outbound connection to 213.180.193.56:443'
    ].join('\n')
    const r = classifyDirectPublic(log, { smartRuSplit: false })
    expect(r.leakedCount).toBe(1)
    expect(r.leakedExamples).toContain('213.180.193.56')
  })

  it('flags a foreign-hostname IP direct-out as a leak even when smart-RU is ON', () => {
    // A non-RU host resolving to a foreign IP must NOT be excused by smart-RU.
    const log = [
      '+0300 x INFO [505 5ms] dns: exchanged A example.com. 7 IN A 93.184.216.34',
      '+0300 x INFO [606 0ms] inbound/tun[tun-in]: inbound connection to 93.184.216.34:443',
      '+0300 x INFO [606 0ms] router: found process path: C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
      '+0300 x INFO [606 0ms] outbound/direct[direct-out]: outbound connection to 93.184.216.34:443'
    ].join('\n')
    const r = classifyDirectPublic(log, { smartRuSplit: true })
    expect(r.leakedCount).toBe(1)
    expect(r.leakedExamples).toContain('93.184.216.34')
  })
})

describe('isVpnCoreProcessPath', () => {
  it('recognises VPN-core executables by leaf name, case-insensitively', () => {
    expect(isVpnCoreProcessPath('C:\\Program Files\\Happ\\Happ.exe')).toBe(true)
    expect(isVpnCoreProcessPath('C:\\Program Files\\Hiddify\\Hiddify.exe')).toBe(true)
    expect(isVpnCoreProcessPath('C:\\Windows\\System32\\xray.exe')).toBe(true)
    expect(isVpnCoreProcessPath('C:\\Program Files\\VPN Tunnel Enforcer\\VPN Tunnel Enforcer.exe')).toBe(true)
    expect(isVpnCoreProcessPath('C:\\Users\\x\\vpnte-xray.exe')).toBe(true)
  })

  it('rejects ordinary apps', () => {
    expect(isVpnCoreProcessPath('C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe')).toBe(false)
    expect(isVpnCoreProcessPath('C:\\Users\\Redmi\\AppData\\Local\\Yandex\\YandexBrowser\\Application\\browser.exe')).toBe(false)
    expect(isVpnCoreProcessPath('C:\\Windows\\System32\\curl.exe')).toBe(false)
    expect(isVpnCoreProcessPath('')).toBe(false)
  })
})

describe('isRuHostname', () => {
  it('matches RU TLDs', () => {
    expect(isRuHostname('yandex.ru')).toBe(true)
    expect(isRuHostname('api.browser.yandex.ru')).toBe(true)
    expect(isRuHostname('example.su')).toBe(true)
    expect(isRuHostname('пример.xn--p1ai')).toBe(true)
  })

  it('matches RU commercial services on non-.ru TLDs', () => {
    expect(isRuHostname('api.browser.yandex.net')).toBe(true)
    expect(isRuHostname('s3.yandex.net')).toBe(true)
    expect(isRuHostname('vk.com')).toBe(true)
    expect(isRuHostname('cdn.vk.com')).toBe(true)
  })

  it('rejects foreign hostnames', () => {
    expect(isRuHostname('example.com')).toBe(false)
    expect(isRuHostname('google.com')).toBe(false)
    expect(isRuHostname('youboost.app')).toBe(false)
    expect(isRuHostname('')).toBe(false)
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

describe('isBenignProcessSearchLine', () => {
  it('treats "router: failed to search process: Access is denied" as benign', () => {
    // Real-shaped lines from a healthy session (2026-09-25 diagnostic): the
    // router cannot open SYSTEM/other-user processes, logs this at INFO and
    // routes by the remaining matchers. Not an error.
    expect(isBenignProcessSearchLine(
      '+0300 2026-09-25 17:32:53 INFO [2574407273 0ms] router: failed to search process: Access is denied.'
    )).toBe(true)
    expect(isBenignProcessSearchLine(
      '+0300 2026-09-25 17:34:50 INFO router: failed to search process: Access is denied.'
    )).toBe(true)
  })

  it('does not match other router failures', () => {
    expect(isBenignProcessSearchLine(
      '+0300 x ERROR [1 0ms] router: failed to initialize rule-set geoip-ru: file missing'
    )).toBe(false)
    expect(isBenignProcessSearchLine(
      '+0300 x ERROR outbound/vless[proxy-out]: connection to server failed: i/o timeout'
    )).toBe(false)
  })

  it('keeps process-search noise out of the error summary but keeps real errors', () => {
    const log = [
      '+0300 2026-09-25 17:32:53 INFO [2574407273 0ms] router: failed to search process: Access is denied.',
      '+0300 2026-09-25 17:34:50 INFO router: failed to search process: Access is denied.',
      '+0300 x ERROR [3 0ms] outbound/vless[proxy-out]: connection to server failed: i/o timeout'
    ].join('\n')
    const errors = extractRealErrors(log)
    expect(errors.length).toBe(1)
    expect(errors[0]).toMatch(/i\/o timeout/)
  })

  it('produces a clean summary for a healthy session full of process-search noise', () => {
    const log = [
      '+0300 2026-09-25 17:32:53 INFO [2574407273 0ms] router: failed to search process: Access is denied.',
      '+0300 2026-09-25 17:32:53 INFO [2574407273 0ms] outbound/vless[proxy-out]: outbound connection to ex.com:443',
      '+0300 2026-09-25 17:34:50 INFO router: failed to search process: Access is denied.'
    ].join('\n')
    expect(extractRealErrors(log)).toEqual([])
    expect(summarizeSingboxLog(log)).not.toContain('errors:')
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
    vi.mocked(childExecFile).mockImplementation((_file: string, _args: any, _opts: any, cb: any) => {
      const callback = typeof _opts === 'function' ? _opts : cb
      callback(new Error('curl missing'), '', 'curl missing')
      return {} as any
    })
    vi.mocked(childExec).mockImplementation((cmd: string, _opts: any, cb: any) => {
      if (String(cmd).toLowerCase().includes('powershell')) {
        cb(null, '198.51.100.77\n', '')
        return {} as any
      }
      cb(new Error('error'), '', '')
      return {} as any
    })

    const ip = await getPublicIpV4()
    const commands = [
      ...vi.mocked(childExecFile).mock.calls.map(([file, args]) => `${file} ${(args || []).join(' ')}`),
      ...vi.mocked(childExec).mock.calls.map(([cmd]) => String(cmd))
    ]
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
