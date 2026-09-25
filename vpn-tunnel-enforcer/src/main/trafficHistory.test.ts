import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { appendFile, mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

const state = vi.hoisted(() => ({
  userData: ''
}))

vi.mock('electron', () => ({
  app: { getPath: () => state.userData },
  ipcMain: { handle: vi.fn() },
  BrowserWindow: { getAllWindows: () => [] }
}))
vi.mock('./appLogger', () => ({ logEvent: vi.fn() }))
vi.mock('./domainEnrichment', () => ({
  buildEnrichmentProxyRules: vi.fn(),
  domainEnrichmentService: {
    clear: vi.fn(),
    get: vi.fn(),
    onUpdate: vi.fn(),
    queueDomains: vi.fn()
  }
}))
vi.mock('./settings', () => ({
  settingsStore: { get: () => ({ domainEnrichmentEnabled: false }) }
}))
vi.mock('./tunController', () => ({
  tunController: { getStatus: () => ({ running: false }) }
}))
vi.mock('./trafficConnections', () => ({
  clearRecordedTrafficDomains: vi.fn(),
  getRecordedTrafficDomains: () => [],
  getInfraHosts: () => new Set<string>(),
  shouldRecordHost: (host: string) => host
}))

import { getTrafficHistory, parseSingboxLogLine } from './trafficHistory'

let runtimeDir = ''

function logLine(domain: string): string {
  return `+0300 2026-07-17 20:51:00 DEBUG [123 0ms] dns: exchanged ${domain} NOERROR 30\n`
}

beforeEach(async () => {
  state.userData = await mkdtemp(join(tmpdir(), 'vpnte-traffic-history-'))
  runtimeDir = join(state.userData, 'tun-runtime')
  await mkdir(runtimeDir, { recursive: true })
})

afterEach(async () => {
  await rm(state.userData, { recursive: true, force: true })
})

describe('traffic history log parsing', () => {
  it('parses supported sing-box lines without allocating patterns per call', () => {
    expect(parseSingboxLogLine(logLine('Example.COM').trim())).toMatchObject({
      domain: 'example.com'
    })
  })

  it('parses the real sing-box 1.13 DNS exchange format (record-type token)', () => {
    // Real lines from a production 2026-09-25 log. The old pattern missed all
    // of these because of the "A"/"AAAA"/"HTTPS" token after the verb — which
    // is why the history only ever showed api.ipify.org (matched via "to <d>").
    expect(parseSingboxLogLine(
      '+0300 2026-09-25 17:17:06 INFO [1657141230 946ms] dns: exchanged A sub.alvsub.cc. 13 IN A 5.129.240.114'
    )).toMatchObject({ domain: 'sub.alvsub.cc' })
    expect(parseSingboxLogLine(
      '+0300 2026-09-25 17:17:55 INFO [3321415587 5.41s] dns: exchanged A yandex.ru. 7 IN A 213.180.193.56'
    )).toMatchObject({ domain: 'yandex.ru' })
    expect(parseSingboxLogLine(
      '+0300 2026-09-25 17:24:01 INFO [3339232011 328ms] dns: cached A youboost.app. 59 IN A 109.71.15.131'
    )).toMatchObject({ domain: 'youboost.app' })
    expect(parseSingboxLogLine(
      '+0300 2026-09-25 17:17:06 INFO [1 5ms] dns: exchanged AAAA www.youtube.com. 7 IN AAAA 2a00::1'
    )).toMatchObject({ domain: 'www.youtube.com' })
    expect(parseSingboxLogLine(
      '+0300 2026-09-25 17:17:06 DEBUG [1657141230 0ms] dns: exchange A chatgpt.com. IN A'
    )).toMatchObject({ domain: 'chatgpt.com' })
  })

  it('still matches a hostname in a "to <domain>:port" connection line', () => {
    expect(parseSingboxLogLine(
      '+0300 2026-09-25 17:47:40 INFO [2440758562 1ms] inbound/mixed[mixed-direct-in]: inbound connection to api.ipify.org:80'
    )).toMatchObject({ domain: 'api.ipify.org' })
  })

  it('does not treat a bare IP destination as a domain', () => {
    expect(parseSingboxLogLine(
      '+0300 2026-09-25 17:24:01 INFO [698962057 0ms] inbound/tun[tun-in]: inbound connection to 109.71.15.131:443'
    )).toBeNull()
  })

  it('uses a bounded initial tail and incorporates only appended log data afterwards', async () => {
    const logPath = join(runtimeDir, 'sing-box.log')
    const filler = 'DEBUG connection retry without a hostname\n'.repeat(30_000)
    await writeFile(logPath, logLine('old.example') + filler + logLine('recent.example'), 'utf8')

    const first = await getTrafficHistory()
    expect(first.map(entry => entry.domain)).toContain('recent.example')
    expect(first.map(entry => entry.domain)).not.toContain('old.example')

    await appendFile(logPath, logLine('appended.example'), 'utf8')
    const second = await getTrafficHistory()
    expect(second.map(entry => entry.domain)).toEqual(expect.arrayContaining([
      'recent.example',
      'appended.example'
    ]))
    expect(second.find(entry => entry.domain === 'recent.example')?.count).toBe(1)
  })
})
