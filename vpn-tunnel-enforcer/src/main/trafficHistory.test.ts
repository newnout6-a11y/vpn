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
