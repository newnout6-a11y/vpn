import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mkdtempSync, rmSync, readFileSync } from 'fs'
import { tmpdir } from 'os'
import { join } from 'path'

let tmpRoot: string

vi.mock('electron', () => ({
  app: {
    getPath: () => tmpRoot
  },
  shell: { openPath: vi.fn() }
}))

vi.mock('./vpnProfiles', () => ({
  redactSensitiveConfig: (value: unknown) => value,
  redactSensitiveText: (value: string) => value
}))

const flush = () => new Promise((resolve) => setTimeout(resolve, 50))

describe('appLogger topology redaction', () => {
  beforeEach(() => {
    tmpRoot = mkdtempSync(join(tmpdir(), 'vpnte-log-redact-'))
    vi.resetModules()
  })

  afterEach(() => {
    try { rmSync(tmpRoot, { recursive: true, force: true }) } catch { /* ignore */ }
  })

  it('redacts network topology in messages and details', async () => {
    const { logEvent, getAppLogPath } = await import('./appLogger')
    logEvent('info', 'test', 'adapter 192.0.2.44 saw mac aa:bb:cc:dd:ee:ff', {
      publicIpViaProxy: '203.0.113.10',
      adapterAlias: 'Ethernet 7',
      routeCount: 2,
      keptCounter: 3
    })
    await flush()

    const raw = readFileSync(getAppLogPath(), 'utf8')
    expect(raw).not.toContain('192.0.2.44')
    expect(raw).not.toContain('203.0.113.10')
    expect(raw).not.toContain('aa:bb:cc:dd:ee:ff')
    expect(raw).not.toContain('Ethernet 7')
    expect(raw).toContain('<redacted-ip>')
    expect(raw).toContain('<redacted-mac>')
    expect(raw).toContain('"keptCounter":3')
  })
})
