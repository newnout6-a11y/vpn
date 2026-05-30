/**
 * L1 regression: app.log must rotate by size instead of growing forever.
 *
 * Earlier the logger only ever appended — every IPC call logs at debug level,
 * so over weeks of uptime the file reached hundreds of MB (slow append queue,
 * disk pressure, huge diagnostics ZIP). We now roll app.log → app.prev.log
 * once it crosses the cap, keeping one previous generation.
 *
 * We point app.getPath('userData') at a real temp dir and drive logEvent until
 * the file rolls, then assert app.prev.log exists and app.log is small again.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mkdtempSync, rmSync, existsSync, statSync } from 'fs'
import { tmpdir } from 'os'
import { join } from 'path'

let tmpRoot: string

vi.mock('electron', () => ({
  app: {
    getPath: () => tmpRoot
  },
  shell: { openPath: vi.fn() }
}))
// vpnProfiles pulls a heavy graph; stub the two redactors the logger uses.
vi.mock('./vpnProfiles', () => ({
  redactSensitiveConfig: (v: unknown) => v,
  redactSensitiveText: (v: string) => v
}))

const flush = () => new Promise((r) => setTimeout(r, 50))

describe('appLogger rotation', () => {
  beforeEach(() => {
    tmpRoot = mkdtempSync(join(tmpdir(), 'vpnte-log-'))
    vi.resetModules()
  })
  afterEach(() => {
    try { rmSync(tmpRoot, { recursive: true, force: true }) } catch { /* ignore */ }
  })

  it('rolls app.log to app.prev.log once it exceeds the cap', async () => {
    const { logEvent, getLogDir } = await import('./appLogger')
    const logDir = getLogDir()
    const appLog = join(logDir, 'app.log')
    const prevLog = join(logDir, 'app.prev.log')

    // Detail strings are truncated to ~4000 chars by the logger, so each line
    // lands around ~3.6 KB. 5 MB cap / 3.6 KB ≈ 1400 lines to roll; write 2500
    // to be safely over even after truncation.
    const blob = 'x'.repeat(3500)
    for (let i = 0; i < 2500; i++) {
      logEvent('info', 'test', `line ${i}`, { blob })
    }
    // Poll for the roll rather than a fixed sleep — the append queue is async.
    for (let i = 0; i < 100 && !existsSync(prevLog); i++) await flush()

    expect(existsSync(prevLog)).toBe(true)
    // After a roll, the live log holds only post-roll lines → well under cap.
    expect(existsSync(appLog)).toBe(true)
    expect(statSync(appLog).size).toBeLessThan(5 * 1024 * 1024)
    // The previous generation should itself be bounded (one roll's worth).
    expect(statSync(prevLog).size).toBeLessThanOrEqual(6 * 1024 * 1024)
  })

  it('keeps a single small file when well under the cap', async () => {
    const { logEvent, getLogDir } = await import('./appLogger')
    const logDir = getLogDir()
    const prevLog = join(logDir, 'app.prev.log')

    for (let i = 0; i < 20; i++) logEvent('info', 'test', `small ${i}`)
    await flush()

    expect(existsSync(prevLog)).toBe(false)
  })
})
