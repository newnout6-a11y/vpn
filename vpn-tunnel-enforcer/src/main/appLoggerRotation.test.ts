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
import { mkdtempSync, rmSync, existsSync, statSync, mkdirSync, writeFileSync } from 'fs'
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
    const logSpy = vi.spyOn(console, 'log').mockImplementation(() => undefined)
    const { logEvent, getLogDir } = await import('./appLogger')
    try {
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
      for (let i = 0; i < 250 && (!existsSync(prevLog) || !existsSync(appLog)); i++) await flush()

      expect(existsSync(prevLog)).toBe(true)
      // After a roll, the live log holds only post-roll lines → well under cap.
      expect(existsSync(appLog)).toBe(true)
      expect(statSync(appLog).size).toBeLessThan(5 * 1024 * 1024)
      // The previous generation should itself be bounded (one roll's worth).
      expect(statSync(prevLog).size).toBeLessThanOrEqual(6 * 1024 * 1024)
    } finally {
      logSpy.mockRestore()
    }
  }, 15000)

  it('keeps a single small file when well under the cap', async () => {
    const { logEvent, getLogDir } = await import('./appLogger')
    const logDir = getLogDir()
    const prevLog = join(logDir, 'app.prev.log')

    for (let i = 0; i < 20; i++) logEvent('info', 'test', `small ${i}`)
    await flush()

    expect(existsSync(prevLog)).toBe(false)
  })

  it('repairs reversible UTF-8/Windows-1251 mojibake without changing valid Russian', async () => {
    const { repairMojibake } = await import('./appLogger')

    expect(repairMojibake('Р—Р°С‰РёС‚Р° РІРєР»СЋС‡РµРЅР°')).toBe('Защита включена')
    expect(repairMojibake('Защита включена')).toBe('Защита включена')
    expect(repairMojibake('plain ASCII')).toBe('plain ASCII')
  })

  it('retains rotation byte stats when rename fails so subsequent writes retry rotation', async () => {
    const logSpy = vi.spyOn(console, 'log').mockImplementation(() => undefined)
    const { logEvent, getLogDir } = await import('./appLogger')
    try {
      const logDir = getLogDir()
      const appLog = join(logDir, 'app.log')
      const prevLog = join(logDir, 'app.prev.log')

      // Block rotation by creating a non-empty directory at app.prev.log,
      // causing unlink and rename to fail with EPERM.
      mkdirSync(prevLog, { recursive: true })
      writeFileSync(join(prevLog, 'lock.tmp'), 'blocking file')

      const blob = 'x'.repeat(3500)
      for (let i = 0; i < 2500; i++) {
        logEvent('info', 'test', `line ${i}`, { blob })
      }
      for (let i = 0; i < 250 && (!existsSync(appLog) || statSync(appLog).size < 5 * 1024 * 1024); i++) {
        await flush()
      }

      // Rename failed, app.log exceeded 5 MB and prevLog is still a directory
      expect(existsSync(appLog)).toBe(true)
      expect(statSync(appLog).size).toBeGreaterThanOrEqual(5 * 1024 * 1024)
      expect(statSync(prevLog).isDirectory()).toBe(true)

      // Unblock: remove the directory so subsequent rename can succeed
      rmSync(prevLog, { recursive: true, force: true })

      // Write one single line. Because currentLogBytes retained the >= 5 MB stat,
      // this subsequent write must immediately re-attempt rotation and succeed.
      logEvent('info', 'test', 'retry line', { blob: 'small' })

      for (let i = 0; i < 250 && (!existsSync(prevLog) || statSync(appLog).size >= 5 * 1024 * 1024); i++) {
        await flush()
      }

      // Rotation has now succeeded: prevLog is a file (not dir) and appLog rolled
      expect(existsSync(prevLog)).toBe(true)
      expect(statSync(prevLog).isFile()).toBe(true)
      expect(statSync(appLog).size).toBeLessThan(5 * 1024 * 1024)
    } finally {
      logSpy.mockRestore()
    }
  }, 15000)
})
