// AT-01-009 / F-005/F-006: log cleanup cannot bootstrap or bless privileged runtime.
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'fs'
import { tmpdir } from 'os'
import { join } from 'path'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { shell } from 'electron'

let root: string
const acl = vi.hoisted(() => vi.fn())
const failFiles = vi.hoisted(() => new Set<string>())
vi.mock('fs/promises', async importOriginal => {
  const actual = await importOriginal<typeof import('fs/promises')>()
  const fail = (path: unknown) => { if (failFiles.has(String(path))) throw Object.assign(new Error('FAKE-SECRET at /private/log'), { code: 'EACCES' }) }
  return { ...actual, writeFile: async (...args: Parameters<typeof actual.writeFile>) => { fail(args[0]); return actual.writeFile(...args) },
    truncate: async (...args: Parameters<typeof actual.truncate>) => { fail(args[0]); return actual.truncate(...args) },
    unlink: async (...args: Parameters<typeof actual.unlink>) => { fail(args[0]); return actual.unlink(...args) } }
})
vi.mock('electron', () => ({ app: { getPath: () => join(root, 'user-data') }, shell: { openPath: vi.fn() } }))
vi.mock('./runtimePaths', () => ({ getPrivilegedRuntimeDir: () => join(root, 'program-data', 'instance', 'tun-runtime') }))
vi.mock('./runtimeDirSecurity', () => ({
  directoryExists: async (path: string) => existsSync(path),
  verifyDirectoryHardened: acl
}))
vi.mock('./vpnProfiles', () => ({ redactSensitiveConfig: (value: unknown) => value, redactSensitiveText: (value: string) => value }))

beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), 'vpnte-log-cleanup-'))
  acl.mockReset().mockResolvedValue({ hardened: true })
  failFiles.clear()
  vi.resetModules()
})
afterEach(async () => { const { flushAppLog } = await import('./appLogger'); await flushAppLog(); rmSync(root, { recursive: true, force: true }) })

describe('privileged TUN log cleanup', () => {
  it('persists the next failure event after rejected cleanup preflight (AT-00-005)', async () => {
    const runtime = join(root, 'program-data', 'instance', 'tun-runtime')
    mkdirSync(runtime, { recursive: true })
    acl.mockResolvedValueOnce({ hardened: false })
    const { clearAppLog, logEvent, flushAppLog, getAppLogPath } = await import('./appLogger')
    await expect(clearAppLog()).rejects.toMatchObject({ category: 'permission' })
    logEvent('error', 'diagnostics', 'cleanup preflight rejected', new Error('retained-preflight-stack'))
    await flushAppLog()
    const log = readFileSync(getAppLogPath(), 'utf8')
    expect(log).toContain('cleanup preflight rejected')
    expect(log).toContain('retained-preflight-stack')
  })
  it('reports absent files separately without inflating cleared counts (AT-00-004)', async () => {
    const { clearAppLog } = await import('./appLogger')
    expect(await clearAppLog()).toEqual({ success: true, cleared: [], absent: ['app-log', 'app-previous-log'], errors: [] })
  })
  it('keeps message and traceback for a per-file failure in the local log (AT-00-005)', async () => {
    const runtime = join(root, 'program-data', 'instance', 'tun-runtime')
    mkdirSync(runtime, { recursive: true }); writeFileSync(join(runtime, 'xray.log'), 'must survive')
    failFiles.add(join(runtime, 'xray.log'))
    const { clearAppLog, flushAppLog, getAppLogPath } = await import('./appLogger')
    await clearAppLog(); await flushAppLog()
    const log = readFileSync(getAppLogPath(), 'utf8')
    expect(log).toContain('log cleanup failed')
    expect(log).toContain('FAKE-SECRET')
    expect(log).toContain('stack')
    expect(log).toContain('appLoggerCleanup.test.ts')
  })
  it('rejects a shell refusal instead of reporting an opened folder (AT-00-004)', async () => {
    const { openLogFolder } = await import('./appLogger')
    vi.mocked(shell.openPath).mockResolvedValueOnce('FAKE-SECRET shell error')
    await expect(openLogFolder()).rejects.toThrow('FAKE-SECRET shell error')
    vi.mocked(shell.openPath).mockResolvedValueOnce('')
    await expect(openLogFolder()).resolves.toBe(join(root, 'user-data', 'logs'))
  })
  it('reports failed current and previous logs without hiding successful clears (AT-00-004)', async () => {
    const runtime = join(root, 'program-data', 'instance', 'tun-runtime')
    mkdirSync(runtime, { recursive: true })
    writeFileSync(join(runtime, 'sing-box.log'), 'retained')
    writeFileSync(join(runtime, 'xray.prev.log'), 'retained previous')
    failFiles.add(join(runtime, 'sing-box.log')); failFiles.add(join(runtime, 'xray.prev.log'))
    const { clearAppLog } = await import('./appLogger')
    const result = await clearAppLog()
    expect(result).toEqual({ success: false, cleared: [], absent: ['app-log', 'app-previous-log', 'sing-box-previous-log', 'xray-log',
      'xray-a-log', 'xray-a-previous-log', 'xray-b-log', 'xray-b-previous-log'],
      errors: [{ artifact: 'sing-box-log', error: expect.objectContaining({ category: 'permission', code: 'IPC_PERMISSION_DENIED' }) },
        { artifact: 'xray-previous-log', error: expect.objectContaining({ category: 'permission' }) }] })
    expect(JSON.stringify(result)).not.toMatch(/FAKE-SECRET|\/private\/|program-data/)
    expect(readFileSync(join(runtime, 'sing-box.log'), 'utf8')).toBe('retained')
    expect(readFileSync(join(runtime, 'xray.prev.log'), 'utf8')).toBe('retained previous')
    failFiles.clear()
    expect(await clearAppLog()).toMatchObject({ success: true, errors: [] })
  })
  it('clears app.log without creating any missing runtime namespace components', async () => {
    const { clearAppLog, getAppLogPath } = await import('./appLogger')
    await clearAppLog()
    expect(existsSync(getAppLogPath())).toBe(false)
    expect(existsSync(join(root, 'program-data'))).toBe(false)
    expect(acl).not.toHaveBeenCalled()
  })

  it('clears existing logs only after verifying the runtime', async () => {
    const runtime = join(root, 'program-data', 'instance', 'tun-runtime')
    mkdirSync(runtime, { recursive: true })
    writeFileSync(join(runtime, 'sing-box.log'), 'current')
    writeFileSync(join(runtime, 'sing-box.prev.log'), 'previous')
    writeFileSync(join(runtime, 'xray.log'), 'current xray')
    writeFileSync(join(runtime, 'xray.prev.log'), 'previous xray')
    for (const slot of ['a', 'b']) {
      writeFileSync(join(runtime, `xray-${slot}.log`), `current ${slot}`)
      writeFileSync(join(runtime, `xray-${slot}.prev.log`), `previous ${slot}`)
    }
    writeFileSync(join(runtime, 'xray-foreign.log'), 'unowned')
    const { clearAppLog, startEngineLogRetention } = await import('./appLogger')
    const stop = startEngineLogRetention()
    try {
      await clearAppLog()
      expect(acl).toHaveBeenCalledExactlyOnceWith(runtime)
      expect(readFileSync(join(runtime, 'sing-box.log'), 'utf8')).toBe('')
      expect(existsSync(join(runtime, 'sing-box.prev.log'))).toBe(false)
      expect(readFileSync(join(runtime, 'xray.log'), 'utf8')).toBe('')
      expect(existsSync(join(runtime, 'xray.prev.log'))).toBe(false)
      for (const slot of ['a', 'b']) {
        expect(readFileSync(join(runtime, `xray-${slot}.log`), 'utf8')).toBe('')
        expect(existsSync(join(runtime, `xray-${slot}.prev.log`))).toBe(false)
      }
      expect(readFileSync(join(runtime, 'xray-foreign.log'), 'utf8')).toBe('unowned')
    } finally { await stop() }
  })

  it('exports both fixed upstream slots through the existing redaction without admitting other files (AT-08-001 / AT-01-002)', async () => {
    const runtime = join(root, 'program-data', 'instance', 'tun-runtime')
    mkdirSync(runtime, { recursive: true })
    for (const slot of ['a', 'b']) for (const suffix of ['log', 'prev.log']) {
      writeFileSync(join(runtime, `xray-${slot}.${suffix}`), `slot ${slot} peer 203.0.113.9:443`)
    }
    writeFileSync(join(runtime, 'xray-foreign.log'), 'must not export')
    const { getFullLogs } = await import('./appLogger')
    const logs = await getFullLogs()
    const slots = logs.filter(log => /^xray-[ab]\.(?:prev\.)?log$/.test(log.name))
    expect(slots.map(log => log.name)).toEqual(['xray-a.log', 'xray-a.prev.log', 'xray-b.log', 'xray-b.prev.log'])
    for (const log of slots) {
      expect(log.exists).toBe(true)
      expect(log.content).toContain('slot')
      expect(log.content).not.toContain('203.0.113.9')
    }
    expect(logs.some(log => log.name === 'xray-foreign.log')).toBe(false)
  })

  it('reports an upstream slot clear failure without hiding its neighboring clear (AT-00-004 / AT-08-001)', async () => {
    const runtime = join(root, 'program-data', 'instance', 'tun-runtime')
    mkdirSync(runtime, { recursive: true })
    writeFileSync(join(runtime, 'xray-a.log'), 'retained')
    writeFileSync(join(runtime, 'xray-b.log'), 'cleared')
    failFiles.add(join(runtime, 'xray-a.log'))
    const { clearAppLog } = await import('./appLogger')
    const report = await clearAppLog()
    expect(report.success).toBe(false)
    expect(report.cleared).toContain('xray-b-log')
    expect(report.errors).toEqual([{ artifact: 'xray-a-log', error: expect.objectContaining({ category: 'permission' }) }])
    expect(JSON.stringify(report)).not.toMatch(/FAKE-SECRET|program-data/)
    expect(readFileSync(join(runtime, 'xray-a.log'), 'utf8')).toBe('retained')
    expect(readFileSync(join(runtime, 'xray-b.log'), 'utf8')).toBe('')
  })

  it('refuses untrusted runtime writes without poisoning a later cleanup attempt', async () => {
    const runtime = join(root, 'program-data', 'instance', 'tun-runtime')
    mkdirSync(runtime, { recursive: true })
    writeFileSync(join(runtime, 'sing-box.log'), 'must survive')
    writeFileSync(join(runtime, 'sing-box.prev.log'), 'must survive too')
    acl.mockResolvedValueOnce({ hardened: false })
    const { clearAppLog } = await import('./appLogger')
    await expect(clearAppLog()).rejects.toMatchObject({ category: 'permission' })
    expect(readFileSync(join(runtime, 'sing-box.log'), 'utf8')).toBe('must survive')
    expect(readFileSync(join(runtime, 'sing-box.prev.log'), 'utf8')).toBe('must survive too')
    await clearAppLog()
    expect(readFileSync(join(runtime, 'sing-box.log'), 'utf8')).toBe('')
  })
})
