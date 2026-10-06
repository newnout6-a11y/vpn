// AT-01-009 / F-005/F-006: log cleanup cannot bootstrap or bless privileged runtime.
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'fs'
import { tmpdir } from 'os'
import { join } from 'path'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

let root: string
const acl = vi.hoisted(() => vi.fn())
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
  vi.resetModules()
})
afterEach(() => rmSync(root, { recursive: true, force: true }))

describe('privileged TUN log cleanup', () => {
  it('clears app.log without creating any missing runtime namespace components', async () => {
    const { clearAppLog, getAppLogPath } = await import('./appLogger')
    await clearAppLog()
    expect(readFileSync(getAppLogPath(), 'utf8')).toBe('')
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
    const { clearAppLog, startEngineLogRetention } = await import('./appLogger')
    const stop = startEngineLogRetention()
    try {
      await clearAppLog()
      expect(acl).toHaveBeenCalledExactlyOnceWith(runtime)
      expect(readFileSync(join(runtime, 'sing-box.log'), 'utf8')).toBe('')
      expect(existsSync(join(runtime, 'sing-box.prev.log'))).toBe(false)
      expect(readFileSync(join(runtime, 'xray.log'), 'utf8')).toBe('')
      expect(existsSync(join(runtime, 'xray.prev.log'))).toBe(false)
    } finally { await stop() }
  })

  it('refuses untrusted runtime writes without poisoning a later cleanup attempt', async () => {
    const runtime = join(root, 'program-data', 'instance', 'tun-runtime')
    mkdirSync(runtime, { recursive: true })
    writeFileSync(join(runtime, 'sing-box.log'), 'must survive')
    writeFileSync(join(runtime, 'sing-box.prev.log'), 'must survive too')
    acl.mockResolvedValueOnce({ hardened: false })
    const { clearAppLog } = await import('./appLogger')
    await expect(clearAppLog()).rejects.toThrow('RuntimeSecurityAclError')
    expect(readFileSync(join(runtime, 'sing-box.log'), 'utf8')).toBe('must survive')
    expect(readFileSync(join(runtime, 'sing-box.prev.log'), 'utf8')).toBe('must survive too')
    await clearAppLog()
    expect(readFileSync(join(runtime, 'sing-box.log'), 'utf8')).toBe('')
  })
})
