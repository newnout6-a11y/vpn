// AT-01-001/010, F-001: unavailable secrets cannot trigger network rollback.
import { readFileSync } from 'fs'
import { join } from 'path'
import { beforeEach, describe, expect, it, vi } from 'vitest'
const reads = vi.hoisted(() => ({ settings: vi.fn(), profiles: vi.fn(), groups: vi.fn() }))
vi.mock('./settings', () => ({ settingsStore: { get: reads.settings } }))
vi.mock('./sharedStores', () => ({ serverPickerStore: { get: reads.profiles }, serverGroupsStore: { get: reads.groups } }))
import { readSecureStartupSettings } from './secureStartup'
beforeEach(() => {
  reads.settings.mockReset().mockReturnValue({ mode: 'hard' })
  reads.profiles.mockReset().mockReturnValue([])
  reads.groups.mockReset().mockReturnValue([])
})
describe('secure startup preflight', () => {
  it('opens settings, profiles and groups in order before returning settings', () => {
    expect(readSecureStartupSettings()).toEqual({ mode: 'hard' })
    expect(reads.profiles).toHaveBeenCalledWith('profiles')
    expect(reads.groups).toHaveBeenCalledWith('groups')
    expect(reads.settings.mock.invocationCallOrder[0]).toBeLessThan(reads.profiles.mock.invocationCallOrder[0])
    expect(reads.profiles.mock.invocationCallOrder[0]).toBeLessThan(reads.groups.mock.invocationCallOrder[0])
  })
  it.each(['settings', 'profiles', 'groups'] as const)('propagates a %s failure without substituting empty stores', store => {
    const error = new Error('Secure storage unavailable')
    reads[store].mockImplementation(() => { throw error })
    expect(readSecureStartupSettings).toThrow(error)
    if (store === 'settings') expect(reads.profiles).not.toHaveBeenCalled()
    if (store !== 'groups') expect(reads.groups).not.toHaveBeenCalled()
  })
  it('routes a failed preflight to graceful quit before login-item, helpers, recovery and renderer effects', () => {
    const source = readFileSync(join(__dirname, 'index.ts'), 'utf8')
    const start = source.indexOf('try { initialSettings = readSecureStartupSettings() }')
    const end = source.indexOf('settingsStore.syncLoginItem()', start)
    expect(start).toBeGreaterThan(0)
    const refusal = source.slice(start, end)
    expect(refusal).toContain('secureStartupRefused = true')
    expect(refusal).toContain('app.quit()')
    expect(refusal).not.toContain('app.exit(1)')
    expect(refusal).not.toContain('performShutdownCleanup')
    for (const effect of ['startElevatedPsHelper()', 'await performCrashRecovery()', 'createWindow()']) {
      expect(source.indexOf(effect, start)).toBeGreaterThan(end)
    }
    expect(refusal).toContain('protection\', error)')
  })
  it('allows Electron to flush key state without invoking ordinary shutdown on a secure-store refusal', () => {
    const source = readFileSync(join(__dirname, 'index.ts'), 'utf8')
    const beforeQuit = source.indexOf("app.on('before-quit'")
    const guardStart = source.indexOf('if (secureStartupRefused)', beforeQuit)
    const normalStart = source.indexOf('if (shutdownInProgress)', beforeQuit)
    expect(guardStart).toBeGreaterThan(beforeQuit)
    expect(guardStart).toBeLessThan(normalStart)
    const run = new Function('secureStartupRefused', 'event', 'cleanup', `let isQuitting = false; ${source.slice(guardStart, normalStart)} cleanup()`)
    const event = { preventDefault: vi.fn() }, cleanup = vi.fn()
    run(true, event, cleanup)
    expect(cleanup).not.toHaveBeenCalled()
    expect(event.preventDefault).not.toHaveBeenCalled()
    run(false, event, cleanup)
    expect(cleanup).toHaveBeenCalledOnce()
  })
})
