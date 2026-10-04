// AT-01-001/010, F-001: unavailable secrets cannot trigger network rollback.
import { readFileSync } from 'fs'
import { join } from 'path'
import { beforeEach, describe, expect, it, vi } from 'vitest'
const reads = vi.hoisted(() => ({ settings: vi.fn(), profiles: vi.fn(), groups: vi.fn() }))
vi.mock('./settings', () => ({ settingsStore: { get: reads.settings } }))
vi.mock('./sharedStores', () => ({ serverPickerStore: { get: reads.profiles }, serverGroupsStore: { get: reads.groups } }))
import { readSecureStartupSettings, startupFailureDetail, handleSecureStartupBeforeQuit } from './secureStartup'
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
    expect(refusal).toContain("startupFailureDetail(error, 'secure-store-preflight')")
  })
  it.each([true, false])('uses the real quit guard: refused=%s', refused => {
    const markQuitting = vi.fn(), event = { preventDefault: vi.fn() }, cleanup = vi.fn()
    const beforeQuit = () => {
      if (handleSecureStartupBeforeQuit(refused, markQuitting)) return
      event.preventDefault()
      cleanup()
    }
    beforeQuit()
    expect(markQuitting).toHaveBeenCalledTimes(refused ? 1 : 0)
    expect(event.preventDefault).toHaveBeenCalledTimes(refused ? 0 : 1)
    expect(cleanup).toHaveBeenCalledTimes(refused ? 0 : 1)
  })
  it('wires the exported quit guard before ordinary shutdown in production', () => {
    const source = readFileSync(join(__dirname, 'index.ts'), 'utf8')
    const beforeQuit = source.indexOf("app.on('before-quit'")
    const guard = 'if (handleSecureStartupBeforeQuit(secureStartupRefused, () => { isQuitting = true })) return'
    const guardStart = source.indexOf(guard, beforeQuit)
    expect(guardStart).toBeGreaterThan(beforeQuit)
    expect(guardStart).toBeLessThan(source.indexOf('if (shutdownInProgress)', beforeQuit))
    expect(guardStart).toBeLessThan(source.indexOf('event.preventDefault()', beforeQuit))
    expect(guardStart).toBeLessThan(source.indexOf("await performShutdownCleanup('before-quit')", beforeQuit))
  })
  it.each(['secure-store-preflight', 'startup'] as const)('keeps %s failure details allowlisted without reading exception text', stage => {
    const error = new Error('FAKE-STARTUP-CREDENTIAL')
    for (const key of ['name', 'message', 'stack', 'code']) {
      Object.defineProperty(error, key, { get: () => { throw new Error('exception text must not be inspected') } })
    }
    expect(startupFailureDetail(error, stage)).toEqual({
      code: stage === 'startup' ? 'STARTUP_FAILED' : 'SECURE_STORE_PREFLIGHT_FAILED', type: 'Error'
    })
    expect(startupFailureDetail('FAKE-STARTUP-CREDENTIAL', stage).type).toBe('NonError')
  })
})
