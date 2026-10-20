// AT-00-004/005: locale-independent registry receipts, partial evidence and delivery.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { ipcError } from '../shared/ipc-result'
const state = vi.hoisted(() => ({ exec: vi.fn(), shown: 0, name: 'vpnte-legacy', requests: [] as Array<{ modelId: string; reset: boolean; script: string }> }))
vi.mock('electron', () => ({ app: { getName: () => state.name, getPath: () => '/tmp/vpnte-test' },
  Notification: Object.assign(class { show() { ++state.shown } }, { isSupported: () => true }) }))
vi.mock('child_process', () => {
  const execFile = vi.fn()
  Object.defineProperty(execFile, Symbol.for('nodejs.util.promisify.custom'), { value: (file: string, args: string[], options: unknown) => {
    expect(file).toBe('powershell.exe')
    expect(args.slice(0, 3)).toEqual(['-NoProfile', '-NonInteractive', '-EncodedCommand'])
    expect(options).toMatchObject({ windowsHide: true, timeout: 5000 })
    const script = Buffer.from(args[3], 'base64').toString('utf16le')
    const modelId = Buffer.from(script.match(/FromBase64String\('([^']+)'\)/)![1], 'base64').toString('utf8')
    const reset = script.includes('$reset = $true')
    state.requests.push({ modelId, reset, script })
    return state.exec(modelId, reset)
  } })
  return { execFile }
})
vi.mock('./settings', () => ({ settingsStore: { get: () => ({ desktopNotifications: true }) } }))
vi.mock('./appLogger', () => ({ logEvent: vi.fn() }))
const realPlatform = process.platform
const receipt = (value: number | null, cleared = false) => ({ stdout: JSON.stringify({ value, cleared }), stderr: '' })
beforeEach(() => {
  vi.resetModules(); state.exec.mockReset(); state.requests = []; state.shown = 0; state.name = 'vpnte-legacy'
  Object.defineProperty(process, 'platform', { value: 'win32', configurable: true })
})
afterEach(() => Object.defineProperty(process, 'platform', { value: realPlatform, configurable: true }))

describe('notification registry evidence', () => {
  it('clears only blocked values and retains explicit allow-state', async () => {
    state.exec.mockImplementation(async (id: string, reset: boolean) => receipt(id === 'vpnte-legacy' ? 0 : 1, reset && id === 'vpnte-legacy'))
    const { resetWindowsNotificationBlock } = await import('./notifications')
    expect(await resetWindowsNotificationBlock()).toEqual({ cleared: ['vpnte-legacy'], errors: [] })
    expect(state.requests).toHaveLength(2)
    for (const request of state.requests) {
      expect(request.reset).toBe(true)
      expect(request.script).toContain("$key.DeleteValue('Enabled', $false)")
      expect(request.script).toContain('$reset -and $value -eq 0')
      expect(request.script).not.toMatch(/DeleteSubKey|GetValueNames|reg delete|\/va/)
    }
  })
  it('accepts language-independent missing-value receipts without error text matching', async () => {
    state.exec.mockResolvedValue(receipt(null))
    const { getWindowsNotificationState, resetWindowsNotificationBlock } = await import('./notifications')
    expect(await getWindowsNotificationState()).toEqual({ enabled: true, appUserModelId: null })
    expect(await resetWindowsNotificationBlock()).toEqual({ cleared: [], errors: [] })
    expect(state.requests.every(item => item.script.includes('Microsoft.Win32.Registry'))).toBe(true)
  })
  it.each([
    ['permission', { category: 'permission', diagnostic: 'System.UnauthorizedAccessException', hresult: -2147024891 }],
    ['internal', { category: 'internal', diagnostic: 'System.IO.InvalidDataException', hresult: -2146233087 }]
  ])('maps .NET %s failures independently of Windows display language', async (category, result) => {
    state.exec.mockResolvedValue({ stdout: JSON.stringify(result), stderr: '' })
    const { getWindowsNotificationState, resetWindowsNotificationBlock } = await import('./notifications')
    await expect(getWindowsNotificationState()).rejects.toMatchObject({ category })
    const report = await resetWindowsNotificationBlock()
    expect(report.errors).toHaveLength(2)
    expect(report.errors[0].error).toEqual(ipcError(category as 'permission' | 'internal'))
  })
  it.each([
    ['permission', Object.assign(new Error('FAKE-SECRET'), { code: 'EACCES' })],
    ['timeout', Object.assign(new Error('FAKE-SECRET'), { code: 'ETIMEDOUT' })],
    ['timeout', Object.assign(new Error('FAKE-SECRET'), { killed: true, signal: 'SIGTERM' })],
    ['internal', new Error('FAKE-SECRET')]
  ])('preserves %s without false enabled state; explicit retry bypasses negative cache', async (category, error) => {
    state.exec.mockRejectedValue(error)
    const { getWindowsNotificationState } = await import('./notifications')
    await expect(getWindowsNotificationState()).rejects.toMatchObject({ category })
    state.exec.mockResolvedValue(receipt(0))
    await expect(getWindowsNotificationState()).rejects.toMatchObject({ category })
    expect(state.exec).toHaveBeenCalledOnce()
    expect(await getWindowsNotificationState(true)).toMatchObject({ enabled: false })
  })
  it.each(['bad JSON', '{}', '{"value":null,"cleared":true}', '{"value":"0","cleared":false}'])('rejects malformed receipts: %s', async stdout => {
    state.exec.mockResolvedValue({ stdout, stderr: '' })
    const { getWindowsNotificationState } = await import('./notifications')
    await expect(getWindowsNotificationState()).rejects.toMatchObject({ category: 'internal' })
  })
  it('preserves successful clears beside a typed per-AUMID failure', async () => {
    state.exec.mockImplementation(async (id: string) => {
      if (id === 'vpnte-legacy') throw Object.assign(new Error('FAKE-SECRET at /private/registry'), { code: 'EACCES' })
      return receipt(0, true)
    })
    const { resetWindowsNotificationBlock } = await import('./notifications')
    expect(await resetWindowsNotificationBlock()).toEqual({ cleared: ['com.vpntunnelenforcer.app'], errors: [{ appUserModelId: 'vpnte-legacy', error: ipcError('permission') }] })
  })
  it('fences invalidated in-flight reads and coalesces concurrent probes', async () => {
    let release!: (value: unknown) => void
    state.exec.mockReturnValueOnce(new Promise(resolve => { release = resolve }))
    const { getWindowsNotificationState, invalidateOsNotificationStateCache } = await import('./notifications')
    const first = getWindowsNotificationState(), second = getWindowsNotificationState()
    expect(state.exec).toHaveBeenCalledOnce()
    invalidateOsNotificationStateCache()
    release(receipt(0)); await Promise.all([first, second])
    state.exec.mockResolvedValue(receipt(1))
    expect(await getWindowsNotificationState()).toMatchObject({ enabled: true })
    expect(state.exec).toHaveBeenCalledTimes(2)
  })
  it('does not delay OS delivery or repeatedly probe/log while status fails', async () => {
    let reject!: (error: unknown) => void
    state.exec.mockReturnValueOnce(new Promise((_resolve, fail) => { reject = fail }))
    const { notify, getWindowsNotificationState, setInAppFallbackCallback } = await import('./notifications')
    const { logEvent } = await import('./appLogger')
    vi.mocked(logEvent).mockClear()
    const fallback = vi.fn(); setInAppFallbackCallback(fallback)
    await notify('error', 'First', 'Body')
    expect(state.shown).toBe(1); expect(fallback).toHaveBeenCalledOnce()
    const strict = getWindowsNotificationState()
    reject(new Error('read failed'))
    await expect(strict).rejects.toMatchObject({ category: 'internal' })
    await notify('warn', 'Second', 'Body')
    await notify('info', 'Third', 'Body')
    expect(state.shown).toBe(3); expect(fallback).toHaveBeenCalledTimes(3)
    expect(state.exec).toHaveBeenCalledOnce()
    expect(logEvent).toHaveBeenCalledTimes(1)
  })
  it('uses only fallback when a successful read proves an OS block', async () => {
    state.exec.mockResolvedValue(receipt(0))
    const { notify, getWindowsNotificationState, setInAppFallbackCallback } = await import('./notifications')
    await getWindowsNotificationState()
    const fallback = vi.fn(); setInAppFallbackCallback(fallback)
    await notify('error', 'Blocked', 'Body')
    expect(state.shown).toBe(0); expect(fallback).toHaveBeenCalledOnce()
  })
  it('encodes an AUMID without interpolating it as PowerShell source', async () => {
    state.name = "legacy'; throw 'untrusted"
    state.exec.mockResolvedValue(receipt(null))
    const { getWindowsNotificationState } = await import('./notifications')
    await getWindowsNotificationState()
    expect(state.requests[1].modelId).toBe(state.name)
    expect(state.requests[1].script).not.toContain(state.name)
  })
})
