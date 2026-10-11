// AT-03-003 / AT-03-007: in-process WinINet notification (koffi mocked, no real wininet.dll calls).
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
const k = vi.hoisted(() => ({
  results: [true, true] as boolean[], calls: [] as unknown[][], loadError: null as Error | null, loads: 0, funcArgs: null as unknown[] | null
}))
vi.mock('koffi', () => ({
  default: {
    load: (name: string) => {
      k.loads++
      if (k.loadError) throw k.loadError
      expect(name).toBe('wininet.dll')
      return { func: (...args: unknown[]) => { k.funcArgs = args; return (...call: unknown[]) => { k.calls.push(call); return k.results[(k.calls.length - 1) % 2] } } }
    }
  }
}))
import { notifyWinInetSettingsChangedNative, resetWinInetNativeForTests, WinInetCallError } from './winInet'
const platform = Object.getOwnPropertyDescriptor(process, 'platform')!
beforeEach(() => {
  k.results = [true, true]; k.calls = []; k.loadError = null; k.loads = 0; k.funcArgs = null
  resetWinInetNativeForTests()
  Object.defineProperty(process, 'platform', { configurable: true, value: 'win32' })
})
afterEach(() => Object.defineProperty(process, 'platform', platform))
describe('native WinINet notification', () => {
  it('calls InternetSetOptionW(39) then (37) and loads the binding once', async () => {
    await notifyWinInetSettingsChangedNative()
    await notifyWinInetSettingsChangedNative()
    expect(k.funcArgs).toEqual(['InternetSetOptionW', 'bool', ['void*', 'uint32', 'void*', 'uint32'], '__stdcall'])
    expect(k.calls.slice(0, 2)).toEqual([[null, 39, null, 0], [null, 37, null, 0]])
    expect(k.loads).toBe(1)
  })
  it('throws the settings-notification error when option 39 returns false and skips the refresh', async () => {
    k.results = [false, true]
    await expect(notifyWinInetSettingsChangedNative()).rejects.toThrow('WinINet settings notification failed')
    expect(k.calls).toHaveLength(1)
  })
  it('throws WinInetCallError with the refresh message when option 37 returns false', async () => {
    k.results = [true, false]
    const error = await notifyWinInetSettingsChangedNative().catch(e => e)
    expect(error).toBeInstanceOf(WinInetCallError)
    expect(error.message).toBe('WinINet refresh failed')
  })
  it('propagates a koffi load failure as a non-WinInetCallError and retries on the next call', async () => {
    k.loadError = new Error('koffi.node missing')
    const error = await notifyWinInetSettingsChangedNative().catch(e => e)
    expect(error.message).toBe('koffi.node missing')
    expect(error).not.toBeInstanceOf(WinInetCallError)
    k.loadError = null
    await expect(notifyWinInetSettingsChangedNative()).resolves.toBeUndefined()
    expect(k.loads).toBe(2)
  })
  it('rejects clearly on non-Windows without loading koffi', async () => {
    Object.defineProperty(process, 'platform', { configurable: true, value: 'linux' })
    await expect(notifyWinInetSettingsChangedNative()).rejects.toThrow('only available on Windows')
    expect(k.loads).toBe(0)
  })
})
