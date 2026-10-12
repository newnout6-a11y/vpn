// AT-03-003 / AT-03-007: the main-side WinINet notification keeps the two failure meanings apart across the host
// boundary: a genuine `false` stays authoritative (not retried through PowerShell), a host problem does not.
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { NativeHostError } from './hostProtocol'

const host = vi.hoisted(() => ({ call: vi.fn() }))
vi.mock('./nativeHost', () => ({ callNativeHost: host.call }))
import { notifyWinInetSettingsChangedNative, WinInetCallError } from './winInet'

beforeEach(() => { host.call.mockReset() })

describe('notifyWinInetSettingsChangedNative', () => {
  it('resolves when the host reports success', async () => {
    host.call.mockResolvedValue(true)
    await expect(notifyWinInetSettingsChangedNative()).resolves.toBeUndefined()
    expect(host.call).toHaveBeenCalledWith('wininet')
  })

  it('re-throws a WinINet false as WinInetCallError (authoritative)', async () => {
    host.call.mockImplementation(async () => { throw new NativeHostError('wininet-false', 'WinINet refresh failed') })
    const error = await notifyWinInetSettingsChangedNative().catch(e => e)
    expect(error).toBeInstanceOf(WinInetCallError)
    expect(error.message).toBe('WinINet refresh failed')
  })

  it.each(['unavailable', 'read-refused'] as const)('lets a %s host failure through so the caller falls back to PowerShell', async kind => {
    host.call.mockImplementation(async () => { throw new NativeHostError(kind, 'host problem') })
    const error = await notifyWinInetSettingsChangedNative().catch(e => e)
    expect(error).toBeInstanceOf(NativeHostError)
    expect(error).not.toBeInstanceOf(WinInetCallError)
  })
})
