// AT-01-008: process-owned clipboard timeout. Native Windows clipboard oracle remains L3.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
const state = vi.hoisted(() => ({ text: '', formats: ['text/plain'] }))
vi.mock('electron', () => ({ clipboard: {
  readText: vi.fn(async () => state.text),
  writeText: vi.fn(async (text: string) => { state.text = text; state.formats = ['text/plain'] }),
  read: vi.fn(async () => [{ types: [...state.formats] }]),
  clear: vi.fn(() => { state.text = ''; state.formats = [] })
} }))
vi.mock('./appLogger', () => ({ logEvent: vi.fn() }))
import { clipboard } from 'electron'
import { copySecretToClipboard, clearOwnedSecretClipboard, SECRET_CLIPBOARD_TTL_MS } from './secretClipboard'
beforeEach(() => { vi.useFakeTimers(); vi.clearAllMocks(); state.text = ''; state.formats = ['text/plain'] })
afterEach(async () => { await clearOwnedSecretClipboard(); vi.useRealTimers() })
describe('main-owned secret clipboard', () => {
  it('writes in main, exposes only TTL metadata and clears after 60 seconds', async () => {
    const result = await copySecretToClipboard('FAKE-VPN-SECRET')
    expect(result).toEqual({ clearAfterMs: 60_000 })
    expect(JSON.stringify(result)).not.toContain('FAKE')
    await vi.advanceTimersByTimeAsync(SECRET_CLIPBOARD_TTL_MS - 1)
    expect(state.text).toBe('FAKE-VPN-SECRET')
    await vi.advanceTimersByTimeAsync(1)
    expect(state.text).toBe(''); expect(clipboard.clear).toHaveBeenCalledTimes(1)
  })
  it('never destroys newer clipboard text', async () => {
    await copySecretToClipboard('FAKE-VPN-SECRET'); state.text = 'user replacement'
    await vi.advanceTimersByTimeAsync(SECRET_CLIPBOARD_TTL_MS)
    expect(state.text).toBe('user replacement'); expect(clipboard.clear).not.toHaveBeenCalled()
  })
  it('preserves foreign formats even if the plain text matches', async () => {
    await copySecretToClipboard('FAKE-VPN-SECRET'); state.formats = ['text/plain', 'text/html']
    await vi.advanceTimersByTimeAsync(SECRET_CLIPBOARD_TTL_MS)
    expect(clipboard.clear).not.toHaveBeenCalled()
  })
  it('replacing a copied key resets the deadline; old timer cannot clear new key', async () => {
    await copySecretToClipboard('FAKE-OLD')
    await vi.advanceTimersByTimeAsync(30_000)
    await copySecretToClipboard('FAKE-NEW')
    await vi.advanceTimersByTimeAsync(30_000)
    expect(state.text).toBe('FAKE-NEW')
    await vi.advanceTimersByTimeAsync(30_000)
    expect(state.text).toBe(''); expect(clipboard.clear).toHaveBeenCalledTimes(1)
  })
  it('awaits native reads on main shutdown and cancels the timer', async () => {
    await copySecretToClipboard('FAKE-VPN-SECRET'); await clearOwnedSecretClipboard()
    expect(state.text).toBe('')
    await vi.advanceTimersByTimeAsync(SECRET_CLIPBOARD_TTL_MS)
    expect(clipboard.clear).toHaveBeenCalledTimes(1)
  })
  it('retries a temporary native read failure without overwriting unknown contents', async () => {
    await copySecretToClipboard('FAKE-VPN-SECRET')
    vi.mocked(clipboard.readText).mockRejectedValueOnce(new Error('clipboard busy'))
    await vi.advanceTimersByTimeAsync(SECRET_CLIPBOARD_TTL_MS)
    expect(clipboard.clear).not.toHaveBeenCalled()
    await vi.advanceTimersByTimeAsync(5_000)
    expect(state.text).toBe('')
  })
  it('failed replacement writes retain the original cleanup deadline', async () => {
    await copySecretToClipboard('FAKE-OLD')
    vi.mocked(clipboard.writeText).mockRejectedValueOnce(new Error('clipboard busy'))
    await expect(copySecretToClipboard('FAKE-NEW')).rejects.toThrow('clipboard busy')
    await vi.advanceTimersByTimeAsync(SECRET_CLIPBOARD_TTL_MS)
    expect(state.text).toBe('')
  })
  it('acknowledges a copy only after the native write resolves', async () => {
    let complete!: () => void
    vi.mocked(clipboard.writeText).mockImplementationOnce(text => new Promise(resolve => {
      complete = () => { state.text = text; resolve() }
    }))
    const acknowledgement = vi.fn()
    const pendingCopy = copySecretToClipboard('FAKE-DELAYED').then(acknowledgement)
    await Promise.resolve()
    expect(acknowledgement).not.toHaveBeenCalled()
    complete(); await pendingCopy
    expect(acknowledgement).toHaveBeenCalledWith({ clearAfterMs: 60_000 })
  })
  it('serializes a replacement behind in-flight cleanup and retains its new deadline', async () => {
    await copySecretToClipboard('FAKE-OLD')
    let read!: (text: string) => void
    vi.mocked(clipboard.readText).mockImplementationOnce(() => new Promise(resolve => { read = resolve }))
    const cleanup = clearOwnedSecretClipboard()
    await Promise.resolve()
    const replacement = copySecretToClipboard('FAKE-NEW')
    read('FAKE-OLD'); await cleanup; await replacement
    expect(state.text).toBe('FAKE-NEW')
    await vi.advanceTimersByTimeAsync(SECRET_CLIPBOARD_TTL_MS)
    expect(state.text).toBe('')
  })
  it('preserves text replaced while async format discovery was pending', async () => {
    await copySecretToClipboard('FAKE-OLD')
    vi.mocked(clipboard.read).mockImplementationOnce(async () => {
      state.text = 'user replacement'
      return [{ types: ['text/plain'] }] as Electron.ClipboardItem[]
    })
    await clearOwnedSecretClipboard()
    expect(state.text).toBe('user replacement')
    expect(clipboard.clear).not.toHaveBeenCalled()
  })
  it('an old deadline firing during a delayed replacement cannot clear the new key', async () => {
    await copySecretToClipboard('FAKE-OLD')
    await vi.advanceTimersByTimeAsync(SECRET_CLIPBOARD_TTL_MS - 1_000)
    let complete!: () => void
    vi.mocked(clipboard.writeText).mockImplementationOnce(text => new Promise(resolve => {
      complete = () => { state.text = text; resolve() }
    }))
    const replacement = copySecretToClipboard('FAKE-NEW')
    await Promise.resolve()
    await vi.advanceTimersByTimeAsync(2_000)
    complete(); await replacement
    await vi.advanceTimersByTimeAsync(0)
    expect(state.text).toBe('FAKE-NEW')
    expect(clipboard.clear).not.toHaveBeenCalled()
    await vi.advanceTimersByTimeAsync(SECRET_CLIPBOARD_TTL_MS)
    expect(state.text).toBe('')
  })
  it('never clears when initial format ownership cannot be established', async () => {
    vi.mocked(clipboard.read).mockRejectedValueOnce(new Error('clipboard busy'))
    await copySecretToClipboard('FAKE-OLD')
    await vi.advanceTimersByTimeAsync(SECRET_CLIPBOARD_TTL_MS)
    expect(clipboard.clear).not.toHaveBeenCalled()
  })
  it('retries rejected native format reads during cleanup', async () => {
    await copySecretToClipboard('FAKE-OLD')
    vi.mocked(clipboard.read).mockRejectedValueOnce(new Error('clipboard busy'))
    await vi.advanceTimersByTimeAsync(SECRET_CLIPBOARD_TTL_MS)
    expect(state.text).toBe('FAKE-OLD')
    await vi.advanceTimersByTimeAsync(5_000)
    expect(state.text).toBe('')
  })
})
