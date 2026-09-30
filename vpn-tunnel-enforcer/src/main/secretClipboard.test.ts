// AT-01-008: process-owned clipboard timeout. Native Windows clipboard oracle remains L3.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
const state = vi.hoisted(() => ({ text: '', formats: ['text/plain'] }))
vi.mock('electron', () => ({ clipboard: {
  readText: vi.fn(() => state.text),
  writeText: vi.fn((text: string) => { state.text = text; state.formats = ['text/plain'] }),
  availableFormats: vi.fn(() => [...state.formats]),
  clear: vi.fn(() => { state.text = ''; state.formats = [] })
} }))
vi.mock('./appLogger', () => ({ logEvent: vi.fn() }))
import { clipboard } from 'electron'
import { copySecretToClipboard, clearOwnedSecretClipboard, SECRET_CLIPBOARD_TTL_MS } from './secretClipboard'
beforeEach(() => { vi.useFakeTimers(); vi.clearAllMocks(); state.text = ''; state.formats = ['text/plain'] })
afterEach(() => { clearOwnedSecretClipboard(); vi.useRealTimers() })
describe('main-owned secret clipboard', () => {
  it('writes in main, exposes only TTL metadata and clears after 60 seconds', async () => {
    const result = copySecretToClipboard('FAKE-VPN-SECRET')
    expect(result).toEqual({ clearAfterMs: 60_000 })
    expect(JSON.stringify(result)).not.toContain('FAKE')
    await vi.advanceTimersByTimeAsync(SECRET_CLIPBOARD_TTL_MS - 1)
    expect(state.text).toBe('FAKE-VPN-SECRET')
    await vi.advanceTimersByTimeAsync(1)
    expect(state.text).toBe(''); expect(clipboard.clear).toHaveBeenCalledTimes(1)
  })
  it('never destroys newer clipboard text', async () => {
    copySecretToClipboard('FAKE-VPN-SECRET'); state.text = 'user replacement'
    await vi.advanceTimersByTimeAsync(SECRET_CLIPBOARD_TTL_MS)
    expect(state.text).toBe('user replacement'); expect(clipboard.clear).not.toHaveBeenCalled()
  })
  it('preserves foreign formats even if the plain text matches', async () => {
    copySecretToClipboard('FAKE-VPN-SECRET'); state.formats = ['text/plain', 'text/html']
    await vi.advanceTimersByTimeAsync(SECRET_CLIPBOARD_TTL_MS)
    expect(clipboard.clear).not.toHaveBeenCalled()
  })
  it('replacing a copied key resets the deadline; old timer cannot clear new key', async () => {
    copySecretToClipboard('FAKE-OLD')
    await vi.advanceTimersByTimeAsync(30_000)
    copySecretToClipboard('FAKE-NEW')
    await vi.advanceTimersByTimeAsync(30_000)
    expect(state.text).toBe('FAKE-NEW')
    await vi.advanceTimersByTimeAsync(30_000)
    expect(state.text).toBe(''); expect(clipboard.clear).toHaveBeenCalledTimes(1)
  })
  it('clears synchronously on main shutdown and cancels the timer', async () => {
    copySecretToClipboard('FAKE-VPN-SECRET'); clearOwnedSecretClipboard()
    expect(state.text).toBe('')
    await vi.advanceTimersByTimeAsync(SECRET_CLIPBOARD_TTL_MS)
    expect(clipboard.clear).toHaveBeenCalledTimes(1)
  })
  it('retries a temporary native read failure without overwriting unknown contents', async () => {
    copySecretToClipboard('FAKE-VPN-SECRET')
    vi.mocked(clipboard.readText).mockImplementationOnce(() => { throw new Error('clipboard busy') })
    await vi.advanceTimersByTimeAsync(SECRET_CLIPBOARD_TTL_MS)
    expect(clipboard.clear).not.toHaveBeenCalled()
    await vi.advanceTimersByTimeAsync(5_000)
    expect(state.text).toBe('')
  })
  it('failed replacement writes retain the original cleanup deadline', async () => {
    copySecretToClipboard('FAKE-OLD')
    vi.mocked(clipboard.writeText).mockImplementationOnce(() => { throw new Error('clipboard busy') })
    expect(() => copySecretToClipboard('FAKE-NEW')).toThrow('clipboard busy')
    await vi.advanceTimersByTimeAsync(SECRET_CLIPBOARD_TTL_MS)
    expect(state.text).toBe('')
  })
})
