import { afterEach, describe, expect, it, vi } from 'vitest'
import { scheduleSecretClipboardCleanup } from './secretClipboard'

describe('secret clipboard cleanup (AT-01-008)', () => {
  afterEach(() => {
    vi.useRealTimers()
    vi.unstubAllGlobals()
  })

  it('clears only the unchanged exported secret', async () => {
    vi.useFakeTimers()
    const writeText = vi.fn().mockResolvedValue(undefined)
    vi.stubGlobal('navigator', {
      clipboard: {
        readText: vi.fn().mockResolvedValue('FAKE-SECRET'),
        writeText
      }
    })
    scheduleSecretClipboardCleanup('FAKE-SECRET', 100)
    await vi.advanceTimersByTimeAsync(100)
    expect(writeText).toHaveBeenCalledWith('')
  })

  it('does not destroy newer clipboard content', async () => {
    vi.useFakeTimers()
    const writeText = vi.fn().mockResolvedValue(undefined)
    vi.stubGlobal('navigator', {
      clipboard: {
        readText: vi.fn().mockResolvedValue('new user content'),
        writeText
      }
    })
    scheduleSecretClipboardCleanup('FAKE-SECRET', 100)
    await vi.advanceTimersByTimeAsync(100)
    expect(writeText).not.toHaveBeenCalled()
  })
})