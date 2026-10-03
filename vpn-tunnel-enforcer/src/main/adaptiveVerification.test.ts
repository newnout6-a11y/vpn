import { afterEach, describe, expect, it, vi } from 'vitest'
import { collectAdaptiveSamples } from './adaptiveVerification'

afterEach(() => { vi.useRealTimers() })
describe('adaptive sample ownership (AT-10-003 / AT-10-006)', () => {
  it('cancels the stability window immediately without probing', async () => {
    vi.useFakeTimers()
    const controller = new AbortController(), probe = vi.fn()
    const pending = collectAdaptiveSamples(() => true, controller.signal, probe)
    controller.abort()
    expect(await pending).toBeNull()
    expect(probe).not.toHaveBeenCalled()
    expect(vi.getTimerCount()).toBe(0)
  })
  it.each([1, 2, 3])('discards cancellation during probe %s and never probes the next server', async count => {
    vi.useFakeTimers()
    const controller = new AbortController()
    let current = true
    const probe = vi.fn(async () => {
      if (probe.mock.calls.length === count) { current = false; controller.abort() }
      return 10
    })
    const pending = collectAdaptiveSamples(() => current, controller.signal, probe)
    await vi.runAllTimersAsync()
    expect(await pending).toBeNull()
    expect(probe).toHaveBeenCalledTimes(count)
  })
  it('discards a late failure from the old profile without an abort-aware provider', async () => {
    vi.useFakeTimers()
    const controller = new AbortController()
    let current = true, complete!: (value: null) => void
    const probe = vi.fn(() => new Promise<null>(resolve => { complete = resolve }))
    const pending = collectAdaptiveSamples(() => current, controller.signal, probe)
    await vi.advanceTimersByTimeAsync(20_000)
    current = false
    complete(null)
    expect(await pending).toBeNull()
    expect(probe).toHaveBeenCalledOnce()
  })
  it('retains 2-of-3 successful observations for the current profile', async () => {
    vi.useFakeTimers()
    const probe = vi.fn().mockResolvedValueOnce(10).mockResolvedValueOnce(null).mockResolvedValueOnce(20)
    const pending = collectAdaptiveSamples(() => true, new AbortController().signal, probe)
    await vi.runAllTimersAsync()
    expect(await pending).toEqual([10, 20])
    expect(probe).toHaveBeenCalledTimes(3)
  })
})
