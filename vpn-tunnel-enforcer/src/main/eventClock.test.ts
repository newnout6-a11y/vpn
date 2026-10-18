// AT-00-005: timestamps keep elapsed ordering across Windows/NTP clock changes.
import { afterEach, expect, it, vi } from 'vitest'

afterEach(() => { vi.restoreAllMocks(); vi.resetModules() })

it('distinguishes a new clock origin after cold module initialization', async () => {
  const first = await import('./eventClock')
  vi.resetModules()
  const second = await import('./eventClock')
  expect(second.eventClockId).not.toBe(first.eventClockId)
})

it('keeps monotonic elapsed time independent of calendar dates across wall-clock jumps', async () => {
  const epoch = 1792368000000
  const wall = vi.spyOn(Date, 'now').mockReturnValue(epoch)
  const elapsed = vi.spyOn(process.hrtime, 'bigint').mockReturnValue(10_000_000n)
  const { monotonicTimeMs } = await import('./eventClock')
  expect(monotonicTimeMs()).toBe(0)
  elapsed.mockReturnValue(15_900_000n)
  wall.mockReturnValue(epoch - 3_600_000)
  expect(monotonicTimeMs()).toBe(5)
  elapsed.mockReturnValue(20_000_000n)
  wall.mockReturnValue(epoch + 86_400_000)
  expect(monotonicTimeMs()).toBe(10)
  expect(monotonicTimeMs()).toBe(10)
})
