// AT-00-005: timestamps keep elapsed ordering across Windows/NTP clock changes.
import { afterEach, expect, it, vi } from 'vitest'

afterEach(() => { vi.restoreAllMocks(); vi.resetModules() })

it('anchors event time once and follows monotonic elapsed time across wall-clock jumps', async () => {
  const epoch = 1792368000000
  const wall = vi.spyOn(Date, 'now').mockReturnValue(epoch)
  const elapsed = vi.spyOn(process.hrtime, 'bigint').mockReturnValue(10_000_000n)
  const { eventTimestamp } = await import('./eventClock')
  expect(eventTimestamp()).toBe(epoch)
  elapsed.mockReturnValue(15_900_000n)
  wall.mockReturnValue(epoch - 3_600_000)
  expect(eventTimestamp()).toBe(epoch + 5)
  elapsed.mockReturnValue(20_000_000n)
  wall.mockReturnValue(epoch + 86_400_000)
  expect(eventTimestamp()).toBe(epoch + 10)
  expect(eventTimestamp()).toBe(epoch + 10)
})
