// AT-00-005: calendar corrections do not distort duration used by stats/UI.
import { expect, it } from 'vitest'
import { connectionDurationMs } from './connection-history'

it('uses captured duration for corrected calendar dates and a safe legacy fallback', () => {
  expect(connectionDurationMs({ startedAt: 10000, endedAt: 100, durationMs: 2500 })).toBe(2500)
  expect(connectionDurationMs({ startedAt: 100, endedAt: 10000, durationMs: 0 })).toBe(0)
  expect(connectionDurationMs({ startedAt: 100, endedAt: 2100 })).toBe(2000)
  expect(connectionDurationMs({ startedAt: 2100, endedAt: 100 })).toBe(0)
  expect(connectionDurationMs({ startedAt: 100, endedAt: null, durationMs: 2500 })).toBe(0)
})
