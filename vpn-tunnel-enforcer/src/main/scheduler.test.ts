/**
 * Unit tests for scheduler pure functions.
 */

import { describe, it, expect } from 'vitest'
import { isScheduleActive, computeNextEvent, parseTimeToMinutes } from './scheduler'
import type { ScheduleEntry } from '../shared/ipc-types'

// ─── Helper ──────────────────────────────────────────────────────────────────

function makeSchedule(overrides: Partial<ScheduleEntry> = {}): ScheduleEntry {
  return {
    id: 'test-1',
    name: 'Test Schedule',
    enabled: true,
    days: [1, 2, 3, 4, 5], // Mon-Fri
    startTime: '09:00',
    endTime: '17:00',
    profileId: 'profile-1',
    mode: 'hard',
    ...overrides
  }
}

// ─── parseTimeToMinutes ──────────────────────────────────────────────────────

describe('parseTimeToMinutes', () => {
  it('parses "00:00" to 0', () => {
    expect(parseTimeToMinutes('00:00')).toBe(0)
  })

  it('parses "09:30" to 570', () => {
    expect(parseTimeToMinutes('09:30')).toBe(570)
  })

  it('parses "23:59" to 1439', () => {
    expect(parseTimeToMinutes('23:59')).toBe(1439)
  })

  it('returns NaN for invalid input', () => {
    expect(parseTimeToMinutes('')).toBeNaN()
    expect(parseTimeToMinutes('abc')).toBeNaN()
    expect(parseTimeToMinutes('25:00')).toBeNaN()
    expect(parseTimeToMinutes('12:60')).toBeNaN()
  })
})

// ─── isScheduleActive ────────────────────────────────────────────────────────

describe('isScheduleActive', () => {
  it('returns true when timestamp is within schedule window', () => {
    // Wednesday 2024-01-10 at 12:00 UTC
    const wed12 = new Date(2024, 0, 10, 12, 0, 0).getTime()
    const schedule = makeSchedule({ days: [3], startTime: '09:00', endTime: '17:00' }) // Wed
    expect(isScheduleActive(schedule, wed12)).toBe(true)
  })

  it('returns false when day is not in schedule', () => {
    // Sunday 2024-01-07 at 12:00
    const sun12 = new Date(2024, 0, 7, 12, 0, 0).getTime()
    const schedule = makeSchedule({ days: [1, 2, 3, 4, 5] }) // Mon-Fri only
    expect(isScheduleActive(schedule, sun12)).toBe(false)
  })

  it('returns false when time is before startTime', () => {
    // Wednesday 2024-01-10 at 08:59
    const wed859 = new Date(2024, 0, 10, 8, 59, 0).getTime()
    const schedule = makeSchedule({ days: [3], startTime: '09:00', endTime: '17:00' })
    expect(isScheduleActive(schedule, wed859)).toBe(false)
  })

  it('returns true at exactly startTime (inclusive)', () => {
    // Wednesday 2024-01-10 at 09:00
    const wed900 = new Date(2024, 0, 10, 9, 0, 0).getTime()
    const schedule = makeSchedule({ days: [3], startTime: '09:00', endTime: '17:00' })
    expect(isScheduleActive(schedule, wed900)).toBe(true)
  })

  it('returns false at exactly endTime (exclusive)', () => {
    // Wednesday 2024-01-10 at 17:00
    const wed1700 = new Date(2024, 0, 10, 17, 0, 0).getTime()
    const schedule = makeSchedule({ days: [3], startTime: '09:00', endTime: '17:00' })
    expect(isScheduleActive(schedule, wed1700)).toBe(false)
  })

  it('returns false when schedule is disabled', () => {
    const wed12 = new Date(2024, 0, 10, 12, 0, 0).getTime()
    const schedule = makeSchedule({ days: [3], enabled: false })
    expect(isScheduleActive(schedule, wed12)).toBe(false)
  })

  it('returns false when days array is empty', () => {
    const wed12 = new Date(2024, 0, 10, 12, 0, 0).getTime()
    const schedule = makeSchedule({ days: [] })
    expect(isScheduleActive(schedule, wed12)).toBe(false)
  })
})

// ─── computeNextEvent ────────────────────────────────────────────────────────

describe('computeNextEvent', () => {
  it('returns null for empty schedules', () => {
    expect(computeNextEvent([], Date.now())).toBeNull()
  })

  it('returns null when all schedules are disabled', () => {
    const schedule = makeSchedule({ enabled: false })
    expect(computeNextEvent([schedule], Date.now())).toBeNull()
  })

  it('returns the nearest start event when before schedule window', () => {
    // Wednesday 2024-01-10 at 07:00 — before the 09:00 start
    const wed700 = new Date(2024, 0, 10, 7, 0, 0).getTime()
    const schedule = makeSchedule({ days: [3], startTime: '09:00', endTime: '17:00' })

    const result = computeNextEvent([schedule], wed700)
    expect(result).not.toBeNull()
    expect(result!.type).toBe('start')
    expect(result!.schedule.id).toBe(schedule.id)

    const expectedStart = new Date(2024, 0, 10, 9, 0, 0).getTime()
    expect(result!.at).toBe(expectedStart)
  })

  it('returns the nearest stop event when inside schedule window', () => {
    // Wednesday 2024-01-10 at 12:00 — inside the 09:00-17:00 window
    const wed1200 = new Date(2024, 0, 10, 12, 0, 0).getTime()
    const schedule = makeSchedule({ days: [3], startTime: '09:00', endTime: '17:00' })

    const result = computeNextEvent([schedule], wed1200)
    expect(result).not.toBeNull()
    expect(result!.type).toBe('stop')

    const expectedStop = new Date(2024, 0, 10, 17, 0, 0).getTime()
    expect(result!.at).toBe(expectedStop)
  })

  it('returns event strictly greater than now', () => {
    const now = Date.now()
    const schedule = makeSchedule({ days: [0, 1, 2, 3, 4, 5, 6], startTime: '00:00', endTime: '23:59' })

    const result = computeNextEvent([schedule], now)
    if (result) {
      expect(result.at).toBeGreaterThan(now)
    }
  })

  it('picks the chronologically nearest event across multiple schedules', () => {
    // Wednesday 2024-01-10 at 15:00
    const wed1500 = new Date(2024, 0, 10, 15, 0, 0).getTime()

    const schedule1 = makeSchedule({
      id: 's1',
      days: [3],
      startTime: '09:00',
      endTime: '17:00' // stop at 17:00
    })
    const schedule2 = makeSchedule({
      id: 's2',
      days: [3],
      startTime: '15:30',
      endTime: '20:00' // start at 15:30
    })

    const result = computeNextEvent([schedule1, schedule2], wed1500)
    expect(result).not.toBeNull()
    // 15:30 start is closer than 17:00 stop
    expect(result!.type).toBe('start')
    expect(result!.schedule.id).toBe('s2')
  })
})

// ─── Overnight windows (F2 regression) ──────────────────────────────────────

describe('isScheduleActive — overnight windows (start > end)', () => {
  // Window 22:00–06:00 listed on Wednesday (day 3). The window opened Wed 22:00
  // belongs to Wednesday and closes Thursday 06:00.
  const overnight = makeSchedule({ days: [3], startTime: '22:00', endTime: '06:00' })

  it('is active in the evening segment on the listed day', () => {
    const wed2300 = new Date(2024, 0, 10, 23, 0, 0).getTime() // Wed 23:00
    expect(isScheduleActive(overnight, wed2300)).toBe(true)
  })

  it('is active in the morning segment of the NEXT day', () => {
    const thu0500 = new Date(2024, 0, 11, 5, 0, 0).getTime() // Thu 05:00
    expect(isScheduleActive(overnight, thu0500)).toBe(true)
  })

  it('is inactive in the daytime gap', () => {
    const wed1200 = new Date(2024, 0, 10, 12, 0, 0).getTime() // Wed 12:00
    const thu1200 = new Date(2024, 0, 11, 12, 0, 0).getTime() // Thu 12:00
    expect(isScheduleActive(overnight, wed1200)).toBe(false)
    expect(isScheduleActive(overnight, thu1200)).toBe(false)
  })

  it('is inactive Thursday evening (Thursday is not a listed start day)', () => {
    const thu2300 = new Date(2024, 0, 11, 23, 0, 0).getTime() // Thu 23:00
    expect(isScheduleActive(overnight, thu2300)).toBe(false)
  })

  it('treats a zero-length window (start === end) as never active', () => {
    const zero = makeSchedule({ days: [3], startTime: '09:00', endTime: '09:00' })
    const wed900 = new Date(2024, 0, 10, 9, 0, 0).getTime()
    const wed1200 = new Date(2024, 0, 10, 12, 0, 0).getTime()
    expect(isScheduleActive(zero, wed900)).toBe(false)
    expect(isScheduleActive(zero, wed1200)).toBe(false)
  })
})

describe('computeNextEvent — overnight windows', () => {
  const overnight = makeSchedule({ days: [3], startTime: '22:00', endTime: '06:00' })

  it('finds the start at 22:00 on the listed day when before it', () => {
    const wed2000 = new Date(2024, 0, 10, 20, 0, 0).getTime() // Wed 20:00
    const next = computeNextEvent([overnight], wed2000)
    expect(next?.type).toBe('start')
    expect(new Date(next!.at).getHours()).toBe(22)
    expect(new Date(next!.at).getDate()).toBe(10) // same Wed
  })

  it('finds the stop on the NEXT day at 06:00 while inside the evening segment', () => {
    const wed2300 = new Date(2024, 0, 10, 23, 0, 0).getTime() // Wed 23:00, inside window
    const next = computeNextEvent([overnight], wed2300)
    expect(next?.type).toBe('stop')
    expect(new Date(next!.at).getHours()).toBe(6)
    expect(new Date(next!.at).getDate()).toBe(11) // Thursday
  })
})
