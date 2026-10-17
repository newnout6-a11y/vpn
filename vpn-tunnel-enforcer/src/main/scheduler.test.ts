/**
 * Unit tests for scheduler pure functions.
 */

import { afterEach, beforeEach, describe, it, expect, vi } from 'vitest'
import { isScheduleActive, computeNextEvent, parseTimeToMinutes, schedulerService } from './scheduler'
import type { ScheduleEntry } from '../shared/ipc-types'

vi.mock('electron', () => ({ ipcMain: { handle: vi.fn() } }))
vi.mock('electron-store', () => ({
  default: class {
    private schedules: ScheduleEntry[] = []
    get() { return this.schedules }
    set(_key: string, schedules: ScheduleEntry[]) { this.schedules = schedules }
  }
}))

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

  it('returns the end of the combined window across overlapping schedules (AT-10-002)', () => {
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
    expect(result!.type).toBe('stop')
    expect(result!.schedule.id).toBe('s2')
    expect(result!.at).toBe(new Date(2024, 0, 10, 20).getTime())
  })
})

describe('merged schedule windows — AT-10-002 / F-123', () => {
  beforeEach(() => {
    vi.useFakeTimers()
    vi.setSystemTime(new Date(2024, 0, 10, 8, 59))
    for (const schedule of schedulerService.getSchedules()) schedulerService.deleteSchedule(schedule.id)
  })

  afterEach(() => {
    for (const schedule of schedulerService.getSchedules()) schedulerService.deleteSchedule(schedule.id)
    schedulerService.stop()
    vi.useRealTimers()
  })

  it.each([
    ['overlap', '09:30', '11:00'],
    ['adjacent', '10:00', '11:00'],
    ['same end', '09:30', '10:00'],
    ['nested', '09:15', '09:45']
  ])('connects once and stops only after the last %s window closes', (_kind, startTime, endTime) => {
    schedulerService.createSchedule(makeSchedule({ startTime: '09:00', endTime: '10:00' }))
    schedulerService.createSchedule(makeSchedule({ startTime, endTime }))
    const onConnect = vi.fn(), onDisconnect = vi.fn()
    schedulerService.init({ onConnect, onDisconnect })

    const endHour = endTime === '11:00' ? 11 : 10
    vi.advanceTimersByTime(new Date(2024, 0, 10, endHour).getTime() - Date.now() - 1)
    expect(onConnect).toHaveBeenCalledTimes(1)
    expect(onDisconnect).not.toHaveBeenCalled()
    vi.advanceTimersByTime(1)
    expect(onDisconnect).toHaveBeenCalledTimes(1)
  })

  it('keeps an overnight window active while the next day window still requires VPN', () => {
    const overnight = makeSchedule({ id: 'night', days: [3], startTime: '22:00', endTime: '06:00' })
    const morning = makeSchedule({ id: 'morning', days: [4], startTime: '05:00', endTime: '08:00' })
    for (const schedules of [[overnight, morning], [morning, overnight]]) {
      expect(computeNextEvent(schedules, new Date(2024, 0, 11, 2).getTime())).toMatchObject({
        type: 'stop', at: new Date(2024, 0, 11, 8).getTime(), schedule: { id: 'morning' }
      })
    }
  })

  it('does not merge a disabled window or a real gap between windows', () => {
    const first = makeSchedule({ startTime: '09:00', endTime: '10:00' })
    const disabled = makeSchedule({ enabled: false, startTime: '09:30', endTime: '12:00' })
    const later = makeSchedule({ startTime: '10:01', endTime: '11:00' })
    expect(computeNextEvent([first, disabled, later], new Date(2024, 0, 10, 9, 30).getTime())).toMatchObject({
      type: 'stop', at: new Date(2024, 0, 10, 10).getTime()
    })
    expect(computeNextEvent([first, disabled, later], new Date(2024, 0, 10, 10).getTime())).toMatchObject({
      type: 'start', at: new Date(2024, 0, 10, 10, 1).getTime()
    })
  })
})

describe('local DST boundaries — AT-10-001 / AT-10-002', () => {
  afterEach(() => {
    for (const schedule of schedulerService.getSchedules()) schedulerService.deleteSchedule(schedule.id)
    schedulerService.stop()
    vi.useRealTimers()
    vi.unstubAllEnvs()
  })

  it.each([
    ['America/New_York', '2024-03-10T01:00:00-05:00', '02:30', '2024-03-10T03:30:00-04:00', '2024-03-10T04:00:00-04:00'],
    ['Australia/Lord_Howe', '2024-10-06T01:00:00+10:30', '02:15', '2024-10-06T02:45:00+11:00', '2024-10-06T04:00:00+11:00'],
    ['America/New_York', '2024-11-03T00:00:00-04:00', '01:30', '2024-11-03T01:30:00-04:00', '2024-11-03T04:00:00-05:00']
  ])('preserves one start and the following stop in %s (%s)', (zone, before, startTime, start, stop) => {
    vi.stubEnv('TZ', zone)
    const schedule = makeSchedule({ days: [0], startTime, endTime: '04:00' })
    const startTs = Date.parse(start), stopTs = Date.parse(stop)
    // Verify that Node really uses the requested zone, independently of the host OS.
    expect(new Date(stopTs).getHours()).toBe(4)
    expect(computeNextEvent([schedule], Date.parse(before))).toMatchObject({ type: 'start', at: startTs })
    expect(isScheduleActive(schedule, startTs - 1)).toBe(false)
    expect(isScheduleActive(schedule, startTs)).toBe(true)
    expect(computeNextEvent([schedule], startTs)).toMatchObject({ type: 'stop', at: stopTs })
    expect(isScheduleActive(schedule, stopTs - 1)).toBe(true)
    expect(isScheduleActive(schedule, stopTs)).toBe(false)
  })

  it('does not reactivate a completed window in the second occurrence of a repeated hour', () => {
    vi.stubEnv('TZ', 'America/New_York')
    const schedule = makeSchedule({ days: [0], startTime: '01:15', endTime: '01:45' })
    expect(isScheduleActive(schedule, Date.parse('2024-11-03T01:30:00-04:00'))).toBe(true)
    expect(isScheduleActive(schedule, Date.parse('2024-11-03T01:30:00-05:00'))).toBe(false)
  })

  it('resolves an overnight end on its own calendar day after a DST gap', () => {
    vi.stubEnv('TZ', 'America/New_York')
    const schedule = makeSchedule({ days: [0], startTime: '22:00', endTime: '02:30' })
    expect(computeNextEvent([schedule], Date.parse('2024-03-10T23:00:00-04:00'))).toMatchObject({
      type: 'stop', at: Date.parse('2024-03-11T02:30:00-04:00')
    })
  })

  it('merges a normalized gap start into an already active window', () => {
    vi.stubEnv('TZ', 'America/New_York')
    const first = makeSchedule({ days: [0], startTime: '01:00', endTime: '03:45' })
    const second = makeSchedule({ days: [0], startTime: '02:30', endTime: '04:00' })
    expect(computeNextEvent([first, second], Date.parse('2024-03-10T01:30:00-05:00'))).toMatchObject({
      type: 'stop', at: Date.parse('2024-03-10T04:00:00-04:00')
    })
  })

  it('connects once at the normalized start and disconnects at the end', () => {
    vi.stubEnv('TZ', 'America/New_York')
    vi.useFakeTimers()
    vi.setSystemTime(new Date('2024-03-10T01:00:00-05:00'))
    schedulerService.createSchedule(makeSchedule({ days: [0], startTime: '02:30', endTime: '04:00' }))
    const onConnect = vi.fn(), onDisconnect = vi.fn()
    schedulerService.init({ onConnect, onDisconnect })
    expect(onConnect).not.toHaveBeenCalled()
    vi.advanceTimersByTime(Date.parse('2024-03-10T03:30:00-04:00') - Date.now())
    expect(onConnect).toHaveBeenCalledTimes(1)
    expect(onDisconnect).not.toHaveBeenCalled()
    vi.advanceTimersByTime(30 * 60 * 1000)
    expect(onConnect).toHaveBeenCalledTimes(1)
    expect(onDisconnect).toHaveBeenCalledTimes(1)
  })

  it('skips a window reversed by gap normalization instead of emitting a lone stop', () => {
    vi.stubEnv('TZ', 'America/New_York')
    const schedule = makeSchedule({ days: [0], startTime: '02:30', endTime: '03:00' })
    expect(isScheduleActive(schedule, Date.parse('2024-03-10T03:15:00-04:00'))).toBe(false)
    expect(computeNextEvent([schedule], Date.parse('2024-03-10T01:00:00-05:00'))).toMatchObject({
      type: 'start', at: Date.parse('2024-03-17T02:30:00-04:00')
    })
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

  // F-193: after midnight the window opened the previous day is still active; its stop must not be lost.
  it('finds the stop at 06:00 the same morning when the window opened yesterday', () => {
    const thu0200 = new Date(2024, 0, 11, 2, 0, 0).getTime() // Thu 02:00, window opened Wed 22:00
    const next = computeNextEvent([overnight], thu0200)
    expect(next?.type).toBe('stop')
    expect(new Date(next!.at).getDate()).toBe(11)
    expect(new Date(next!.at).getHours()).toBe(6)
  })

  it('after the morning stop the next event is the following start', () => {
    const thu0700 = new Date(2024, 0, 11, 7, 0, 0).getTime()
    const next = computeNextEvent([overnight], thu0700)
    expect(next?.type).toBe('start')
    expect(new Date(next!.at).getDate()).toBe(17) // next Wednesday
  })
})
