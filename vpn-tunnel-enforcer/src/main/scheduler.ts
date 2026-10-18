/**
 * Scheduler Service — main process module for scheduled VPN connect/disconnect.
 *
 * Responsibilities:
 * - CRUD operations for schedule entries (stored in electron-store)
 * - Determine if a schedule is currently active (day-of-week + time range)
 * - Compute the next scheduled start/stop event
 * - Timer management: set a timer for the next event, connect/disconnect VPN when it fires
 * - Handle app restart during an active schedule window (connect immediately)
 * - Register IPC handlers for all SchedulerChannels
 *
 * Pure functions exported for property testing:
 * - isScheduleActive(schedule, timestamp)
 * - computeNextEvent(schedules, now)
 */

import { ipcMain } from 'electron'
import Store from 'electron-store'
import { randomUUID } from 'crypto'
import type { ScheduleEntry, ScheduleNextEvent as NextEvent } from '../shared/ipc-types'
export type { ScheduleNextEvent as NextEvent } from '../shared/ipc-types'

// ─── Types ───────────────────────────────────────────────────────────────────

// ─── Store ───────────────────────────────────────────────────────────────────

interface SchedulerStoreSchema {
  schedules: ScheduleEntry[]
}

const schedulerStore = new Store<SchedulerStoreSchema>({
  name: 'scheduler',
  defaults: {
    schedules: []
  }
})

// ─── Pure Functions (exported for property testing) ──────────────────────────

/**
 * Parse "HH:mm" string into total minutes since midnight.
 * Returns NaN for invalid input.
 */
export function parseTimeToMinutes(time: string): number {
  if (!time || typeof time !== 'string') return NaN
  const parts = time.split(':')
  if (parts.length !== 2) return NaN
  const hours = parseInt(parts[0], 10)
  const minutes = parseInt(parts[1], 10)
  if (isNaN(hours) || isNaN(minutes)) return NaN
  if (hours < 0 || hours > 23 || minutes < 0 || minutes > 59) return NaN
  return hours * 60 + minutes
}

interface ScheduleWindow {
  start: number
  stop: number
  schedule: ScheduleEntry
}

/**
 * Resolve both boundaries on their own local calendar day using Date's compatible
 * DST policy: shift missing times forward by the gap; choose the earlier instant
 * for repeated times. Skip windows collapsed/reversed by that normalization.
 * The same concrete intervals drive restart detection and scheduled events.
 */
function scheduleWindows(schedule: ScheduleEntry, now: number, daysAhead = 0): ScheduleWindow[] {
  if (!schedule.enabled || !Array.isArray(schedule.days) || schedule.days.length === 0) return []
  const start = parseTimeToMinutes(schedule.startTime)
  const end = parseTimeToMinutes(schedule.endTime)
  if (isNaN(start) || isNaN(end) || start === end) return []

  const date = new Date(now)
  const year = date.getFullYear(), month = date.getMonth(), day = date.getDate()
  const windows: ScheduleWindow[] = []
  // Yesterday is needed for overnight windows still active this morning (F-193).
  for (let offset = -1; offset <= daysAhead; offset++) {
    const calendarDay = new Date(year, month, day + offset)
    if (!schedule.days.includes(calendarDay.getDay())) continue
    const startTs = new Date(year, month, day + offset, Math.floor(start / 60), start % 60).getTime()
    const stopTs = new Date(year, month, day + offset + (start > end ? 1 : 0), Math.floor(end / 60), end % 60).getTime()
    if (stopTs > startTs) windows.push({ start: startTs, stop: stopTs, schedule })
  }
  return windows
}

/** Active inside a resolved local [start, stop) interval, including overnight. */
export function isScheduleActive(schedule: ScheduleEntry, timestamp: number): boolean {
  return scheduleWindows(schedule, timestamp).some((window) => window.start <= timestamp && timestamp < window.stop)
}

/**
 * Return the next boundary of the union of enabled local schedule windows.
 * Overlapping/adjacent windows connect once and stop only at the final end.
 */
export function computeNextEvent(schedules: ScheduleEntry[], now: number): NextEvent | null {
  // Include a look-ahead day so truncation cannot create a spurious stop at the
  // weekly search horizon when another window continues protection beyond it.
  const windows = schedules.flatMap((schedule) => scheduleWindows(schedule, now, 8))
    .sort((a, b) => a.start - b.start)
  const date = new Date(now)
  const horizon = new Date(date.getFullYear(), date.getMonth(), date.getDate() + 8).getTime()

  for (let i = 0; i < windows.length; i++) {
    const first = windows[i]
    let last = first
    while (i + 1 < windows.length && windows[i + 1].start <= last.stop) {
      const next = windows[++i]
      if (next.stop > last.stop) last = next
    }
    if (first.start > now && first.start < horizon) {
      return { type: 'start', at: first.start, schedule: first.schedule }
    }
    if (last.stop > now && last.stop < horizon) {
      return { type: 'stop', at: last.stop, schedule: last.schedule }
    }
  }
  return null
}

// ─── Timer Management ────────────────────────────────────────────────────────

let currentTimer: ReturnType<typeof setTimeout> | null = null
let vpnConnectCallback: ((schedule: ScheduleEntry) => void) | null = null
let vpnDisconnectCallback: ((schedule: ScheduleEntry) => void) | null = null

function clearSchedulerTimer(): void {
  if (currentTimer !== null) {
    clearTimeout(currentTimer)
    currentTimer = null
  }
}

function scheduleNextTimer(): void {
  clearSchedulerTimer()

  const schedules = schedulerStore.get('schedules')
  const now = Date.now()
  const next = computeNextEvent(schedules, now)

  if (!next) return

  const delay = Math.max(0, next.at - now)

  // Cap timer at 24 hours to avoid overflow issues with setTimeout
  const maxDelay = 24 * 60 * 60 * 1000
  const actualDelay = Math.min(delay, maxDelay)

  currentTimer = setTimeout(() => {
    if (delay > maxDelay) {
      // Re-schedule if the event is more than 24h away
      scheduleNextTimer()
      return
    }

    if (next.type === 'start' && vpnConnectCallback) {
      vpnConnectCallback(next.schedule)
    } else if (next.type === 'stop' && vpnDisconnectCallback) {
      vpnDisconnectCallback(next.schedule)
    }

    // Schedule the next event after this one fires
    scheduleNextTimer()
  }, actualDelay)
}

// ─── CRUD Operations ─────────────────────────────────────────────────────────

function getSchedules(): ScheduleEntry[] {
  const stored = schedulerStore.get('schedules')
  if (!Array.isArray(stored)) return []
  return stored
}

function createSchedule(entry: Omit<ScheduleEntry, 'id'>): ScheduleEntry {
  validateSchedule(entry)
  const newEntry: ScheduleEntry = {
    ...entry,
    id: randomUUID()
  }
  const schedules = getSchedules()
  schedules.push(newEntry)
  schedulerStore.set('schedules', schedules)
  scheduleNextTimer()
  return newEntry
}

function updateSchedule(id: string, patch: Partial<ScheduleEntry>): ScheduleEntry {
  const schedules = getSchedules()
  const index = schedules.findIndex((s) => s.id === id)
  if (index === -1) {
    throw new Error(`Schedule not found: ${id}`)
  }

  const updated: ScheduleEntry = { ...schedules[index], ...patch, id } // id cannot be changed
  validateSchedule(updated)
  schedules[index] = updated
  schedulerStore.set('schedules', schedules)
  scheduleNextTimer()
  return updated
}

function validateSchedule(entry: Omit<ScheduleEntry, 'id'> | ScheduleEntry): void {
  if (!entry || typeof entry.name !== 'string' || !entry.name.trim() || !Array.isArray(entry.days) || entry.days.some((d) => !Number.isInteger(d) || d < 0 || d > 6)) {
    throw new Error('Invalid schedule')
  }
  if (parseTimeToMinutes(entry.startTime) !== parseTimeToMinutes(entry.startTime) || parseTimeToMinutes(entry.endTime) !== parseTimeToMinutes(entry.endTime)) throw new Error('Invalid schedule time')
  if (!['hard', 'soft', 'direct'].includes(entry.mode)) throw new Error('Invalid schedule mode')
}

function deleteSchedule(id: string): void {
  const schedules = getSchedules()
  const filtered = schedules.filter((s) => s.id !== id)
  schedulerStore.set('schedules', filtered)
  scheduleNextTimer()
}

function getNextEvent(): NextEvent | null {
  const schedules = getSchedules()
  return computeNextEvent(schedules, Date.now())
}

// ─── App Restart Handling ────────────────────────────────────────────────────

/**
 * On initialization, checks if any schedule is currently active.
 * If so, calls the VPN connect callback immediately.
 */
function handleAppRestart(): void {
  const schedules = getSchedules()
  const now = Date.now()

  for (const schedule of schedules) {
    if (isScheduleActive(schedule, now)) {
      if (vpnConnectCallback) {
        vpnConnectCallback(schedule)
      }
      break // Only connect once for the first active schedule
    }
  }
}

// ─── Public API ──────────────────────────────────────────────────────────────

export const schedulerService = {
  /**
   * Initialize the scheduler service.
   * Sets up callbacks for VPN connect/disconnect and handles app restart.
   */
  init(options: {
    onConnect: (schedule: ScheduleEntry) => void
    onDisconnect: (schedule: ScheduleEntry) => void
  }): void {
    vpnConnectCallback = options.onConnect
    vpnDisconnectCallback = options.onDisconnect
    handleAppRestart()
    scheduleNextTimer()
  },

  /** Stop the scheduler (clear timers). */
  stop(): void {
    clearSchedulerTimer()
    vpnConnectCallback = null
    vpnDisconnectCallback = null
  },

  /**
   * Re-read schedules from the store and re-arm the timer. Used after a
   * settings import overwrites the scheduler store so the live timer reflects
   * the imported schedules without an app restart.
   */
  reschedule(): void {
    scheduleNextTimer()
  },

  getSchedules,
  createSchedule,
  updateSchedule,
  deleteSchedule,
  getNextEvent
}

// ─── IPC Registration ────────────────────────────────────────────────────────

export function registerSchedulerIpcHandlers(): void {
  ipcMain.handle('scheduler:list', () => {
    return schedulerService.getSchedules()
  })

  ipcMain.handle('scheduler:create', (_event, entry: Omit<ScheduleEntry, 'id'>) => {
    return schedulerService.createSchedule(entry)
  })

  ipcMain.handle('scheduler:update', (_event, id: string, patch: Partial<ScheduleEntry>) => {
    return schedulerService.updateSchedule(id, patch)
  })

  ipcMain.handle('scheduler:delete', (_event, id: string) => {
    schedulerService.deleteSchedule(id)
  })

  ipcMain.handle('scheduler:next-event', () => {
    return schedulerService.getNextEvent()
  })
}
