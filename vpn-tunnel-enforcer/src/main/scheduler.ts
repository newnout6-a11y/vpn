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
import type { ScheduleEntry } from '../shared/ipc-types'

// ─── Types ───────────────────────────────────────────────────────────────────

export interface NextEvent {
  type: 'start' | 'stop'
  at: number
  schedule: ScheduleEntry
}

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

/**
 * Determines if a schedule is active at the given timestamp.
 *
 * A schedule is active if:
 * 1. The timestamp's day-of-week is in the schedule's days array
 * 2. The timestamp's time-of-day is >= startTime (inclusive) and < endTime (exclusive)
 *
 * Times are in "HH:mm" format. Days use 0=Sun, 1=Mon, ..., 6=Sat.
 */
export function isScheduleActive(schedule: ScheduleEntry, timestamp: number): boolean {
  if (!schedule.enabled) return false
  if (!Array.isArray(schedule.days) || schedule.days.length === 0) return false

  const date = new Date(timestamp)
  const dayOfWeek = date.getDay() // 0=Sun, 1=Mon, ..., 6=Sat

  if (!schedule.days.includes(dayOfWeek)) return false

  const startMinutes = parseTimeToMinutes(schedule.startTime)
  const endMinutes = parseTimeToMinutes(schedule.endTime)
  if (isNaN(startMinutes) || isNaN(endMinutes)) return false

  const currentMinutes = date.getHours() * 60 + date.getMinutes()

  // startTime inclusive, endTime exclusive
  return currentMinutes >= startMinutes && currentMinutes < endMinutes
}

/**
 * Computes the chronologically nearest future start or stop event across all
 * enabled schedules.
 *
 * Returns null if no schedules are enabled or no future event can be found
 * within the next 7 days.
 */
export function computeNextEvent(schedules: ScheduleEntry[], now: number): NextEvent | null {
  const enabledSchedules = schedules.filter((s) => s.enabled && s.days.length > 0)
  if (enabledSchedules.length === 0) return null

  let nearest: NextEvent | null = null

  for (const schedule of enabledSchedules) {
    const startMinutes = parseTimeToMinutes(schedule.startTime)
    const endMinutes = parseTimeToMinutes(schedule.endTime)
    if (isNaN(startMinutes) || isNaN(endMinutes)) continue

    // Check up to 8 days ahead to find the next event
    for (let dayOffset = 0; dayOffset <= 7; dayOffset++) {
      const candidateDate = new Date(now)
      candidateDate.setDate(candidateDate.getDate() + dayOffset)
      const dayOfWeek = candidateDate.getDay()

      if (!schedule.days.includes(dayOfWeek)) continue

      // Compute start event timestamp for this day
      const startEvent = new Date(candidateDate)
      startEvent.setHours(Math.floor(startMinutes / 60), startMinutes % 60, 0, 0)
      const startTs = startEvent.getTime()

      if (startTs > now) {
        if (!nearest || startTs < nearest.at) {
          nearest = { type: 'start', at: startTs, schedule }
        }
      }

      // Compute stop event timestamp for this day
      const stopEvent = new Date(candidateDate)
      stopEvent.setHours(Math.floor(endMinutes / 60), endMinutes % 60, 0, 0)
      const stopTs = stopEvent.getTime()

      if (stopTs > now) {
        if (!nearest || stopTs < nearest.at) {
          nearest = { type: 'stop', at: stopTs, schedule }
        }
      }
    }
  }

  return nearest
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
  schedules[index] = updated
  schedulerStore.set('schedules', schedules)
  scheduleNextTimer()
  return updated
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
