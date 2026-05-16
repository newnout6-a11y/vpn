/**
 * Connection History Service — main process module for storing and exporting connection logs.
 *
 * Responsibilities:
 * - Store ConnectionLogEntry[] in electron-store (max 1000 entries)
 * - Add new connection log entries
 * - Filter entries by level (disconnect reason), date range, text substring
 * - Aggregate statistics: total connection time, total traffic by day/week/month
 * - Export to CSV and JSON formats
 * - Register IPC handlers for connection history channels
 *
 * Pure functions exported for property testing:
 * - filterEntries(entries, filters)
 * - aggregateStats(entries, period)
 */

import { ipcMain } from 'electron'
import Store from 'electron-store'
import { randomUUID } from 'crypto'
import type { ConnectionLogEntry } from '../shared/ipc-types'

// ─── Constants ───────────────────────────────────────────────────────────────

const MAX_ENTRIES = 1000

// ─── Types ───────────────────────────────────────────────────────────────────

export interface ConnectionHistoryFilters {
  /** Filter by disconnect reason (acts as "level") */
  levels?: Array<ConnectionLogEntry['disconnectReason']>
  /** Filter entries started at or after this timestamp */
  dateFrom?: number
  /** Filter entries started at or before this timestamp */
  dateTo?: number
  /** Filter entries whose profileName, mode, or disconnectReason contain this substring (case-insensitive) */
  text?: string
}

export type AggregationPeriod = 'day' | 'week' | 'month'

export interface AggregatedStats {
  /** Total connection time in milliseconds (sum of endedAt - startedAt for completed entries) */
  totalTimeMs: number
  /** Total bytes downloaded */
  totalBytesDown: number
  /** Total bytes uploaded */
  totalBytesUp: number
  /** Number of entries included in the aggregation */
  entryCount: number
}

// ─── Store ───────────────────────────────────────────────────────────────────

interface ConnectionHistoryStoreSchema {
  connectionHistory: ConnectionLogEntry[]
}

const historyStore = new Store<ConnectionHistoryStoreSchema>({
  name: 'connection-history',
  defaults: {
    connectionHistory: []
  }
})

// ─── Pure Functions (exported for property testing) ──────────────────────────

/**
 * Filters connection log entries based on the provided filter criteria.
 * All active filters must be satisfied (AND logic).
 *
 * - levels: entry's disconnectReason must be in the provided array
 * - dateFrom: entry's startedAt must be >= dateFrom
 * - dateTo: entry's startedAt must be <= dateTo
 * - text: entry's profileName, mode, or disconnectReason must contain the substring (case-insensitive)
 */
export function filterEntries(
  entries: ConnectionLogEntry[],
  filters: ConnectionHistoryFilters
): ConnectionLogEntry[] {
  return entries.filter((entry) => {
    // Filter by levels (disconnect reason)
    if (filters.levels && filters.levels.length > 0) {
      if (!filters.levels.includes(entry.disconnectReason)) {
        return false
      }
    }

    // Filter by date range (based on startedAt)
    if (filters.dateFrom != null) {
      if (entry.startedAt < filters.dateFrom) {
        return false
      }
    }

    if (filters.dateTo != null) {
      if (entry.startedAt > filters.dateTo) {
        return false
      }
    }

    // Filter by text substring (case-insensitive)
    if (filters.text != null && filters.text.length > 0) {
      const searchLower = filters.text.toLowerCase()
      const haystack = [entry.profileName, entry.mode, entry.disconnectReason]
        .join(' ')
        .toLowerCase()
      if (!haystack.includes(searchLower)) {
        return false
      }
    }

    return true
  })
}

/**
 * Computes aggregated statistics for the given entries within the specified period.
 *
 * The period determines the time window relative to "now":
 * - 'day': entries from the last 24 hours
 * - 'week': entries from the last 7 days
 * - 'month': entries from the last 30 days
 *
 * Total connection time = sum of (endedAt - startedAt) for entries where endedAt is not null.
 * Total traffic = sum of bytesDown and bytesUp respectively across all entries in the period.
 */
export function aggregateStats(
  entries: ConnectionLogEntry[],
  period: AggregationPeriod,
  now?: number
): AggregatedStats {
  const currentTime = now ?? Date.now()

  const periodMs: Record<AggregationPeriod, number> = {
    day: 24 * 60 * 60 * 1000,
    week: 7 * 24 * 60 * 60 * 1000,
    month: 30 * 24 * 60 * 60 * 1000
  }

  const cutoff = currentTime - periodMs[period]

  const filtered = entries.filter((entry) => entry.startedAt >= cutoff)

  let totalTimeMs = 0
  let totalBytesDown = 0
  let totalBytesUp = 0

  for (const entry of filtered) {
    if (entry.endedAt != null) {
      totalTimeMs += entry.endedAt - entry.startedAt
    }
    totalBytesDown += entry.bytesDown
    totalBytesUp += entry.bytesUp
  }

  return {
    totalTimeMs,
    totalBytesDown,
    totalBytesUp,
    entryCount: filtered.length
  }
}

// ─── CSV/JSON Export ─────────────────────────────────────────────────────────

/**
 * Exports connection log entries to a CSV string.
 */
export function exportCsv(entries: ConnectionLogEntry[]): string {
  const headers = [
    'id',
    'startedAt',
    'endedAt',
    'profileName',
    'profileId',
    'mode',
    'bytesDown',
    'bytesUp',
    'disconnectReason'
  ]

  const rows = entries.map((entry) => {
    return [
      escapeCsvField(entry.id),
      entry.startedAt.toString(),
      entry.endedAt != null ? entry.endedAt.toString() : '',
      escapeCsvField(entry.profileName),
      escapeCsvField(entry.profileId),
      entry.mode,
      entry.bytesDown.toString(),
      entry.bytesUp.toString(),
      entry.disconnectReason
    ].join(',')
  })

  return [headers.join(','), ...rows].join('\n')
}

/**
 * Exports connection log entries to a JSON string.
 */
export function exportJson(entries: ConnectionLogEntry[]): string {
  return JSON.stringify(entries, null, 2)
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

function escapeCsvField(value: string): string {
  if (value.includes(',') || value.includes('"') || value.includes('\n')) {
    return `"${value.replace(/"/g, '""')}"`
  }
  return value
}

// ─── CRUD Operations ─────────────────────────────────────────────────────────

function getEntries(): ConnectionLogEntry[] {
  const stored = historyStore.get('connectionHistory')
  if (!Array.isArray(stored)) return []
  return stored
}

function addEntry(entry: Omit<ConnectionLogEntry, 'id'>): ConnectionLogEntry {
  const newEntry: ConnectionLogEntry = {
    ...entry,
    id: randomUUID()
  }

  const entries = getEntries()
  entries.push(newEntry)

  // Enforce max entries limit — remove oldest entries first
  while (entries.length > MAX_ENTRIES) {
    entries.shift()
  }

  historyStore.set('connectionHistory', entries)
  return newEntry
}

function clearHistory(): void {
  historyStore.set('connectionHistory', [])
}

// ─── Public API ──────────────────────────────────────────────────────────────

export const connectionHistoryService = {
  getEntries,
  addEntry,
  clearHistory,

  filter(filters: ConnectionHistoryFilters): ConnectionLogEntry[] {
    return filterEntries(getEntries(), filters)
  },

  stats(period: AggregationPeriod): AggregatedStats {
    return aggregateStats(getEntries(), period)
  },

  exportCsv(): string {
    return exportCsv(getEntries())
  },

  exportJson(): string {
    return exportJson(getEntries())
  }
}

// ─── IPC Registration ────────────────────────────────────────────────────────

export function registerConnectionHistoryIpcHandlers(): void {
  ipcMain.handle('connection-history:list', () => {
    return connectionHistoryService.getEntries()
  })

  ipcMain.handle(
    'connection-history:add',
    (_event, entry: Omit<ConnectionLogEntry, 'id'>) => {
      return connectionHistoryService.addEntry(entry)
    }
  )

  ipcMain.handle(
    'connection-history:filter',
    (_event, filters: ConnectionHistoryFilters) => {
      return connectionHistoryService.filter(filters)
    }
  )

  ipcMain.handle(
    'connection-history:stats',
    (_event, period: AggregationPeriod) => {
      return connectionHistoryService.stats(period)
    }
  )

  ipcMain.handle('connection-history:export-csv', () => {
    return connectionHistoryService.exportCsv()
  })

  ipcMain.handle('connection-history:export-json', () => {
    return connectionHistoryService.exportJson()
  })
}
