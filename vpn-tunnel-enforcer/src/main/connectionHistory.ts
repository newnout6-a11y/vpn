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
import { createHash, randomUUID } from 'crypto'
import type { ConnectionLogEntry, ConnectionHistoryFilters, ConnectionHistoryStats as AggregatedStats } from '../shared/ipc-types'
export type { ConnectionHistoryFilters, ConnectionHistoryStats as AggregatedStats } from '../shared/ipc-types'
import { SESSION_OUTCOME_KINDS } from '../shared/ipc-types'
import { logEvent } from './appLogger'

// ─── Constants ───────────────────────────────────────────────────────────────

const MAX_ENTRIES = 1000

// ─── Types ───────────────────────────────────────────────────────────────────

export type AggregationPeriod = 'day' | 'week' | 'month'

// ─── Store ───────────────────────────────────────────────────────────────────

interface ConnectionHistoryStoreSchema {
  connectionHistory: ConnectionLogEntry[]
  /** Preserved for a newer reader or manual recovery; never rendered as valid entries. */
  rejectedConnectionHistory?: unknown[]
}

const isRecord = (value: unknown): value is Record<string, unknown> =>
  value !== null && typeof value === 'object' && !Array.isArray(value)
const isText = (value: unknown): value is string => typeof value === 'string'
const isNumber = (value: unknown): value is number => typeof value === 'number' && Number.isFinite(value)
const isNonNegative = (value: unknown): value is number => isNumber(value) && value >= 0
const optional = (value: unknown, check: (value: unknown) => boolean) => value == null || check(value)
const outcomeKinds = new Set<string>(SESSION_OUTCOME_KINDS)

function validEntry(value: unknown): value is ConnectionLogEntry {
  if (!isRecord(value) || !isText(value.id) || !isText(value.profileId) || !isText(value.profileName)
    || !isNonNegative(value.startedAt) || !(value.endedAt === null || isNonNegative(value.endedAt))
    || !isText(value.mode) || !['hard', 'soft', 'direct'].includes(value.mode)
    || !isText(value.disconnectReason) || !['user', 'error', 'rotation', 'schedule', 'crash'].includes(value.disconnectReason)
    || !isNonNegative(value.bytesDown) || !isNonNegative(value.bytesUp)
    || !optional(value.errorMessage, isText)) return false
  if (value.outcome == null) return true // Records before v1.1.18 have no outcome.
  const outcome = value.outcome
  if (!isRecord(outcome) || !isText(outcome.kind) || !outcomeKinds.has(outcome.kind) || !isText(outcome.headline)) return false
  if (outcome.evidence === undefined) return true
  const evidence = outcome.evidence
  if (!isRecord(evidence)) return false
  return ['singboxStderrTail', 'networkTransition', 'egressCountry', 'egressIp', 'hint']
    .every(key => optional(evidence[key], isText))
    && optional(evidence.singboxExitCode, isNumber)
    && ['adaptiveAttempts', 'autoRestartAttempts'].every(key => optional(evidence[key], isNonNegative))
    && ['killSwitchEngaged', 'leakDetectedDuringSession'].every(key => optional(evidence[key], v => typeof v === 'boolean'))
    && optional(evidence.outboundFault, v => isText(v) && ['reality-key-mismatch', 'tls-handshake-failed', 'upstream-unreachable'].includes(v))
    && optional(evidence.adaptiveMode, v => isText(v) && ['baseline', 'tls-compatibility', 'mtu-compatibility', 'external-managed'].includes(v))
    && optional(evidence.proxyEngine, v => v === 'sing-box' || v === 'xray')
}

let corruptFingerprint: string | undefined
function corrupted(raw: string, reason: 'invalid-json' | 'invalid-schema', rejectedEntries?: number): void {
  const fingerprint = createHash('sha256').update(raw).digest('hex')
  if (fingerprint !== corruptFingerprint) {
    logEvent('error', 'connection-history', 'history.corrupted', {
      reason, ...(rejectedEntries === undefined ? {} : { rejectedEntries })
    })
  }
  corruptFingerprint = fingerprint
}

function deserializeHistory(raw: string): ConnectionHistoryStoreSchema {
  let parsed: unknown
  try { parsed = JSON.parse(raw) }
  catch { corrupted(raw, 'invalid-json'); return { connectionHistory: [] } }
  if (!isRecord(parsed) || !Array.isArray(parsed.connectionHistory)) {
    corrupted(raw, 'invalid-schema')
    return { connectionHistory: [] }
  }
  const entries: ConnectionLogEntry[] = []
  const rejected: unknown[] = []
  for (const entry of parsed.connectionHistory) {
    if (validEntry(entry)) entries.push(entry)
    else rejected.push(entry)
  }
  if (rejected.length) corrupted(raw, 'invalid-schema', rejected.length)
  else corruptFingerprint = undefined
  // Conf atomically saves this repaired view on the next write; never log raw
  // corrupt data, which can include credentials or personal profile names.
  return {
    ...parsed, connectionHistory: entries,
    rejectedConnectionHistory: [
      ...(Array.isArray(parsed.rejectedConnectionHistory) ? parsed.rejectedConnectionHistory : []),
      ...rejected
    ]
  }
}

const historyStore = new Store<ConnectionHistoryStoreSchema>({
  name: 'connection-history',
  deserialize: deserializeHistory,
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
      const haystack = [
        entry.profileName,
        entry.mode,
        entry.disconnectReason,
        entry.errorMessage ?? '',
        entry.outcome?.kind ?? '',
        entry.outcome?.headline ?? ''
      ]
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
 *
 * "Never came up" attempts (outcome.kind === 'start-failed') are excluded — they
 * are not connections and would inflate the count with zero-duration noise.
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

  const filtered = entries.filter(
    (entry) => entry.startedAt >= cutoff && entry.outcome?.kind !== 'start-failed'
  )

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
    'disconnectReason',
    'errorMessage',
    'outcomeKind',
    'outcomeHeadline'
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
      entry.disconnectReason,
      escapeCsvField(entry.errorMessage ?? ''),
      escapeCsvField(entry.outcome?.kind ?? ''),
      escapeCsvField(entry.outcome?.headline ?? '')
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
    errorMessage: entry.errorMessage ?? null,
    outcome: entry.outcome ?? null,
    id: randomUUID()
  }
  if (!validEntry(newEntry)) throw new Error('Invalid connection history entry')

  const entries = getEntries()
  entries.push(newEntry)

  // Enforce max entries limit — remove oldest entries first
  while (entries.length > MAX_ENTRIES) {
    entries.shift()
  }

  historyStore.set('connectionHistory', entries)
  corruptFingerprint = undefined
  return newEntry
}

function clearHistory(): void {
  historyStore.set({ connectionHistory: [], rejectedConnectionHistory: [] })
  corruptFingerprint = undefined
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

  ipcMain.handle('connection-history:clear', () => {
    connectionHistoryService.clearHistory()
    return { success: true }
  })

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
