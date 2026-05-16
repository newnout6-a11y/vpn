/**
 * Unit tests for connectionHistory service.
 * Tests filterEntries, aggregateStats, exportCsv, exportJson pure functions.
 */

import { describe, it, expect } from 'vitest'
import type { ConnectionLogEntry } from '../shared/ipc-types'
import {
  filterEntries,
  aggregateStats,
  exportCsv,
  exportJson,
  type ConnectionHistoryFilters,
  type AggregationPeriod
} from './connectionHistory'

// ─── Test Data ───────────────────────────────────────────────────────────────

const baseEntry: ConnectionLogEntry = {
  id: 'entry-1',
  startedAt: 1700000000000, // Nov 14, 2023
  endedAt: 1700003600000, // +1 hour
  profileName: 'US Server',
  profileId: 'profile-1',
  mode: 'hard',
  bytesDown: 1024000,
  bytesUp: 512000,
  disconnectReason: 'user'
}

const entries: ConnectionLogEntry[] = [
  baseEntry,
  {
    id: 'entry-2',
    startedAt: 1700010000000,
    endedAt: 1700017200000, // +2 hours
    profileName: 'EU Server',
    profileId: 'profile-2',
    mode: 'soft',
    bytesDown: 2048000,
    bytesUp: 1024000,
    disconnectReason: 'error'
  },
  {
    id: 'entry-3',
    startedAt: 1700020000000,
    endedAt: null, // still active
    profileName: 'JP Server',
    profileId: 'profile-3',
    mode: 'direct',
    bytesDown: 500000,
    bytesUp: 250000,
    disconnectReason: 'rotation'
  },
  {
    id: 'entry-4',
    startedAt: 1700030000000,
    endedAt: 1700031800000, // +30 min
    profileName: 'US Server',
    profileId: 'profile-1',
    mode: 'hard',
    bytesDown: 768000,
    bytesUp: 384000,
    disconnectReason: 'schedule'
  }
]

// ─── filterEntries Tests ─────────────────────────────────────────────────────

describe('filterEntries', () => {
  it('returns all entries when no filters are active', () => {
    const result = filterEntries(entries, {})
    expect(result).toHaveLength(entries.length)
    expect(result).toEqual(entries)
  })

  it('filters by levels (disconnect reason)', () => {
    const result = filterEntries(entries, { levels: ['user'] })
    expect(result).toHaveLength(1)
    expect(result[0].id).toBe('entry-1')
  })

  it('filters by multiple levels', () => {
    const result = filterEntries(entries, { levels: ['user', 'error'] })
    expect(result).toHaveLength(2)
    expect(result.map((e) => e.id)).toEqual(['entry-1', 'entry-2'])
  })

  it('filters by dateFrom', () => {
    const result = filterEntries(entries, { dateFrom: 1700015000000 })
    expect(result).toHaveLength(2)
    expect(result.map((e) => e.id)).toEqual(['entry-3', 'entry-4'])
  })

  it('filters by dateTo', () => {
    const result = filterEntries(entries, { dateTo: 1700015000000 })
    expect(result).toHaveLength(2)
    expect(result.map((e) => e.id)).toEqual(['entry-1', 'entry-2'])
  })

  it('filters by date range (dateFrom + dateTo)', () => {
    const result = filterEntries(entries, {
      dateFrom: 1700005000000,
      dateTo: 1700025000000
    })
    expect(result).toHaveLength(2)
    expect(result.map((e) => e.id)).toEqual(['entry-2', 'entry-3'])
  })

  it('filters by text substring (case-insensitive)', () => {
    const result = filterEntries(entries, { text: 'us server' })
    expect(result).toHaveLength(2)
    expect(result.map((e) => e.id)).toEqual(['entry-1', 'entry-4'])
  })

  it('filters by text matching mode', () => {
    const result = filterEntries(entries, { text: 'soft' })
    expect(result).toHaveLength(1)
    expect(result[0].id).toBe('entry-2')
  })

  it('filters by text matching disconnectReason', () => {
    const result = filterEntries(entries, { text: 'rotation' })
    expect(result).toHaveLength(1)
    expect(result[0].id).toBe('entry-3')
  })

  it('combines all filters (AND logic)', () => {
    const result = filterEntries(entries, {
      levels: ['user', 'schedule'],
      text: 'us server',
      dateFrom: 1700025000000
    })
    expect(result).toHaveLength(1)
    expect(result[0].id).toBe('entry-4')
  })

  it('returns empty array when no entries match', () => {
    const result = filterEntries(entries, { text: 'nonexistent' })
    expect(result).toHaveLength(0)
  })

  it('handles empty entries array', () => {
    const result = filterEntries([], { levels: ['user'] })
    expect(result).toHaveLength(0)
  })

  it('ignores empty text filter', () => {
    const result = filterEntries(entries, { text: '' })
    expect(result).toHaveLength(entries.length)
  })

  it('ignores empty levels array', () => {
    const result = filterEntries(entries, { levels: [] })
    expect(result).toHaveLength(entries.length)
  })
})

// ─── aggregateStats Tests ────────────────────────────────────────────────────

describe('aggregateStats', () => {
  // Use a fixed "now" that is within range of our test entries
  const now = 1700040000000

  it('computes total time for completed entries within period', () => {
    const result = aggregateStats(entries, 'day', now)
    // All entries are within 24h of "now"
    // entry-1: 3600000ms, entry-2: 7200000ms, entry-3: null (skipped), entry-4: 1800000ms
    expect(result.totalTimeMs).toBe(3600000 + 7200000 + 1800000)
  })

  it('computes total bytes down and up', () => {
    const result = aggregateStats(entries, 'day', now)
    expect(result.totalBytesDown).toBe(1024000 + 2048000 + 500000 + 768000)
    expect(result.totalBytesUp).toBe(512000 + 1024000 + 250000 + 384000)
  })

  it('counts entries in the period', () => {
    const result = aggregateStats(entries, 'day', now)
    expect(result.entryCount).toBe(4)
  })

  it('excludes entries outside the period', () => {
    // Set "now" far in the future so entries are outside the day window
    const farFuture = 1700200000000 // ~2 days later
    const result = aggregateStats(entries, 'day', farFuture)
    expect(result.entryCount).toBe(0)
    expect(result.totalTimeMs).toBe(0)
    expect(result.totalBytesDown).toBe(0)
    expect(result.totalBytesUp).toBe(0)
  })

  it('handles week period', () => {
    const result = aggregateStats(entries, 'week', now)
    expect(result.entryCount).toBe(4)
  })

  it('handles month period', () => {
    const result = aggregateStats(entries, 'month', now)
    expect(result.entryCount).toBe(4)
  })

  it('handles empty entries', () => {
    const result = aggregateStats([], 'day', now)
    expect(result.totalTimeMs).toBe(0)
    expect(result.totalBytesDown).toBe(0)
    expect(result.totalBytesUp).toBe(0)
    expect(result.entryCount).toBe(0)
  })

  it('skips entries with null endedAt for time calculation but includes traffic', () => {
    const onlyActive: ConnectionLogEntry[] = [
      {
        id: 'active-1',
        startedAt: now - 1000,
        endedAt: null,
        profileName: 'Test',
        profileId: 'p1',
        mode: 'hard',
        bytesDown: 100,
        bytesUp: 50,
        disconnectReason: 'user'
      }
    ]
    const result = aggregateStats(onlyActive, 'day', now)
    expect(result.totalTimeMs).toBe(0)
    expect(result.totalBytesDown).toBe(100)
    expect(result.totalBytesUp).toBe(50)
    expect(result.entryCount).toBe(1)
  })
})

// ─── exportCsv Tests ─────────────────────────────────────────────────────────

describe('exportCsv', () => {
  it('produces correct CSV header', () => {
    const csv = exportCsv([])
    expect(csv).toBe(
      'id,startedAt,endedAt,profileName,profileId,mode,bytesDown,bytesUp,disconnectReason'
    )
  })

  it('produces correct CSV rows', () => {
    const csv = exportCsv([baseEntry])
    const lines = csv.split('\n')
    expect(lines).toHaveLength(2)
    expect(lines[1]).toBe(
      'entry-1,1700000000000,1700003600000,US Server,profile-1,hard,1024000,512000,user'
    )
  })

  it('handles null endedAt', () => {
    const entry: ConnectionLogEntry = { ...baseEntry, endedAt: null }
    const csv = exportCsv([entry])
    const lines = csv.split('\n')
    expect(lines[1]).toContain(',,') // empty endedAt field
  })

  it('escapes fields with commas', () => {
    const entry: ConnectionLogEntry = { ...baseEntry, profileName: 'Server, US' }
    const csv = exportCsv([entry])
    expect(csv).toContain('"Server, US"')
  })

  it('escapes fields with quotes', () => {
    const entry: ConnectionLogEntry = { ...baseEntry, profileName: 'Server "Best"' }
    const csv = exportCsv([entry])
    expect(csv).toContain('"Server ""Best"""')
  })
})

// ─── exportJson Tests ────────────────────────────────────────────────────────

describe('exportJson', () => {
  it('produces valid JSON', () => {
    const json = exportJson(entries)
    const parsed = JSON.parse(json)
    expect(parsed).toEqual(entries)
  })

  it('handles empty array', () => {
    const json = exportJson([])
    expect(JSON.parse(json)).toEqual([])
  })

  it('preserves all fields', () => {
    const json = exportJson([baseEntry])
    const parsed = JSON.parse(json)
    expect(parsed[0]).toEqual(baseEntry)
  })
})
