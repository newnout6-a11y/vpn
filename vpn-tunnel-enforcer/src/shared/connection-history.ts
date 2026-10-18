import type { ConnectionLogEntry } from './ipc-types'

/** Calendar dates may jump. New records carry elapsed time; legacy rows fall back. */
export function connectionDurationMs(entry: Pick<ConnectionLogEntry, 'startedAt' | 'endedAt' | 'durationMs'>): number {
  if (entry.endedAt === null) return 0
  return entry.durationMs ?? Math.max(0, entry.endedAt - entry.startedAt)
}
