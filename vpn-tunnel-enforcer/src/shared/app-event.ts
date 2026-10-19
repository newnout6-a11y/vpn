import { isConnectionProvenance, type ConnectionProvenance } from './connection-provenance'
import { isIpcCorrelationId } from './ipc-result'

export type AppLogLevel = 'debug' | 'info' | 'warn' | 'error'
export interface AppEvent extends ConnectionProvenance {
  version: 1
  ts: string
  monotonicMs: number
  clockId: string
  level: AppLogLevel
  scope: string
  message: string
  details?: unknown
  correlationId?: string
}

/** Existing unversioned JSONL remains readable; unknown versions fail closed. */
export function isAppEvent(value: unknown): boolean {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false
  const row = value as Record<string, unknown>
  if (typeof row.ts !== 'string' || !Number.isFinite(Date.parse(row.ts))
    || !['debug', 'info', 'warn', 'error'].includes(row.level as string)
    || typeof row.scope !== 'string' || typeof row.message !== 'string') return false
  if (row.correlationId !== undefined && !isIpcCorrelationId(row.correlationId)) return false
  if (row.monotonicMs !== undefined && (typeof row.monotonicMs !== 'number' || !Number.isFinite(row.monotonicMs) || row.monotonicMs < 0)) return false
  if (row.clockId !== undefined && (typeof row.clockId !== 'string' || !row.clockId)) return false
  if (row.version === undefined) return true
  return row.version === 1 && typeof row.monotonicMs === 'number' && typeof row.clockId === 'string'
    && isConnectionProvenance({ source: row.source, owner: row.owner, route: row.route, confidence: row.confidence })
}
