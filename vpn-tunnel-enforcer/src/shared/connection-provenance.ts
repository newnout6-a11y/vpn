import { OPERATION_PRIORITY, type OperationOwner } from './operation'

export const CONNECTION_SOURCES = ['ipc', 'tray', 'lifecycle', 'runtime', 'unknown'] as const
export interface ConnectionProvenance {
  source: typeof CONNECTION_SOURCES[number]
  owner: OperationOwner | 'unknown'
  /** Configured mechanism, not proof that every packet used it. */
  route: 'tun' | 'soft-env' | 'unconfirmed'
  /** Confidence in the recorded outcome cause, not packet-level protection. */
  confidence: 'observed' | 'inferred' | 'indeterminate'
}

export function isConnectionProvenance(value: unknown): value is ConnectionProvenance {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false
  const p = value as Record<string, unknown>
  return Object.keys(p).length === 4
    && CONNECTION_SOURCES.some(source => source === p.source)
    && (p.owner === 'unknown' || (typeof p.owner === 'string' && Object.hasOwn(OPERATION_PRIORITY, p.owner)))
    && ['tun', 'soft-env', 'unconfirmed'].includes(p.route as string)
    && ['observed', 'inferred', 'indeterminate'].includes(p.confidence as string)
}
