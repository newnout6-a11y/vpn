/** WP-0 operation metadata is serializable; AbortSignal stays inside main. */
import { ipcError, readIpcErrorCategory, type IpcErrorCategory, type IpcError } from './ipc-result'
export const OPERATION_PRIORITY = {
  recovery: 6, manual: 5, schedule: 4, rotation: 3, autopilot: 2, 'adaptive-retry': 1
} as const
export type OperationOwner = keyof typeof OPERATION_PRIORITY
export interface ConnectionOperation {
  readonly version: 1
  readonly operationId: string
  /** Non-secret action key shared with IPC when present; survives UUID masking. */
  readonly correlationId: string
  readonly owner: OperationOwner
  readonly kind: 'connect' | 'disconnect' | 'rotation'
  readonly startedAt: number
  readonly deadline: number | null
  readonly status: 'running' | 'success' | 'cancelled' | 'error'
  readonly category?: IpcErrorCategory
}
export interface ConnectionOperationRejection {
  success: false
  error: string
  code: 'OPERATION_CONFLICT' | 'OPERATION_CANCELLED' | 'OPERATION_TIMEOUT'
  category: 'conflict' | 'cancelled' | 'timeout'
  operationId?: string
}
export interface ConnectionFailure {
  success: false
  error: string
  code: IpcError['code']
  category: IpcErrorCategory
  warning?: string | null
}
/** Optional guidance is authored by the caller; never pass exception text. */
export function connectionFailure(category: IpcErrorCategory, guidance = ipcError(category).message): ConnectionFailure {
  const error = ipcError(category)
  return { success: false, error: guidance, code: error.code, category }
}
export type ConnectionStartResult = { success: true; error?: never; warning?: string | null; vpnIp?: string | null } | ConnectionFailure | ConnectionOperationRejection
export type ConnectionStopResult = { success: true; error?: never; warning?: string | null } | ConnectionFailure | ConnectionOperationRejection
export type ConnectionRotationResult = ({ success: true; error?: never } | ConnectionFailure) & { newProfile: string }

/** Retain the published admission and scheduler codes alongside IPC codes. */
export function connectionFailureCategory(value: unknown): IpcErrorCategory {
  const canonical = readIpcErrorCategory(value)
  if (canonical) return canonical
  try {
    if (value && typeof value === 'object' && 'code' in value && 'category' in value) {
      if ((value.code === 'OPERATION_CONFLICT' || value.code === 'SCHEDULE_PROFILE_UNAVAILABLE') && value.category === 'conflict') return 'conflict'
      if (value.code === 'OPERATION_CANCELLED' && value.category === 'cancelled') return 'cancelled'
      if (value.code === 'OPERATION_TIMEOUT' && value.category === 'timeout') return 'timeout'
    }
  } catch { /* Unreadable receipts have no confirmed category. */ }
  return 'internal'
}

/** Logs use a reversible non-secret key; managed cancellation retains UUIDv4. */
export function operationLogDetails<T extends { readonly operationId: string }>(operation: T): Omit<T, 'operationId'> & { operationId: string; operationKey: string } {
  const operationKey = /^op_[0-9a-f]{32}$/i.test(operation.operationId)
    ? operation.operationId : 'op_' + operation.operationId.replaceAll('-', '')
  return { ...operation, operationId: operationKey, operationKey }
}

/** Shared metadata for the other long-running feature operations. */
export const OPERATION_DEADLINES = Object.freeze({
  refresh: 120_000, 'speed-test': 600_000, import: 120_000, export: 120_000, rotation: 120_000,
  'health-check': 600_000, 'availability-check': 60_000, 'routing-check': 60_000, 'server-probe': 9_000, 'leak-check': 60_000, snapshot: 60_000
})
export type ManagedOperationKind = keyof typeof OPERATION_DEADLINES
export interface ManagedOperation extends Omit<ConnectionOperation, 'kind' | 'deadline' | 'category'> {
  /** Non-secret receipt identity; UUID operationId remains the cancellation handle. */
  readonly operationKey: string
  readonly kind: ManagedOperationKind
  /** No work clock runs while a native dialog awaits the user's decision. */
  readonly deadline: number | null
  readonly source: import('./connection-provenance').ConnectionProvenance['source']
  readonly category?: import('./ipc-result').IpcErrorCategory
}
