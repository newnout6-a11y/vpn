/** WP-0 operation metadata is serializable; AbortSignal stays inside main. */
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
  readonly kind: 'connect' | 'disconnect'
  readonly startedAt: number
  readonly deadline: number | null
  readonly status: 'running' | 'success' | 'cancelled' | 'error'
  readonly category?: 'conflict' | 'cancelled' | 'timeout' | 'internal'
}
export interface ConnectionOperationRejection {
  success: false
  error: string
  code: 'OPERATION_CONFLICT' | 'OPERATION_CANCELLED' | 'OPERATION_TIMEOUT'
  category: 'conflict' | 'cancelled' | 'timeout'
  operationId?: string
}
export type ConnectionStartResult = { success: boolean; error?: string; warning?: string | null; vpnIp?: string | null } | ConnectionOperationRejection
export type ConnectionStopResult = { success: boolean; error?: string; warning?: string } | ConnectionOperationRejection
