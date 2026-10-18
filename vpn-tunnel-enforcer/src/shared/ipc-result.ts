/** Versioned wire contract. Public messages never contain exception text. */
export const IPC_VERSION = 1 as const
export const IPC_ERRORS = {
  validation: { code: 'IPC_VALIDATION_ERROR', message: 'Некорректные параметры операции' },
  permission: { code: 'IPC_PERMISSION_DENIED', message: 'Недостаточно прав для операции' },
  network: { code: 'IPC_NETWORK_ERROR', message: 'Сетевая операция не выполнена' },
  conflict: { code: 'IPC_STATE_CONFLICT', message: 'Операция недоступна в текущем состоянии' },
  internal: { code: 'IPC_INTERNAL_ERROR', message: 'Не удалось выполнить операцию' },
  cancelled: { code: 'IPC_CANCELLED', message: 'Операция отменена' },
  timeout: { code: 'IPC_TIMEOUT', message: 'Истекло время выполнения операции' }
} as const
export type IpcErrorCategory = keyof typeof IPC_ERRORS
export type IpcError = { [C in IpcErrorCategory]: {
  category: C; code: typeof IPC_ERRORS[C]['code']; message: typeof IPC_ERRORS[C]['message']
} }[IpcErrorCategory]
export type IpcResult<T> = { version: typeof IPC_VERSION; correlationId: string } & (
  | { ok: true; result: T }
  | { ok: false; error: IpcError }
)

export class IpcFault extends Error {
  constructor(readonly category: IpcErrorCategory) { super(IPC_ERRORS[category].message); this.name = 'IpcFault' }
}
export class IpcValidationError extends IpcFault {
  readonly code = 'IPC_VALIDATION_ERROR'
  constructor(message: string) { super('validation'); this.message = message; this.name = 'IpcValidationError' }
}
export function ipcError(category: IpcErrorCategory): IpcError {
  return { category, ...IPC_ERRORS[category] } as IpcError
}

/** Stable categories at the privileged boundary; never serialize arbitrary errors. */
export function classifyIpcError(error: unknown): IpcErrorCategory {
  try { return classifyReadableIpcError(error) } catch { return 'internal' }
}

function classifyReadableIpcError(error: unknown): IpcErrorCategory {
  if (error instanceof IpcFault) return error.category
  const code = error && typeof error === 'object' && 'code' in error ? error.code : undefined
  if (code === 'EACCES' || code === 'EPERM') return 'permission'
  if (code === 'ETIMEDOUT') return 'timeout'
  if (typeof code === 'string' && ['ECONNRESET', 'ECONNREFUSED', 'ENOTFOUND', 'EAI_AGAIN', 'ENETUNREACH', 'EHOSTUNREACH'].includes(code)) return 'network'
  if (error instanceof Error && error.name === 'AbortError') return 'cancelled'
  return 'internal'
}

export class IpcRemoteError extends Error {
  readonly code: IpcError['code']
  readonly category: IpcErrorCategory
  constructor(error: IpcError, readonly correlationId?: string) {
    super(error.message); this.name = 'IpcRemoteError'; this.code = error.code; this.category = error.category
  }
}

export function unwrapIpcResult<T>(value: unknown): T {
  if (value && typeof value === 'object' && 'version' in value && value.version === IPC_VERSION
    && 'correlationId' in value && typeof value.correlationId === 'string'
    && /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value.correlationId)
    && 'ok' in value) {
    if (value.ok === true && 'result' in value) return value.result as T
    if (value.ok === false && 'error' in value && value.error && typeof value.error === 'object'
      && 'category' in value.error && typeof value.error.category === 'string'
      && Object.hasOwn(IPC_ERRORS, value.error.category)) {
      const canonical = ipcError(value.error.category as IpcErrorCategory)
      // Use the canonical message even if a corrupted response supplies text.
      throw new IpcRemoteError(canonical, value.correlationId)
    }
  }
  throw new IpcRemoteError(ipcError('internal'))
}
