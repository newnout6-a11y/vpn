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
const IPC_ERROR_MESSAGES_EN: Record<keyof typeof IPC_ERRORS, string> = {
  validation: 'Invalid operation parameters', permission: 'Permission denied',
  network: 'Network operation failed', conflict: 'Operation unavailable in the current state',
  internal: 'Operation failed', cancelled: 'Operation cancelled', timeout: 'Operation timed out'
}
export type IpcErrorLocale = 'en' | 'ru'
export type IpcErrorCategory = keyof typeof IPC_ERRORS
export type IpcError = { [C in IpcErrorCategory]: {
  category: C; code: typeof IPC_ERRORS[C]['code']; message: string
} }[IpcErrorCategory]
/** Promise rejection data crosses contextBridge; custom Error properties do not. */
export type IpcRemoteErrorData = IpcError & { name: 'IpcRemoteError'; correlationId?: string }
const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i
const CORRELATION_KEY = /^(?:ipc|op)_[0-9a-f]{12}4[0-9a-f]{3}[89ab][0-9a-f]{15}$/i
/** Keep legacy UUID responses readable; new IDs survive credential redaction. */
export function isIpcCorrelationId(value: unknown): value is string {
  return typeof value === 'string' && value.trim() === value && (UUID_V4.test(value) || CORRELATION_KEY.test(value))
}
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
export function ipcError(category: IpcErrorCategory, locale: IpcErrorLocale = 'ru'): IpcError {
  return { category, ...IPC_ERRORS[category], message: locale === 'en' ? IPC_ERROR_MESSAGES_EN[category] : IPC_ERRORS[category].message } as IpcError
}

/** Domain receipts must agree on a canonical code/category pair. */
export function readIpcErrorCategory(value: unknown): IpcErrorCategory | undefined {
  try {
    if (!value || typeof value !== 'object' || !('category' in value) || !('code' in value)) return undefined
    const category = value.category
    return typeof category === 'string' && Object.hasOwn(IPC_ERRORS, category)
      && value.code === IPC_ERRORS[category as IpcErrorCategory].code ? category as IpcErrorCategory : undefined
  } catch { return undefined }
}

/** Stable categories at the privileged boundary; never serialize arbitrary errors. */
export function classifyIpcError(error: unknown): IpcErrorCategory {
  try {
    const category = classifyReadableIpcError(error)
    return Object.hasOwn(IPC_ERRORS, category) ? category : 'internal'
  } catch { return 'internal' }
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

/** Explicit allowlist: never copy arbitrary exception message, stack or cause. */
export function serializeIpcError(error: unknown, locale: IpcErrorLocale): IpcRemoteErrorData {
  let category: IpcErrorCategory = 'internal', correlationId: string | undefined
  try {
    if (error instanceof IpcRemoteError) {
      if (Object.hasOwn(IPC_ERRORS, error.category)) category = error.category
      if (isIpcCorrelationId(error.correlationId)) correlationId = error.correlationId
    } else category = classifyIpcError(error)
  } catch { category = 'internal' }
  return { name: 'IpcRemoteError', ...ipcError(category, locale), ...(correlationId ? { correlationId } : {}) }
}

export function isIpcRemoteErrorData(value: unknown): value is IpcRemoteErrorData {
  try {
    if (!value || typeof value !== 'object' || ![Object.prototype, null].includes(Object.getPrototypeOf(value))) return false
    const error = value as Record<string, unknown>
    if (error.name !== 'IpcRemoteError' || typeof error.category !== 'string' || !Object.hasOwn(IPC_ERRORS, error.category)) return false
    const category = error.category as IpcErrorCategory
    return error.code === IPC_ERRORS[category].code
      && (error.message === IPC_ERRORS[category].message || error.message === IPC_ERROR_MESSAGES_EN[category])
      && (error.correlationId === undefined || isIpcCorrelationId(error.correlationId))
  } catch { return false }
}

export function unwrapIpcResult<T>(value: unknown, locale: IpcErrorLocale = 'ru'): T {
  if (value && typeof value === 'object' && 'version' in value && value.version === IPC_VERSION
    && 'correlationId' in value && isIpcCorrelationId(value.correlationId)
    && 'ok' in value) {
    if (value.ok === true && 'result' in value) return value.result as T
    if (value.ok === false && 'error' in value && value.error && typeof value.error === 'object'
      && 'category' in value.error && typeof value.error.category === 'string'
      && Object.hasOwn(IPC_ERRORS, value.error.category)) {
      const canonical = ipcError(value.error.category as IpcErrorCategory, locale)
      // Use the canonical message even if a corrupted response supplies text.
      throw new IpcRemoteError(canonical, value.correlationId)
    }
  }
  throw new IpcRemoteError(ipcError('internal', locale))
}
