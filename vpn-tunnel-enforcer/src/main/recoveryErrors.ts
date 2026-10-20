import { classifyIpcError, type IpcErrorCategory } from '../shared/ipc-result'

/** Native process/helper receipts, never exception text, determine the category. */
export function classifyRecoveryError(error: unknown): IpcErrorCategory {
  if (error && typeof error === 'object') {
    const receipt = error as { code?: unknown; killed?: unknown; signal?: unknown }
    if (receipt.code === 'elevated-helper-timeout' ||
        (receipt.code === null && receipt.killed === true && receipt.signal === 'SIGTERM')) return 'timeout'
  }
  return classifyIpcError(error)
}
