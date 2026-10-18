import { AsyncLocalStorage } from 'node:async_hooks'
import { isIpcCorrelationId } from '../shared/ipc-result'

const current = new AsyncLocalStorage<string>()

export function currentCorrelationId(): string | undefined { return current.getStore() }

/** Main-generated opaque IDs only. Never put payload, URLs or secrets here. */
export function withCorrelation<T>(correlationId: string, effect: () => T): T {
  if (!/^(ipc|op)_/.test(correlationId) || !isIpcCorrelationId(correlationId)) throw new Error('Invalid action correlation')
  return current.run(correlationId, effect)
}
