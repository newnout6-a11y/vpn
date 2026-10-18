import { AsyncLocalStorage } from 'node:async_hooks'
import { isPromise } from 'node:util/types'
import { isIpcCorrelationId } from '../shared/ipc-result'

const current = new AsyncLocalStorage<{ id: string; active: boolean }>()

export function currentCorrelationId(): string | undefined {
  const scope = current.getStore()
  return scope?.active ? scope.id : undefined
}

/** Main-generated opaque IDs only. Never put payload, URLs or secrets here. */
export function withCorrelation<T>(correlationId: string, effect: () => T): T {
  if (!/^(ipc|op)_/.test(correlationId) || !isIpcCorrelationId(correlationId)) throw new Error('Invalid action correlation')
  const scope = { id: correlationId, active: true }
  return current.run(scope, () => {
    try {
      const result = effect()
      // Timers retain their async store, but cannot retain a completed action.
      // Observe the original Promise without changing its identity or rejection.
      if (isPromise(result)) void result.then(() => { scope.active = false }, () => { scope.active = false })
      else scope.active = false
      return result
    } catch (error) {
      scope.active = false
      throw error
    }
  })
}
