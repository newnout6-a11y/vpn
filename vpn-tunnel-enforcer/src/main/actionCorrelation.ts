import { AsyncLocalStorage } from 'node:async_hooks'
import { isPromise } from 'node:util/types'
import { isIpcCorrelationId } from '../shared/ipc-result'
import { CONNECTION_SOURCES, type ConnectionProvenance } from '../shared/connection-provenance'
import { OPERATION_PRIORITY } from '../shared/operation'

export type ActionMetadata = Pick<ConnectionProvenance, 'source' | 'owner'>
const current = new AsyncLocalStorage<ActionMetadata & { id: string; active: boolean }>()

export function currentCorrelationId(): string | undefined {
  const scope = current.getStore()
  return scope?.active ? scope.id : undefined
}

export function currentActionMetadata(): ActionMetadata | undefined {
  const scope = current.getStore()
  return scope?.active ? { source: scope.source, owner: scope.owner } : undefined
}

/** Main-generated opaque IDs only. Never put payload, URLs or secrets here. */
export function withCorrelation<T>(correlationId: string, effect: () => T, metadata: Partial<ActionMetadata> = {}): T {
  if (!/^(ipc|op)_/.test(correlationId) || !isIpcCorrelationId(correlationId)) throw new Error('Invalid action correlation')
  const parent = current.getStore()
  const inherited = parent?.active && parent.id === correlationId ? parent : undefined
  const scope: ActionMetadata & { id: string; active: boolean } = { id: correlationId, active: true,
    source: metadata.source ?? inherited?.source ?? (correlationId.startsWith('ipc_') ? 'ipc' : 'lifecycle'),
    owner: metadata.owner ?? inherited?.owner ?? 'unknown' }
  if (!CONNECTION_SOURCES.includes(scope.source) || !(scope.owner === 'unknown' || Object.hasOwn(OPERATION_PRIORITY, scope.owner))) throw new Error('Invalid action metadata')
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
