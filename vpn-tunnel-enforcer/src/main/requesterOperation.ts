import type { WebContents } from 'electron'
import { requireString } from './ipcValidation'
import { IpcFault } from '../shared/ipc-result'
import { requestDocumentLifetime } from './requestDocumentLifetime'
import type { OperationLease } from './operationRegistry'

interface Request { controller: AbortController; cancel?: () => boolean }
const requests = new WeakMap<WebContents, Map<string, Request>>()
function requestId(value: unknown): string | undefined {
  if (value === undefined) return undefined
  const id = requireString(value, 'requestId', { maxLength: 36 })
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(id)) throw new IpcFault('validation')
  return id.toLowerCase()
}

/** Wrap an existing owned operation; its registry still owns UUID, deadline,
 * commit fencing and physical drain. The renderer token only grants cancellation. */
export async function runRequesterOperation<T>(sender: WebContents, value: unknown, effect: (signal: AbortSignal, admitted: (lease: OperationLease) => void) => Promise<T>): Promise<T> {
  const id = requestId(value), existing = requests.get(sender)
  if (id && existing?.has(id)) throw new IpcFault('conflict')
  const controller = new AbortController()
  const request: Request = { controller }
  const lifetime = requestDocumentLifetime(sender, controller.signal)
  const owned = id ? existing ?? new Map<string, Request>() : undefined
  if (id && owned) { owned.set(id, request); requests.set(sender, owned) }
  try { return await effect(lifetime.signal, lease => { request.cancel = () => lease.cancel() }) }
  finally {
    lifetime.dispose()
    if (id && owned?.get(id) === request) owned.delete(id)
    if (owned?.size === 0 && requests.get(sender) === owned) requests.delete(sender)
  }
}

export function cancelRequesterOperation(sender: WebContents, value: unknown): boolean {
  const id = requestId(value)
  if (!id) throw new IpcFault('validation')
  const request = requests.get(sender)?.get(id)
  if (!request || request.controller.signal.aborted) return false
  if (request.cancel) return request.cancel()
  request.controller.abort()
  return true
}
