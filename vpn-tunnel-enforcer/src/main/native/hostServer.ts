// AT-07-002 / AT-12-007: message loop of a native-read host (an Electron utility process). Shared by the production
// worker and by the test-only worker used in the Electron e2e, so the crash-injection op never ships.
import type { HostOp, HostRequest, HostResponse } from './hostProtocol'
import { WinInetCallError } from './winInetCore'

type ParentPort = { on(event: 'message', cb: (e: { data: unknown }) => void): void; postMessage(m: unknown): void }

function isRequest(value: unknown): value is HostRequest {
  return typeof value === 'object' && value !== null && Number.isInteger((value as HostRequest).id) && typeof (value as HostRequest).op === 'string'
}

/** Answers every request with the handler's value, or with the failure kind the client must see. */
export function serveHost(handler: (op: HostOp, args: unknown) => Promise<unknown>): void {
  const port = (process as unknown as { parentPort?: ParentPort }).parentPort
  if (!port) throw new Error('a native-read host must run as an Electron utility process')
  port.on('message', async event => {
    if (!isRequest(event.data)) return
    const { id, op, args } = event.data
    let reply: HostResponse
    try {
      reply = { id, ok: true, value: await handler(op, args) }
    } catch (error) {
      reply = {
        id, ok: false,
        kind: error instanceof WinInetCallError ? 'wininet-false' : 'read-refused',
        message: error instanceof Error ? error.message : String(error)
      }
    }
    port.postMessage(reply)
  })
}
