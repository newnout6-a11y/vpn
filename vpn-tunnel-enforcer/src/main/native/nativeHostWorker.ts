// AT-07-002 / AT-12-007: entry of the native-read host, run as an Electron utility process (see hostClient.ts).
// A fatal koffi/N-API error kills THIS process only; the main process sees an exit and callers use PowerShell.
import { runNativeOp } from './nativeOps'
import type { HostRequest, HostResponse } from './hostProtocol'
import { WinInetCallError } from './winInetCore'

const port = (process as unknown as { parentPort?: { on(event: 'message', cb: (e: { data: unknown }) => void): void; postMessage(m: unknown): void } }).parentPort
if (!port) throw new Error('nativeHostWorker must run as an Electron utility process')

function isRequest(value: unknown): value is HostRequest {
  return typeof value === 'object' && value !== null && Number.isInteger((value as HostRequest).id) && typeof (value as HostRequest).op === 'string'
}

port.on('message', async event => {
  if (!isRequest(event.data)) return
  const { id, op, args } = event.data
  let reply: HostResponse
  try {
    reply = { id, ok: true, value: await runNativeOp(op, args) }
  } catch (error) {
    reply = {
      id, ok: false,
      kind: error instanceof WinInetCallError ? 'wininet-false' : 'read-refused',
      message: error instanceof Error ? error.message : String(error)
    }
  }
  port.postMessage(reply)
})
