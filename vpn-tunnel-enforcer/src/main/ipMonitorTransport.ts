// AT-00-003/005: own every OS/TUN request through socket closure and expose fixed stages only.
import http, { type ClientRequest, type IncomingMessage, type RequestOptions } from 'node:http'
import https from 'node:https'
import { isIP, connect as connectTcp, type Socket, type NetConnectOpts } from 'node:net'
import { connect as connectTls, type ConnectionOptions, type TLSSocket } from 'node:tls'

export const IP_SOCKET_DRAIN_MS = 200
export function publicIpTransport() {
  let request: ClientRequest | undefined, socket: Socket | undefined
  let agent: http.Agent | undefined
  let stage = 'dns', closeFailed = false, draining = false
  const stagesMs: Record<string, number> = {}
  const started = performance.now()
  let closing: Promise<void> | undefined
  let requestClosed: Promise<void> = Promise.resolve(), socketClosed: Promise<void> = Promise.resolve()
  const reached = (value: string) => { stage = value; stagesMs[value] = Math.round(performance.now() - started) }
  return {
    transport: {
      request(options: RequestOptions, callback: (response: IncomingMessage) => void) {
        reached(isIP(String(options.hostname ?? options.host ?? '')) ? 'tcp' : 'dns')
        const secure = options.protocol === 'https:'
        const own = (owned: Socket) => {
          if (socket === owned) return
          socket = owned
          socketClosed = new Promise<void>(resolve => owned.once('close', () => { stagesMs.closed = Math.round(performance.now() - started); resolve() }))
          owned.once('lookup', error => { if (!error && !owned.destroyed) reached('tcp') })
          owned.once('connect', () => reached(secure ? 'tls' : 'http'))
          if (secure) (owned as TLSSocket).once('secureConnect', () => reached('http'))
          if (draining) owned.destroy()
          return owned
        }
        // Node can allocate a socket before emitting request.socket. Capture it
        // synchronously so an immediate abort cannot release a still-live socket.
        const template = options.agent && typeof options.agent === 'object' ? (options.agent as https.Agent).options : {}
        agent = secure ? new https.Agent({ ...template, keepAlive: false }) : new http.Agent({ ...template, keepAlive: false })
        agent.createConnection = connection => {
          const owned = secure ? connectTls({ ...connection, rejectUnauthorized: true } as ConnectionOptions) : connectTcp(connection as NetConnectOpts)
          own(owned)
          return owned
        }
        request = (secure ? https : http).request({ ...options, agent }, response => {
          reached('body'); callback(response)
        })
        requestClosed = new Promise<void>(resolve => request!.once('close', resolve))
        request.once('socket', own)
        return request
      }
    },
    diagnostics: () => ({ stage, stagesMs, closeFailed }),
    close(): Promise<void> {
      return closing ??= (async () => {
        draining = true
        request?.destroy(); socket?.destroy(); agent?.destroy()
        const timer = setTimeout(() => { closeFailed = true }, IP_SOCKET_DRAIN_MS)
        try {
          // A socket can be assigned after abort. Read its closure promise only
          // after request.close; a timeout never releases unknown ownership.
          await requestClosed
          await socketClosed
          if (closeFailed) throw new Error('IP_SOCKET_CLOSE_UNCONFIRMED')
        } finally { clearTimeout(timer) }
      })()
    }
  }
}
