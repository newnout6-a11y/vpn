// AT-00-003; AT-02-004; AT-10-004: verify candidate egress before selecting it.
import { Socket, isIP } from 'node:net'
import { connect as connectTls, type TLSSocket } from 'node:tls'
import { Agent, request } from 'node:https'
import type { ClientRequest, IncomingMessage } from 'node:http'
import { SocksClient } from 'socks'
import { isPublicIp } from './publicIp'
import { IpcFault } from '../shared/ipc-result'

export interface SocksUpstream { port: number; username: string; password: string }
const HOST = 'api.ipify.org'
const DEADLINE_MS = 2000
const MAX_BODY_BYTES = 4096

/** Every connection is carried by the owned SOCKS socket; no HTTP proxy env or direct fallback. */
export function probeSocksUpstream(upstream: SocksUpstream, signal?: AbortSignal): Promise<string> {
  if (!upstream || !Number.isInteger(upstream.port) || upstream.port < 1 || upstream.port > 65535 ||
      [upstream.username, upstream.password].some(value => typeof value !== 'string' ||
        Buffer.byteLength(value, 'utf8') < 1 || Buffer.byteLength(value, 'utf8') > 255)) {
    return Promise.reject(new IpcFault('validation'))
  }
  if (signal?.aborted) return Promise.reject(new IpcFault('cancelled'))
  return new Promise<string>((resolve, reject) => {
    const socket = new Socket()
    let secured: TLSSocket | undefined
    let req: ClientRequest | undefined
    let response: IncomingMessage | undefined
    let agent: Agent | undefined
    let settled = false
    const finish = (error?: Error, ip?: string) => {
      if (settled) return
      settled = true
      clearTimeout(deadline)
      signal?.removeEventListener('abort', abort)
      // Retain physical socket ownership through close, including cancellation during SOCKS negotiation.
      const closed = [socket, secured].filter((value): value is Socket => !!value).map(owned =>
        owned.closed ? Promise.resolve() : new Promise<void>(done => owned.once('close', () => done())))
      response?.destroy(); req?.destroy(); secured?.destroy(); socket.destroy(); agent?.destroy()
      let closeDeadline: ReturnType<typeof setTimeout>
      void Promise.race([Promise.all(closed), new Promise<never>((_done, fail) => {
        closeDeadline = setTimeout(() => fail(new IpcFault('internal')), 250)
      })]).then(() => error ? reject(error) : resolve(ip!), reject).finally(() => clearTimeout(closeDeadline))
    }
    const abort = () => finish(new IpcFault('cancelled'))
    const deadline = setTimeout(() => finish(new IpcFault('timeout')), DEADLINE_MS)
    socket.on('error', () => finish(new IpcFault('network')))
    socket.once('connect', () => {
      void SocksClient.createConnection({
        proxy: { host: '127.0.0.1', port: upstream.port, type: 5, userId: upstream.username, password: upstream.password },
        destination: { host: HOST, port: 443 }, command: 'connect', timeout: DEADLINE_MS, existing_socket: socket
      }).then(connection => {
        if (settled) { connection.socket.destroy(); return }
        if (connection.socket !== socket) { connection.socket.destroy(); throw new Error('Unexpected SOCKS socket') }
        secured = connectTls({ socket, servername: HOST, rejectUnauthorized: true, ALPNProtocols: ['http/1.1'], minVersion: 'TLSv1.2' })
        secured.on('error', () => finish(new IpcFault('network')))
        agent = new Agent({ keepAlive: false, maxSockets: 1 })
        // A private agent consumes this exact TLS connection instead of allocating a direct connection.
        agent.createConnection = () => secured!
        req = request({ hostname: HOST, port: 443, path: '/', method: 'GET', agent,
          headers: { Accept: 'text/plain', Connection: 'close' } }, incoming => {
          response = incoming
          incoming.on('error', () => finish(new IpcFault('network')))
          incoming.once('aborted', () => finish(new IpcFault('network')))
          if (settled) { incoming.destroy(); return }
          if (incoming.statusCode !== 200) { finish(new IpcFault('network')); return }
          const chunks: Buffer[] = []
          let bytes = 0
          incoming.on('data', (chunk: Buffer) => {
            if (settled) return
            bytes += chunk.length
            if (bytes > MAX_BODY_BYTES) finish(new IpcFault('network'))
            else chunks.push(Buffer.from(chunk))
          })
          incoming.once('end', () => {
            if (settled) return
            const ip = Buffer.concat(chunks).toString('utf8').trim()
            if (!isIP(ip) || !isPublicIp(ip)) finish(new IpcFault('network'))
            else finish(undefined, ip)
          })
        })
        req.on('error', () => finish(new IpcFault('network')))
        req.end()
      }).catch(() => finish(new IpcFault('network')))
    })
    signal?.addEventListener('abort', abort, { once: true })
    if (signal?.aborted) abort()
    else { try { socket.connect(upstream.port, '127.0.0.1') } catch { finish(new IpcFault('network')) } }
  })
}
