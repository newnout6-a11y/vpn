// AT-00-003; AT-02-004; AT-10-004: verify candidate egress before selecting it.
import { Socket, isIP } from 'node:net'
import { connect as connectTls, type TLSSocket } from 'node:tls'
import { Agent, request } from 'node:https'
import type { ClientRequest, IncomingMessage } from 'node:http'
import { SocksClient } from 'socks'
import { isPublicIp } from './publicIp'
import { IpcFault } from '../shared/ipc-result'
import { logEvent } from './appLogger'

export interface SocksUpstream { port: number; username: string; password: string }
const HOSTS = ['api.ipify.org', 'icanhazip.com'] as const
const DEADLINE_MS = 2000
const MAX_BODY_BYTES = 4096
type ProbeStage = 'local-connect' | 'socks-handshake' | 'tls-handshake' | 'https-response' | 'response-body' | 'socket-close'
type ProbeCode = 'CONNECT_FAILED' | 'SOCKS_FAILED' | 'SOCKS_AUTH_REQUIRED' | 'TLS_FAILED' | 'HTTPS_FAILED' | 'HTTP_STATUS' |
  'SOCKS_AUTH_REJECTED' | 'SOCKS_UPSTREAM_REJECTED' | 'SOCKS_CLOSED' |
  'RESPONSE_TOO_LARGE' | 'INVALID_PUBLIC_IP' | 'SOCKET_CLOSE_UNCONFIRMED' | 'CANCELLED' | 'DEADLINE' | 'OK'

function socksFailureCode(error: unknown): ProbeCode {
  if (!(error instanceof Error)) return 'SOCKS_FAILED'
  if (error.message === 'Socks5 Authentication failed') return 'SOCKS_AUTH_REJECTED'
  if (error.message === 'Socket closed') return 'SOCKS_CLOSED'
  if (['Failure', 'NotAllowed', 'NetworkUnreachable', 'HostUnreachable', 'ConnectionRefused', 'TTLExpired',
    'CommandNotSupported', 'AddressNotSupported'].some(status => error.message === `Socks5 proxy rejected connection - ${status}`)) {
    return 'SOCKS_UPSTREAM_REJECTED'
  }
  return 'SOCKS_FAILED'
}

/** Every connection is carried by the owned SOCKS socket; no HTTP proxy env or direct fallback. */
export function probeSocksUpstream(upstream: SocksUpstream, signal?: AbortSignal): Promise<string> {
  if (!upstream || !Number.isInteger(upstream.port) || upstream.port < 1 || upstream.port > 65535 ||
      [upstream.username, upstream.password].some(value => typeof value !== 'string' ||
        Buffer.byteLength(value, 'utf8') < 1 || Buffer.byteLength(value, 'utf8') > 255)) {
    return Promise.reject(new IpcFault('validation'))
  }
  if (signal?.aborted) return Promise.reject(new IpcFault('cancelled'))
  return probeProviders(upstream, signal)
}

async function probeProviders(upstream: SocksUpstream, signal?: AbortSignal): Promise<string> {
  const deadlineAt = performance.now() + DEADLINE_MS
  const losers = new AbortController()
  const ownedSignal = signal ? AbortSignal.any([signal, losers.signal]) : losers.signal
  let selected: string | undefined
  const results = await Promise.allSettled(HOSTS.map((_host, providerIndex) =>
    probeProvider(upstream, providerIndex, deadlineAt, ownedSignal).then(ip => {
      if (!selected) { selected = ip; losers.abort() }
      return ip
    })))
  // A winner cannot release ownership while another socket's closure is unknown.
  const failures = results.filter((result): result is PromiseRejectedResult => result.status === 'rejected')
  const closeFailure = failures.find(result => result.reason?.category === 'internal')
  if (closeFailure) throw closeFailure.reason
  if (signal?.aborted) throw new IpcFault('cancelled')
  if (selected) return selected
  throw failures.find(result => result.reason?.category === 'timeout')?.reason ?? failures[0]?.reason ?? new IpcFault('network')
}

function probeProvider(upstream: SocksUpstream, providerIndex: number, deadlineAt: number, signal: AbortSignal): Promise<string> {
  return new Promise<string>((resolve, reject) => {
    const host = HOSTS[providerIndex]
    const began = performance.now()
    let stage: ProbeStage = 'local-connect'
    const socket = new Socket()
    let secured: TLSSocket | undefined
    let req: ClientRequest | undefined
    let response: IncomingMessage | undefined
    let agent: Agent | undefined
    let settled = false
    let authenticated = false
    let authReply = Buffer.alloc(0)
    const finish = (error?: IpcFault, ip?: string, code: ProbeCode = error ?
      (stage === 'local-connect' ? 'CONNECT_FAILED' : stage === 'socks-handshake' ? 'SOCKS_FAILED' :
        stage === 'tls-handshake' ? 'TLS_FAILED' : 'HTTPS_FAILED') : 'OK') => {
      if (settled) return
      settled = true
      clearTimeout(deadline)
      signal?.removeEventListener('abort', abort)
      socket.off('data', requirePasswordAuth)
      // Retain physical socket ownership through close, including cancellation during SOCKS negotiation.
      const closed = [socket, secured].filter((value): value is Socket => !!value).map(owned =>
        owned.closed ? Promise.resolve() : new Promise<void>(done => owned.once('close', () => done())))
      response?.destroy(); req?.destroy(); secured?.destroy(); socket.destroy(); agent?.destroy()
      let closeDeadline: ReturnType<typeof setTimeout>
      const complete = (closeFailed = false) => {
        const failure = closeFailed ? new IpcFault('internal') : error
        logEvent(failure ? 'warn' : 'debug', 'socks-upstream-probe', 'candidate egress probe completed', {
          providerIndex,
          stage: closeFailed ? 'socket-close' : stage,
          outcome: failure?.category ?? 'success', code: closeFailed ? 'SOCKET_CLOSE_UNCONFIRMED' : code,
          durationMs: Math.round(performance.now() - began)
        })
        if (failure) reject(failure)
        else resolve(ip!)
      }
      void Promise.race([Promise.all(closed), new Promise<never>((_done, fail) => {
        closeDeadline = setTimeout(() => fail(new IpcFault('internal')), 250)
      })]).then(() => complete(), () => complete(true)).finally(() => clearTimeout(closeDeadline))
    }
    const requirePasswordAuth = (chunk: Buffer) => {
      if (settled) return
      authReply = Buffer.concat([authReply, chunk.subarray(0, 2 - authReply.length)])
      if (authReply.length < 2) return
      socket.off('data', requirePasswordAuth)
      authenticated = authReply[0] === 5 && authReply[1] === 2
      if (!authenticated) finish(new IpcFault('network'), undefined, 'SOCKS_AUTH_REQUIRED')
    }
    const abort = () => finish(new IpcFault('cancelled'), undefined, 'CANCELLED')
    const deadline = setTimeout(() => finish(new IpcFault('timeout'), undefined, 'DEADLINE'), Math.max(0, deadlineAt - performance.now()))
    socket.on('error', () => finish(new IpcFault('network')))
    socket.once('connect', () => {
      stage = 'socks-handshake'
      // socks also offers NoAuth when credentials are present. A slot must
      // prove the server selected RFC1929 before the library may hand us TLS.
      socket.prependListener('data', requirePasswordAuth)
      void SocksClient.createConnection({
        proxy: { host: '127.0.0.1', port: upstream.port, type: 5, userId: upstream.username, password: upstream.password },
        destination: { host, port: 443 }, command: 'connect', timeout: Math.max(1, Math.ceil(deadlineAt - performance.now())), existing_socket: socket
      }).then(connection => {
        if (settled) { connection.socket.destroy(); return }
        if (connection.socket !== socket) { connection.socket.destroy(); throw new Error('Unexpected SOCKS socket') }
        if (!authenticated) { finish(new IpcFault('network'), undefined, 'SOCKS_AUTH_REQUIRED'); return }
        stage = 'tls-handshake'
        secured = connectTls({ socket, servername: host, rejectUnauthorized: true, ALPNProtocols: ['http/1.1'], minVersion: 'TLSv1.2' })
        secured.on('error', () => finish(new IpcFault('network')))
        secured.once('secureConnect', () => { if (!settled) stage = 'https-response' })
        agent = new Agent({ keepAlive: false, maxSockets: 1 })
        // A private agent consumes this exact TLS connection instead of allocating a direct connection.
        agent.createConnection = () => secured!
        req = request({ hostname: host, port: 443, path: '/', method: 'GET', agent,
          headers: { Accept: 'text/plain', Connection: 'close' } }, incoming => {
          response = incoming
          incoming.on('error', () => finish(new IpcFault('network')))
          incoming.once('aborted', () => finish(new IpcFault('network')))
          if (settled) { incoming.destroy(); return }
          stage = 'response-body'
          if (incoming.statusCode !== 200) { finish(new IpcFault('network'), undefined, 'HTTP_STATUS'); return }
          const chunks: Buffer[] = []
          let bytes = 0
          incoming.on('data', (chunk: Buffer) => {
            if (settled) return
            bytes += chunk.length
            if (bytes > MAX_BODY_BYTES) finish(new IpcFault('network'), undefined, 'RESPONSE_TOO_LARGE')
            else chunks.push(Buffer.from(chunk))
          })
          incoming.once('end', () => {
            if (settled) return
            const ip = Buffer.concat(chunks).toString('utf8').trim()
            if (!isIP(ip) || !isPublicIp(ip)) finish(new IpcFault('network'), undefined, 'INVALID_PUBLIC_IP')
            else finish(undefined, ip)
          })
        })
        req.on('error', () => finish(new IpcFault('network')))
        req.end()
      }).catch(error => finish(new IpcFault('network'), undefined,
        stage === 'socks-handshake' ? socksFailureCode(error) : undefined))
    })
    signal?.addEventListener('abort', abort, { once: true })
    if (signal?.aborted) abort()
    else { try { socket.connect(upstream.port, '127.0.0.1') } catch { finish(new IpcFault('network')) } }
  })
}
