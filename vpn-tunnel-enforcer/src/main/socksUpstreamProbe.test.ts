// AT-00-003; AT-02-004; AT-10-004: production probe over fully synthetic socket/TLS/HTTPS boundaries.
import { EventEmitter } from 'node:events'
import type { Socket as RealSocket } from 'node:net'
import type { TLSSocket } from 'node:tls'
import { spawn } from 'node:child_process'
import { mkdir, mkdtemp, writeFile, rm } from 'node:fs/promises'
import { join, resolve as resolvePath } from 'node:path'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { LOOPBACK_CERT, LOOPBACK_KEY } from '../../scripts/fixtures/socks-upstream-certificate'

const fixture = vi.hoisted(() => ({ sockets: [] as any[], tls: null as any, req: null as any,
  tlsSockets: [] as any[], requests: [] as any[], responseCallbacks: [] as any[],
  responseCallback: null as any, holdClose: false, socks: vi.fn(), tlsConnect: vi.fn(), request: vi.fn(), logEvent: vi.fn() }))
class FixtureSocket extends EventEmitter {
  closed = false
  destroyed = false
  connect = vi.fn((_port: number, _host: string) => { queueMicrotask(() => this.emit('connect')); return this })
  destroy = vi.fn(() => {
    this.destroyed = true
    if (!fixture.holdClose) { this.closed = true; this.emit('close') }
    return this
  })
}
vi.mock('./appLogger', () => ({ logEvent: fixture.logEvent }))

const upstream = { port: 51002, username: 'candidate-user', password: 'candidate-secret' }
const PROVIDER_HOSTS = ['cloudflare.com', 'api.ipify.org', 'icanhazip.com', 'api.myip.com'] as const
const providerIndexForHost = (host: string) => PROVIDER_HOSTS.indexOf(host as typeof PROVIDER_HOSTS[number])
let probe: typeof import('./socksUpstreamProbe').probeSocksUpstream
beforeEach(async () => {
  vi.resetModules(); vi.useFakeTimers(); vi.clearAllMocks()
  // Each test starts with synthetic boundaries, including after a real fixture.
  vi.doMock('node:net', async () => {
    const actual = await vi.importActual<typeof import('node:net')>('node:net')
    return { ...actual, Socket: class extends FixtureSocket { constructor() { super(); fixture.sockets.push(this) } } }
  })
  vi.doMock('node:tls', () => ({ connect: fixture.tlsConnect }))
  vi.doMock('socks', () => ({ SocksClient: { createConnection: fixture.socks } }))
  vi.doMock('node:https', () => ({ Agent: class { createConnection: any; destroy = vi.fn() }, request: fixture.request }))
  fixture.sockets = []; fixture.tls = null; fixture.req = null; fixture.holdClose = false
  fixture.responseCallback = null
  fixture.tlsSockets = []; fixture.requests = []; fixture.responseCallbacks = []
  fixture.socks.mockImplementation(async (options: any) => {
    options.existing_socket.emit('data', Buffer.from([5, 2]))
    return { socket: options.existing_socket }
  })
  fixture.tlsConnect.mockImplementation((options: any) => {
    const secured = new FixtureSocket(); fixture.tlsSockets[providerIndexForHost(options.servername)] = secured
    fixture.tls ??= secured
    return secured
  })
  fixture.request.mockImplementation((options: any, callback: any) => {
    const req = Object.assign(new EventEmitter(), { destroy: vi.fn(), end: vi.fn() })
    const providerIndex = providerIndexForHost(options.hostname)
    fixture.responseCallbacks[providerIndex] = callback; fixture.requests[providerIndex] = req
    fixture.responseCallback ??= callback; fixture.req ??= req
    return req
  })
  probe = (await import('./socksUpstreamProbe')).probeSocksUpstream
})

// AT-02-004: real Node/socks transports, confined to loopback.

async function realTransport(options: { trustCertificate?: boolean; holdResponse?: boolean; noAuth?: boolean; xray?: boolean; primaryFailure?: boolean } = {}) {
  vi.useRealTimers()
  const net = await vi.importActual<typeof import('node:net')>('node:net')
  const tls = await vi.importActual<typeof import('node:tls')>('node:tls')
  const https = await vi.importActual<typeof import('node:https')>('node:https')
  const socks = await vi.importActual<typeof import('socks')>('socks')
  const peers = new Set<RealSocket>(), clients: TLSSocket[] = [], destinations: string[] = []
  let authenticated = 0, requests = 0
  const own = (socket: RealSocket) => {
    peers.add(socket); socket.on('error', () => {}); socket.once('close', () => peers.delete(socket)); return socket
  }
  const endpoint = https.createServer({ key: LOOPBACK_KEY, cert: LOOPBACK_CERT }, (request, response) => {
    requests++
    if (!options.holdResponse) {
      const host = String(request.headers.host || '').split(':')[0]
      const failed = options.primaryFailure && ['cloudflare.com', 'api.ipify.org'].includes(host)
      const body = host === 'cloudflare.com' ? 'ip=8.8.8.8\n' : host === 'icanhazip.com' ? '8.8.8.8\n'
        : JSON.stringify({ ip: '8.8.8.8', country: 'ZZ' })
      response.writeHead(failed ? 503 : 200, { 'Content-Type': 'text/plain' }).end(body)
    }
  })
  endpoint.on('connection', own)
  endpoint.on('tlsClientError', () => {})
  const listen = (server: import('node:net').Server) => new Promise<number>((resolve, reject) => {
    server.once('error', reject)
    server.listen(0, '127.0.0.1', () => resolve((server.address() as import('node:net').AddressInfo).port))
  })
  const endpointPort = await listen(endpoint)
  const proxy = net.createServer(socket => {
    own(socket)
    let phase = 0, buffered = Buffer.alloc(0)
    const receive = (chunk: Buffer) => {
      buffered = Buffer.concat([buffered, chunk])
      if (phase === 0) {
        if (buffered.length < 2 || buffered.length < 2 + buffered[1]) return
        const length = 2 + buffered[1]
        if (buffered[0] !== 5 || !buffered.subarray(2, length).includes(2)) { socket.end(Buffer.from([5, 255])); return }
        buffered = buffered.subarray(length); phase = options.noAuth ? 2 : 1
        if (options.noAuth) {
          // Fragment the method reply to exercise the mandatory auth guard.
          socket.write(Buffer.from([5])); setImmediate(() => socket.write(Buffer.from([0])))
        } else socket.write(Buffer.from([5, 2]))
      }
      if (phase === 1) {
        if (buffered.length < 2 || buffered.length < 3 + buffered[1]) return
        const usernameEnd = 2 + buffered[1], length = usernameEnd + 1 + buffered[usernameEnd]
        if (buffered.length < length) return
        const valid = buffered[0] === 1 && buffered.subarray(2, usernameEnd).toString() === upstream.username &&
          buffered.subarray(usernameEnd + 1, length).toString() === upstream.password
        if (!valid) { socket.end(Buffer.from([1, 1])); return }
        authenticated++; buffered = buffered.subarray(length); phase = 2; socket.write(Buffer.from([1, 0]))
      }
      if (phase === 2) {
        if (buffered.length < 5) return
        if (buffered[0] !== 5 || buffered[1] !== 1 || buffered[3] !== 3) { socket.destroy(); return }
        const length = 7 + buffered[4]
        if (buffered.length < length) return
        const destination = `${buffered.subarray(5, length - 2).toString()}:${buffered.readUInt16BE(length - 2)}`
        destinations.push(destination)
        if (!PROVIDER_HOSTS.some(host => `${host}:443` === destination)) { socket.destroy(); return }
        const trailing = buffered.subarray(length)
        phase = 3; socket.off('data', receive)
        // Only the requested logical endpoint is rewritten, always to our own listener.
        const target = own(net.connect(endpointPort, '127.0.0.1', () => {
          socket.write(Buffer.from([5, 0, 0, 1, 127, 0, 0, 1, endpointPort >> 8, endpointPort & 255]))
          if (trailing.length) target.write(trailing)
          socket.pipe(target); target.pipe(socket)
        }))
        socket.once('close', () => target.destroy()); target.once('close', () => socket.destroy())
      }
    }
    socket.on('data', receive)
  })
  const port = await listen(proxy)
  let xray: ReturnType<typeof spawn> | undefined, directory: string | undefined
  const stopXray = async () => {
    if (xray && xray.exitCode === null && xray.signalCode === null) {
      const closed = new Promise<void>(done => xray!.once('close', () => done()))
      xray.kill()
      let timer: ReturnType<typeof setTimeout>
      try { await Promise.race([closed, new Promise<never>((_done, fail) => {
        timer = setTimeout(() => fail(new Error('Loopback Xray exit not confirmed')), 2000)
      })]) } finally { clearTimeout(timer!) }
    }
    if (directory) {
      if (resolvePath(directory, '..') !== resolvePath('.tmp')) throw new Error('Invalid loopback fixture directory')
      await rm(directory, { recursive: true, force: true })
    }
  }
  if (options.xray) {
    await new Promise<void>(done => proxy.close(() => done()))
    await mkdir(resolvePath('.tmp'), { recursive: true })
    directory = await mkdtemp(join(resolvePath('.tmp'), 'socks-xray-'))
    const configPath = join(directory, 'xray.json')
    await writeFile(configPath, JSON.stringify({ log: { loglevel: 'none' },
      inbounds: [{ listen: '127.0.0.1', port, protocol: 'socks', settings: {
        auth: 'password', accounts: [{ user: upstream.username, pass: upstream.password }], udp: false } }],
      outbounds: [{ protocol: 'freedom', settings: { redirect: `127.0.0.1:${endpointPort}` } }]
    }))
    xray = spawn(resolvePath('resources/xray.exe'), ['run', '-c', configPath], { windowsHide: true, stdio: 'ignore' })
    const childStarted = new Promise<void>((done, fail) => { xray!.once('spawn', () => done()); xray!.once('error', fail) })
    try {
      await childStarted
      await vi.waitFor(async () => {
        if (xray!.exitCode !== null) throw new Error('Loopback Xray exited before readiness')
        await new Promise<void>((done, fail) => {
          const readiness = net.connect(port, '127.0.0.1', () => { readiness.destroy(); done() })
          readiness.once('error', fail)
        })
      }, { timeout: 2000, interval: 10 })
    } catch (error) { await stopXray(); await new Promise<void>(done => endpoint.close(() => done())); throw error }
  }
  vi.doMock('node:net', () => net)
  vi.doMock('socks', () => socks)
  vi.doMock('node:https', () => https)
  vi.doMock('node:tls', () => ({ ...tls, connect: (connection: import('node:tls').ConnectionOptions) => {
    if (!connection.socket) throw new Error('Fixture forbids unowned TLS connections')
    const secured = tls.connect({ ...connection, ...(options.trustCertificate === false ? {} : { ca: LOOPBACK_CERT }) })
    clients.push(secured)
    return secured
  } }))
  vi.resetModules()
  const realProbe = (await import('./socksUpstreamProbe')).probeSocksUpstream
  return {
    probe: (signal?: AbortSignal, password = upstream.password) => realProbe({ ...upstream, port, password }, signal),
    get authenticated() { return authenticated }, get requests() { return requests }, destinations, clients,
    async drained() { await vi.waitFor(() => { expect(peers.size).toBe(0); expect(clients.every(socket => socket.closed)).toBe(true) }, { timeout: 1000 }) },
    async close() {
      for (const socket of peers) socket.destroy()
      for (const socket of clients) socket.destroy()
      await stopXray()
      await Promise.all([proxy, endpoint].map(server => new Promise<void>(resolve => server.close(() => resolve()))))
    }
  }
}

describe('real authenticated SOCKS5 → verified TLS → HTTPS loopback transport', () => {
  it.skipIf(process.platform !== 'win32')('passes through the actual bundled Xray SOCKS inbound and verified loopback TLS', async () => {
    const transport = await realTransport({ xray: true })
    try {
      await expect(transport.probe()).resolves.toBe('8.8.8.8')
      expect(transport.requests).toBeGreaterThanOrEqual(1)
      expect(transport.clients.length).toBeGreaterThanOrEqual(1)
      expect(transport.clients.every(socket => socket.authorized)).toBe(true)
      await transport.drained()
    } finally { await transport.close() }
  }, 10000)
  it('rejects a server selecting NoAuth before creating TLS or HTTP', async () => {
    const transport = await realTransport({ noAuth: true })
    try {
      await expect(transport.probe()).rejects.toMatchObject({ category: 'network' })
      expect(transport.authenticated).toBe(0); expect(transport.clients).toHaveLength(0); expect(transport.requests).toBe(0)
      const { logEvent } = await import('./appLogger')
      expect(logEvent).toHaveBeenLastCalledWith('warn', 'socks-upstream-probe', 'candidate egress probe completed',
        expect.objectContaining({ stage: 'socks-handshake', code: 'SOCKS_AUTH_REQUIRED', outcome: 'network' }))
      await transport.drained()
    } finally { await transport.close() }
  })
  it('returns a public address through the authenticated owned socket using the real socks and HTTPS libraries', async () => {
    const transport = await realTransport()
    try {
      await expect(transport.probe()).resolves.toBe('8.8.8.8')
      expect(transport.authenticated).toBeGreaterThanOrEqual(1); expect(transport.requests).toBeGreaterThanOrEqual(1)
      expect(transport.destinations).toContain('cloudflare.com:443')
      expect(transport.destinations.every(destination => PROVIDER_HOSTS.some(host => `${host}:443` === destination))).toBe(true)
      expect(transport.clients.every(socket => socket.authorized)).toBe(true)
      expect(fixture.logEvent).toHaveBeenCalledWith('debug', 'socks-upstream-probe', 'candidate egress probe completed',
        { providerIndex: expect.any(Number), stage: 'response-body', outcome: 'success', code: 'OK', durationMs: expect.any(Number) })
      await transport.drained()
    } finally { await transport.close() }
  })
  it('uses a second fixed provider when the first returns503, with actual authenticated SOCKS and verified TLS', async () => {
    const transport = await realTransport({ primaryFailure: true })
    try {
      await expect(transport.probe()).resolves.toBe('8.8.8.8')
      expect(transport.destinations.some(destination => ['icanhazip.com:443', 'api.myip.com:443'].includes(destination))).toBe(true)
      expect(transport.clients.every(socket => socket.authorized)).toBe(true)
      expect(fixture.logEvent.mock.calls.some(call => call[0] === 'debug' && call[3].code === 'OK' && [2, 3].includes(call[3].providerIndex))).toBe(true)
      await transport.drained()
    } finally { await transport.close() }
  })
  it('rejects wrong SOCKS credentials before opening TLS or HTTPS', async () => {
    const transport = await realTransport()
    try {
      await expect(transport.probe(undefined, 'wrong-password')).rejects.toMatchObject({ category: 'network' })
      expect(transport.authenticated).toBe(0); expect(transport.requests).toBe(0); expect(transport.clients).toHaveLength(0)
      expect(fixture.logEvent.mock.calls[0][3]).toMatchObject({ stage: 'socks-handshake', code: 'SOCKS_AUTH_REJECTED' })
      await transport.drained()
    } finally { await transport.close() }
  })
  it('rejects the untrusted certificate with real verification enabled', async () => {
    const transport = await realTransport({ trustCertificate: false })
    try {
      await expect(transport.probe()).rejects.toMatchObject({ category: 'network' })
      expect(transport.authenticated).toBe(4); expect(transport.requests).toBe(0)
      expect(transport.clients[0].authorized).toBe(false)
      expect(fixture.logEvent.mock.calls[0][3]).toMatchObject({ stage: 'tls-handshake', code: 'TLS_FAILED' })
      await transport.drained()
    } finally { await transport.close() }
  })
  it('aborts an in-flight HTTPS response and closes the real sockets', async () => {
    const transport = await realTransport({ holdResponse: true }), controller = new AbortController()
    try {
      const pending = transport.probe(controller.signal)
      const failed = expect(pending).rejects.toMatchObject({ category: 'cancelled' })
      await vi.waitFor(() => expect(transport.requests).toBe(4))
      controller.abort(); await failed; await transport.drained()
    } finally { await transport.close() }
  })
  it('bounds a stalled real HTTPS response by the common deadline and closes the real sockets', async () => {
    const transport = await realTransport({ holdResponse: true })
    try {
      await expect(transport.probe()).rejects.toMatchObject({ category: 'timeout' })
      expect(transport.requests).toBe(4); await transport.drained()
    } finally { await transport.close() }
  })
})
afterEach(() => { vi.useRealTimers() })
async function running(signal?: AbortSignal) {
  const pending = probe(upstream, signal)
  await vi.waitFor(() => expect(fixture.req).not.toBeNull())
  return { pending }
}
function respond(body: string, statusCode = 200, providerIndex?: number) {
  const response = Object.assign(new EventEmitter(), { statusCode, destroy: vi.fn() })
  const targets = providerIndex === undefined
    ? fixture.responseCallbacks.map((callback, index) => ({ callback, index })).filter(item => item.callback)
    : [{ callback: fixture.responseCallbacks[providerIndex], index: providerIndex }]
  for (const { callback, index } of targets) {
    const formatted = statusCode === 200 && isPublicIpForFixture(body)
      ? index === 0 ? `ip=${body.trim()}\n` : index === 1 || index === 3 ? JSON.stringify({ ip: body.trim() }) : `${body.trim()}\n`
      : body
    callback(response)
    response.emit('data', Buffer.from(formatted.slice(0, 2)))
    response.emit('data', Buffer.from(formatted.slice(2)))
    response.emit('end')
  }
  return response
}
function respondOne(index: number, body: string, statusCode = 200) {
  const response = Object.assign(new EventEmitter(), { statusCode, destroy: vi.fn() })
  const callback = fixture.responseCallbacks[index]
  if (!callback) throw new Error(`Missing provider callback ${index}`)
  const formatted = statusCode === 200 && isPublicIpForFixture(body)
    ? index === 0 ? `ip=${body.trim()}\n` : index === 1 || index === 3 ? JSON.stringify({ ip: body.trim() }) : `${body.trim()}\n`
    : body
  callback(response)
  response.emit('data', Buffer.from(formatted.slice(0, 2)))
  response.emit('data', Buffer.from(formatted.slice(2)))
  response.emit('end')
}
function isPublicIpForFixture(body: string): boolean {
  const value = body.trim()
  return value === '8.8.8.8' || value === '8.8.4.4' || value === '2606:4700:4700::1111'
}

describe('authenticated candidate egress probe', () => {
  it.each(PROVIDER_HOSTS.map((host, index) => [host, index] as const))('parses the fixed response format for %s', async (_host, index) => {
    const { pending } = await running()
    for (let other = 0; other < PROVIDER_HOSTS.length; other++) if (other !== index) respondOne(other, 'unavailable', 503)
    respondOne(index, '8.8.8.8')
    await expect(pending).resolves.toBe('8.8.8.8')
  })
  it.each(['8.8.8.8'])('accepts a complete HTTPS200 public address %s through the exact authenticated SOCKS socket', async ip => {
    const { pending } = await running()
    respond(` ${ip}\n`)
    await expect(pending).resolves.toBe(ip)
    expect(fixture.sockets[0].connect).toHaveBeenCalledWith(51002, '127.0.0.1')
    expect(fixture.socks).toHaveBeenCalledWith(expect.objectContaining({ existing_socket: fixture.sockets[0],
      proxy: { host: '127.0.0.1', port: 51002, type: 5, userId: upstream.username, password: upstream.password },
      destination: { host: 'cloudflare.com', port: 443 }, command: 'connect', timeout: expect.any(Number)
    }))
    expect(fixture.socks.mock.calls.every(call => call[0].timeout > 0 && call[0].timeout <= 2000)).toBe(true)
    expect(fixture.tlsConnect).toHaveBeenCalledWith({ socket: fixture.sockets[0], servername: 'cloudflare.com',
      rejectUnauthorized: true, ALPNProtocols: ['http/1.1'], minVersion: 'TLSv1.2' })
    const options = fixture.request.mock.calls[0][0]
    expect(options).toMatchObject({ hostname: 'cloudflare.com', port: 443, path: '/cdn-cgi/trace', method: 'GET' })
    expect(options.agent.createConnection()).toBe(fixture.tls)
    expect(JSON.stringify(options.headers)).not.toContain(upstream.password)
    expect(fixture.req.end).toHaveBeenCalledOnce()
    expect(fixture.sockets.every(socket => socket.closed)).toBe(true); expect(fixture.tlsSockets.every(socket => socket.closed)).toBe(true)
    expect(vi.getTimerCount()).toBe(0)
  })
  it('rejects public IPv6 egress and drains every provider instead of returning a different TUN address family (AT-10-004)', async () => {
    const { pending } = await running()
    const failed = expect(pending).rejects.toMatchObject({ category: 'network' })
    respond('2606:4700:4700::1111'); await failed
    expect(fixture.logEvent.mock.calls.every(call => call[3].code === 'INVALID_PUBLIC_IP')).toBe(true)
    expect(fixture.sockets.every(socket => socket.closed)).toBe(true)
    expect(fixture.tlsSockets.every(socket => socket.closed)).toBe(true)
    expect(vi.getTimerCount()).toBe(0)
  })
  it('keeps waiting after a fast IPv6 echo and returns the later IPv4 proof with all sockets closed (AT-10-004)', async () => {
    const { pending } = await running(), finished = vi.fn()
    const result = pending.then(ip => { finished(); return ip })
    respondOne(0, '2606:4700:4700::1111')
    await vi.advanceTimersByTimeAsync(0)
    expect(finished).not.toHaveBeenCalled()
    expect(fixture.sockets[0].closed).toBe(true)
    expect(fixture.tlsSockets[0].closed).toBe(true)
    expect(fixture.requests[1].destroy).not.toHaveBeenCalled()
    respondOne(1, '8.8.4.4')
    await expect(result).resolves.toBe('8.8.4.4')
    expect(fixture.sockets.every(socket => socket.closed)).toBe(true)
    expect(fixture.tlsSockets.every(socket => socket.closed)).toBe(true)
    expect(vi.getTimerCount()).toBe(0)
  })
  it.each(['', '127.0.0.1', '10.0.0.1', '100.64.0.1', '192.0.2.1', '::1', '2001:db8::1', '8.8.8.8 garbage', '[8.8.8.8]'])(
    'refuses a nonpublic or malformed body %j', async body => {
      const { pending } = await running()
      const failed = expect(pending).rejects.toMatchObject({ category: 'network' })
      respond(body); await failed
      expect(fixture.req.destroy).toHaveBeenCalledOnce()
    })
  it('accepts a fixed backup provider after a primary HTTP failure and closes every owned socket (AT-07-003)', async () => {
    const { pending } = await running()
    respond('unavailable', 503, 0)
    respond('8.8.4.4', 200, 1)
    await expect(pending).resolves.toBe('8.8.4.4')
    expect(fixture.socks).toHaveBeenCalledTimes(4)
    expect(fixture.sockets.every(socket => socket.closed)).toBe(true)
    expect(fixture.tlsSockets.every(socket => socket.closed)).toBe(true)
    expect(fixture.logEvent.mock.calls.some(call => call[0] === 'debug' && call[1] === 'socks-upstream-probe' &&
      call[3]?.code === 'OK' && Number(call[3]?.providerIndex) > 0)).toBe(true)
    expect(vi.getTimerCount()).toBe(0)
  })
  it('uses the backup while primary SOCKS is held and closes a late primary negotiation result (AT-02-004)', async () => {
    let release!: (value: any) => void
    fixture.socks.mockImplementationOnce(() => new Promise(resolve => { release = resolve }))
    const { pending } = await running()
    respond('8.8.4.4', 200, 1)
    await expect(pending).resolves.toBe('8.8.4.4')
    expect(fixture.sockets.every(socket => socket.closed)).toBe(true)
    release({ socket: fixture.sockets[0] }); await vi.advanceTimersByTimeAsync(0)
    expect(fixture.tlsConnect).toHaveBeenCalledTimes(3); expect(fixture.request).toHaveBeenCalledTimes(3)
    expect(vi.getTimerCount()).toBe(0)
  })
  it('keeps one total2s deadline when a provider fails near its end (AT-02-004)', async () => {
    const began = Date.now(), { pending } = await running(), finished = vi.fn()
    const failed = expect(pending.finally(finished)).rejects.toMatchObject({ category: 'timeout' })
    await vi.advanceTimersByTimeAsync(1900 - (Date.now() - began))
    respond('unavailable', 503, 0)
    await vi.advanceTimersByTimeAsync(99)
    expect(finished).not.toHaveBeenCalled()
    await vi.advanceTimersByTimeAsync(1); await failed
    expect(Date.now() - began).toBe(2000)
    expect(fixture.sockets.every(socket => socket.closed)).toBe(true)
    expect(fixture.tlsSockets.every(socket => socket.closed)).toBe(true)
    expect(vi.getTimerCount()).toBe(0)
  })
  it.each([false, true])('drains losing sockets before success and rejects unconfirmed closure=%s (AT-00-003)', async closeFails => {
    const { pending } = await running(), finished = vi.fn()
    // The selected provider closes normally, then aborts this held loser.
    const held = [fixture.sockets[0], fixture.tlsSockets[0]]
    for (const owned of held) owned.destroy.mockImplementation(() => { owned.destroyed = true; return owned })
    const result = pending.then(ip => { finished(); return ip }, error => { finished(); return error })
    respond('8.8.4.4', 200, 1)
    await vi.advanceTimersByTimeAsync(100)
    expect(finished).not.toHaveBeenCalled()
    expect(held.every(owned => owned.destroyed && !owned.closed)).toBe(true)
    if (closeFails) await vi.advanceTimersByTimeAsync(150)
    else for (const owned of held) { owned.closed = true; owned.emit('close') }
    if (closeFails) expect(await result).toMatchObject({ category: 'internal' })
    else expect(await result).toBe('8.8.4.4')
    for (const owned of held) { owned.closed = true; owned.emit('close') }
    expect(vi.getTimerCount()).toBe(0)
  })
  it('refuses redirects and non200 responses without following either provider redirect', async () => {
    const { pending } = await running()
    const failed = expect(pending).rejects.toMatchObject({ category: 'network' })
    respond('8.8.8.8', 302); await failed
    expect(fixture.request).toHaveBeenCalledTimes(4)
  })
  it('refuses oversized responses and physically closes both owned sockets', async () => {
    const { pending } = await running()
    const failed = expect(pending).rejects.toMatchObject({ category: 'network' })
    respond('8'.repeat(4097)); await failed
    expect(fixture.sockets.every(socket => socket.destroy.mock.calls.length > 0)).toBe(true)
    expect(fixture.tlsSockets.every(socket => socket.destroy.mock.calls.length > 0)).toBe(true)
    expect(vi.getTimerCount()).toBe(0)
  })
  it('bounds a held SOCKS negotiation by the common2s deadline and closes a late result', async () => {
    let release!: (value: any) => void
    fixture.socks.mockReturnValue(new Promise(resolve => { release = resolve }))
    const pending = probe(upstream)
    const failed = expect(pending).rejects.toMatchObject({ category: 'timeout' })
    await vi.advanceTimersByTimeAsync(2000); await failed
    expect(fixture.sockets.every(socket => socket.closed)).toBe(true)
    release({ socket: fixture.sockets[0] }); await vi.advanceTimersByTimeAsync(0)
    expect(fixture.tlsConnect).not.toHaveBeenCalled(); expect(fixture.request).not.toHaveBeenCalled()
    expect(vi.getTimerCount()).toBe(0)
  })
  it('cancels pending SOCKS negotiation immediately with sanitized error and no late HTTPS', async () => {
    const controller = new AbortController()
    let release!: (value: any) => void
    fixture.socks.mockReturnValue(new Promise(resolve => { release = resolve }))
    const pending = probe(upstream, controller.signal)
    const failed = expect(pending).rejects.toMatchObject({ category: 'cancelled' })
    await vi.waitFor(() => expect(fixture.socks).toHaveBeenCalledTimes(4))
    controller.abort(); await failed
    expect(fixture.sockets[0].closed).toBe(true)
    release({ socket: fixture.sockets[0] }); await vi.advanceTimersByTimeAsync(0)
    expect(fixture.request).not.toHaveBeenCalled(); expect(vi.getTimerCount()).toBe(0)
  })
  it('drains request and TLS on cancellation during the response and ignores queued response completion', async () => {
    const controller = new AbortController()
    const { pending } = await running(controller.signal)
    const failed = expect(pending).rejects.toMatchObject({ category: 'cancelled' })
    const response = Object.assign(new EventEmitter(), { statusCode: 200, destroy: vi.fn() })
    fixture.responseCallback(response)
    controller.abort(); await failed
    response.emit('data', Buffer.from('8.8.8.8')); response.emit('end')
    expect(response.destroy).toHaveBeenCalledOnce(); expect(fixture.req.destroy).toHaveBeenCalledOnce()
    expect(fixture.sockets.every(socket => socket.closed)).toBe(true)
    expect(fixture.tlsSockets.every(socket => socket.closed)).toBe(true)
    expect(vi.getTimerCount()).toBe(0)
  })
  it('rejects TLS verification failure rather than accepting an HTTP fixture response', async () => {
    const { pending } = await running()
    const failed = expect(pending).rejects.toMatchObject({ category: 'network' })
    for (const secured of fixture.tlsSockets) secured.emit('error', new Error('certificate mismatch'))
    respond('8.8.8.8'); await failed
  })
  it.each(['ECONNRESET', 'ERR_TLS_CERT_ALTNAME_INVALID'])('records only the bounded native TLS code %s', async code => {
    const { pending } = await running()
    const failed = expect(pending).rejects.toMatchObject({ category: 'network' })
    for (const secured of fixture.tlsSockets) secured.emit('error', Object.assign(new Error(upstream.password), { code }))
    await failed
    expect(fixture.logEvent.mock.calls.every(call => call[3].nativeCode === code)).toBe(true)
    expect(JSON.stringify(fixture.logEvent.mock.calls)).not.toContain(upstream.password)
  })
  it('captures synchronous HTTPS setup errors without exposing their messages', async () => {
    fixture.request.mockImplementation(() => { throw Object.assign(new Error(upstream.password), { code: 'ERR_INVALID_ARG_TYPE' }) })
    await expect(probe(upstream)).rejects.toMatchObject({ category: 'network' })
    expect(fixture.logEvent.mock.calls.every(call => call[3].nativeCode === 'ERR_INVALID_ARG_TYPE')).toBe(true)
    expect(JSON.stringify(fixture.logEvent.mock.calls)).not.toContain(upstream.password)
  })
  it('omits unknown native codes even when their strings contain a credential', async () => {
    const { pending } = await running()
    const failed = expect(pending).rejects.toMatchObject({ category: 'network' })
    for (const secured of fixture.tlsSockets) secured.emit('error', Object.assign(new Error(upstream.password), { code: upstream.password }))
    await failed
    expect(fixture.logEvent.mock.calls.every(call => !('nativeCode' in call[3]))).toBe(true)
    expect(JSON.stringify(fixture.logEvent.mock.calls)).not.toContain(upstream.password)
  })
  it('does not report success when physical socket closure cannot be confirmed', async () => {
    const { pending } = await running()
    fixture.holdClose = true
    const failed = expect(pending).rejects.toMatchObject({ category: 'internal' })
    respond('8.8.8.8')
    await vi.advanceTimersByTimeAsync(250); await failed
    for (const socket of [...fixture.sockets, ...fixture.tlsSockets]) { socket.closed = true; socket.emit('close') }
    expect(vi.getTimerCount()).toBe(0)
  })
  it('sanitizes SOCKS errors that contain credentials', async () => {
    fixture.socks.mockRejectedValue(new Error(`authentication failed ${upstream.password}`))
    const failed = await probe(upstream).catch(error => error)
    expect(failed.category).toBe('network'); expect(failed.message).not.toContain(upstream.password)
    expect(JSON.stringify(fixture.logEvent.mock.calls)).not.toContain(upstream.password)
    expect(JSON.stringify(fixture.logEvent.mock.calls)).not.toContain(upstream.username)
    for (const call of fixture.logEvent.mock.calls) {
      expect(Object.keys(call[3]).sort()).toEqual(['code', 'durationMs', 'outcome', 'providerIndex', 'stage'])
      expect([0, 1, 2, 3]).toContain(call[3].providerIndex)
    }
    expect(fixture.logEvent.mock.calls[0][3]).toMatchObject({ stage: 'socks-handshake', code: 'SOCKS_FAILED' })
  })
  it.each([
    ['Socks5 Authentication failed', 'SOCKS_AUTH_REJECTED'],
    ['Socks5 proxy rejected connection - ConnectionRefused', 'SOCKS_UPSTREAM_REJECTED'],
    ['Socket closed', 'SOCKS_CLOSED']
  ])('maps only exact library failure %s to the fixed diagnostic %s', async (message, code) => {
    fixture.socks.mockRejectedValue(new Error(message))
    await expect(probe(upstream)).rejects.toMatchObject({ category: 'network' })
    expect(fixture.logEvent.mock.calls[0][3]).toMatchObject({ stage: 'socks-handshake', code })
    expect(JSON.stringify(fixture.logEvent.mock.calls)).not.toContain(message)
  })
  it('validates before allocating handles and rejects an already aborted owner', async () => {
    await expect(probe({ ...upstream, port: 0 })).rejects.toMatchObject({ category: 'validation' })
    await expect(probe({ ...upstream, password: 'я'.repeat(128) })).rejects.toMatchObject({ category: 'validation' })
    const controller = new AbortController(); controller.abort()
    await expect(probe(upstream, controller.signal)).rejects.toMatchObject({ category: 'cancelled' })
    expect(fixture.sockets).toHaveLength(0); expect(vi.getTimerCount()).toBe(0)
  })
})
