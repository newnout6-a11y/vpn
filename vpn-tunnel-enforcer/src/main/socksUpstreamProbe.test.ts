// AT-00-003; AT-02-004; AT-10-004: production probe over fully synthetic socket/TLS/HTTPS boundaries.
import { EventEmitter } from 'node:events'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

const fixture = vi.hoisted(() => ({ sockets: [] as any[], tls: null as any, req: null as any,
  responseCallback: null as any, holdClose: false, socks: vi.fn(), tlsConnect: vi.fn(), request: vi.fn() }))
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
vi.mock('node:net', async importActual => {
  const actual = await importActual<typeof import('node:net')>()
  return { ...actual, Socket: class extends FixtureSocket { constructor() { super(); fixture.sockets.push(this) } } }
})
vi.mock('node:tls', () => ({ connect: fixture.tlsConnect }))
vi.mock('socks', () => ({ SocksClient: { createConnection: fixture.socks } }))
vi.mock('node:https', () => ({ Agent: class { createConnection: any; destroy = vi.fn() }, request: fixture.request }))

const upstream = { port: 51002, username: 'candidate-user', password: 'candidate-secret' }
let probe: typeof import('./socksUpstreamProbe').probeSocksUpstream
beforeEach(async () => {
  vi.resetModules(); vi.useFakeTimers(); vi.clearAllMocks()
  fixture.sockets = []; fixture.tls = null; fixture.req = null; fixture.holdClose = false
  fixture.socks.mockImplementation(async (options: any) => ({ socket: options.existing_socket }))
  fixture.tlsConnect.mockImplementation(() => { fixture.tls = new FixtureSocket(); return fixture.tls })
  fixture.request.mockImplementation((_options: any, callback: any) => {
    fixture.responseCallback = callback
    fixture.req = Object.assign(new EventEmitter(), { destroy: vi.fn(), end: vi.fn() })
    return fixture.req
  })
  probe = (await import('./socksUpstreamProbe')).probeSocksUpstream
})
afterEach(() => { vi.useRealTimers() })
async function running(signal?: AbortSignal) {
  const pending = probe(upstream, signal)
  await vi.waitFor(() => expect(fixture.req).not.toBeNull())
  return { pending }
}
function respond(body: string, statusCode = 200) {
  const response = Object.assign(new EventEmitter(), { statusCode, destroy: vi.fn() })
  fixture.responseCallback(response)
  response.emit('data', Buffer.from(body.slice(0, 2)))
  response.emit('data', Buffer.from(body.slice(2)))
  response.emit('end')
  return response
}

describe('authenticated candidate egress probe', () => {
  it.each(['8.8.8.8', '2606:4700:4700::1111'])('accepts a complete HTTPS200 public address %s through the exact authenticated SOCKS socket', async ip => {
    const { pending } = await running()
    respond(` ${ip}\n`)
    await expect(pending).resolves.toBe(ip)
    expect(fixture.sockets[0].connect).toHaveBeenCalledWith(51002, '127.0.0.1')
    expect(fixture.socks).toHaveBeenCalledWith(expect.objectContaining({ existing_socket: fixture.sockets[0],
      proxy: { host: '127.0.0.1', port: 51002, type: 5, userId: upstream.username, password: upstream.password },
      destination: { host: 'api.ipify.org', port: 443 }, command: 'connect', timeout: 2000
    }))
    expect(fixture.tlsConnect).toHaveBeenCalledWith({ socket: fixture.sockets[0], servername: 'api.ipify.org',
      rejectUnauthorized: true, ALPNProtocols: ['http/1.1'], minVersion: 'TLSv1.2' })
    const options = fixture.request.mock.calls[0][0]
    expect(options).toMatchObject({ hostname: 'api.ipify.org', port: 443, path: '/', method: 'GET' })
    expect(options.agent.createConnection()).toBe(fixture.tls)
    expect(JSON.stringify(options.headers)).not.toContain(upstream.password)
    expect(fixture.req.end).toHaveBeenCalledOnce()
    expect(fixture.sockets[0].closed).toBe(true); expect(fixture.tls.closed).toBe(true)
    expect(vi.getTimerCount()).toBe(0)
  })
  it.each(['', '127.0.0.1', '10.0.0.1', '100.64.0.1', '192.0.2.1', '::1', '2001:db8::1', '8.8.8.8 garbage', '[8.8.8.8]', '{"ip":"8.8.8.8"}'])(
    'refuses a nonpublic or malformed body %j', async body => {
      const { pending } = await running()
      const failed = expect(pending).rejects.toMatchObject({ category: 'network' })
      respond(body); await failed
      expect(fixture.req.destroy).toHaveBeenCalledOnce()
    })
  it('refuses redirects and non200 responses without a second request', async () => {
    const { pending } = await running()
    const failed = expect(pending).rejects.toMatchObject({ category: 'network' })
    respond('8.8.8.8', 302); await failed
    expect(fixture.request).toHaveBeenCalledOnce()
  })
  it('refuses oversized responses and physically closes both owned sockets', async () => {
    const { pending } = await running()
    const failed = expect(pending).rejects.toMatchObject({ category: 'network' })
    respond('8'.repeat(4097)); await failed
    expect(fixture.sockets[0].destroy).toHaveBeenCalled(); expect(fixture.tls.destroy).toHaveBeenCalled()
    expect(vi.getTimerCount()).toBe(0)
  })
  it('bounds a held SOCKS negotiation by the common2s deadline and closes a late result', async () => {
    let release!: (value: any) => void
    fixture.socks.mockReturnValue(new Promise(resolve => { release = resolve }))
    const pending = probe(upstream)
    const failed = expect(pending).rejects.toMatchObject({ category: 'timeout' })
    await vi.advanceTimersByTimeAsync(2000); await failed
    expect(fixture.sockets[0].closed).toBe(true)
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
    await vi.waitFor(() => expect(fixture.socks).toHaveBeenCalledOnce())
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
    expect(vi.getTimerCount()).toBe(0)
  })
  it('rejects TLS verification failure rather than accepting an HTTP fixture response', async () => {
    const { pending } = await running()
    const failed = expect(pending).rejects.toMatchObject({ category: 'network' })
    fixture.tls.emit('error', new Error('certificate mismatch'))
    respond('8.8.8.8'); await failed
  })
  it('does not report success when physical socket closure cannot be confirmed', async () => {
    const { pending } = await running()
    fixture.holdClose = true
    const failed = expect(pending).rejects.toMatchObject({ category: 'internal' })
    respond('8.8.8.8')
    await vi.advanceTimersByTimeAsync(250); await failed
    for (const socket of [fixture.sockets[0], fixture.tls]) { socket.closed = true; socket.emit('close') }
    expect(vi.getTimerCount()).toBe(0)
  })
  it('sanitizes SOCKS errors that contain credentials', async () => {
    fixture.socks.mockRejectedValue(new Error(`authentication failed ${upstream.password}`))
    const failed = await probe(upstream).catch(error => error)
    expect(failed.category).toBe('network'); expect(failed.message).not.toContain(upstream.password)
  })
  it('validates before allocating handles and rejects an already aborted owner', async () => {
    await expect(probe({ ...upstream, port: 0 })).rejects.toMatchObject({ category: 'validation' })
    await expect(probe({ ...upstream, password: 'я'.repeat(128) })).rejects.toMatchObject({ category: 'validation' })
    const controller = new AbortController(); controller.abort()
    await expect(probe(upstream, controller.signal)).rejects.toMatchObject({ category: 'cancelled' })
    expect(fixture.sockets).toHaveLength(0); expect(vi.getTimerCount()).toBe(0)
  })
})
