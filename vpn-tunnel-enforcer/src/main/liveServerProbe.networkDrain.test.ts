// AT-00-003/007: raw DNS, TCP/TLS and traceroute stay owned until actual settlement.
import { EventEmitter } from 'node:events'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
const state = vi.hoisted(() => ({ a: vi.fn(), aaaa: vi.fn(), resolvers: [] as Array<{ cancel: ReturnType<typeof vi.fn> }>, sockets: [] as any[], children: [] as any[], connect: vi.fn(), spawn: vi.fn(), socketFactory: null as (() => any) | null, tlsFactory: null as ((options: any) => any) | null, resolverFactory: null as ((options: any) => any) | null }))
vi.mock('electron', () => ({ app: { getPath: () => '/tmp/test-userdata' }, ipcMain: { handle: vi.fn() } }))
vi.mock('./appLogger', () => ({ logEvent: vi.fn() }))
vi.mock('./settings', () => ({ settingsStore: { get: () => ({ disableGeoLookup: true }) } }))
vi.mock('./serverPicker', () => ({ serverPicker: { getProfiles: () => [], getActiveProfile: () => null } }))
vi.mock('./tunController', () => ({ tunController: { getStatus: () => ({ running: false }) } }))
vi.mock('dns', async original => ({ ...await original<typeof import('dns')>(), promises: { Resolver: class {
  cancel = vi.fn()
  resolve4 = state.a
  resolve6 = state.aaaa
  resolveCname = async () => []
  reverse = async () => []
  constructor(options: unknown) { if (state.resolverFactory) return state.resolverFactory(options); state.resolvers.push(this) }
} } }))
vi.mock('net', async original => ({ ...await original<typeof import('net')>(), Socket: class extends EventEmitter {
  destroy = vi.fn(() => this)
  setTimeout = vi.fn(() => this)
  connect = (...args: unknown[]) => { state.connect(...args); return this }
  constructor() { super(); if (state.socketFactory) return state.socketFactory(); state.sockets.push(this) }
} }))
vi.mock('tls', async original => ({ ...await original<typeof import('tls')>(), connect: (options: unknown, ready: () => void) => {
  if (state.tlsFactory) { const socket = state.tlsFactory(options); socket.once('secureConnect', ready); return socket }
  const socket = Object.assign(new EventEmitter(), { destroy: vi.fn(), ready: () => socket.emit('secureConnect'),
    getPeerCertificate: () => ({ subject: { CN: 'probe.example' } }), getProtocol: () => 'TLSv1.3', getCipher: () => ({ name: 'fixture' }), authorized: true })
  socket.once('secureConnect', ready); state.sockets.push(socket); return socket
} }))
vi.mock('child_process', async original => ({ ...await original<typeof import('child_process')>(), spawn: state.spawn }))
import { probeDns, probePorts, probeReachabilityAndLatency, probeTls, probeRoute } from './liveServerProbe'
const flush = async () => { for (let i = 0; i < 50; i++) await Promise.resolve() }
const releases = new Set<() => void>(), tasks = new Set<Promise<unknown>>()
function held<T>() { let release!: (value: T) => void; const promise = new Promise<T>(resolve => { release = resolve }); releases.add(() => release([] as T)); return { promise, release } }
function observe<T>(promise: Promise<T>) { const result = { settled: false, value: undefined as T | undefined }; const task = promise.then(value => { result.settled = true; result.value = value }, () => { result.settled = true }); tasks.add(task); return { result, task } }
beforeEach(() => {
  vi.useFakeTimers(); state.resolvers = []; state.sockets = []; state.children = []; state.socketFactory = null; state.tlsFactory = null; state.resolverFactory = null
  state.a.mockReset().mockResolvedValue([]); state.aaaa.mockReset().mockResolvedValue([]); state.connect.mockReset()
  state.spawn.mockReset().mockImplementation(() => { const child = Object.assign(new EventEmitter(), { stdout: new EventEmitter(), kill: vi.fn() }); state.children.push(child); return child })
})
afterEach(async () => {
  for (const release of releases) release(); releases.clear()
  for (let i = 0; i < 12; i++) {
    for (const socket of state.sockets) { socket.emit('timeout'); socket.emit('close') }
    await flush(); if (vi.isFakeTimers()) await vi.runOnlyPendingTimersAsync()
  }
  for (const child of state.children) child.emit('close', 0)
  await flush(); if (vi.isFakeTimers()) await vi.runAllTimersAsync(); await Promise.allSettled(tasks); tasks.clear(); vi.useRealTimers()
})
describe('DNS physical settlement', () => {
  it.each(['cancel', 'timeout'])('drains both families after %s and discards late addresses', async boundary => {
    const a = held<Array<{ address: string; ttl: number }>>(), aaaa = held<Array<{ address: string; ttl: number }>>()
    state.a.mockReturnValueOnce(a.promise); state.aaaa.mockReturnValueOnce(aaaa.promise)
    const controller = new AbortController(), { result, task } = observe(probeDns('probe.example', 'basic', controller.signal))
    if (boundary === 'cancel') controller.abort(); else await vi.advanceTimersByTimeAsync(2501)
    await flush(); expect(state.resolvers.slice(0, 2).every(resolver => resolver.cancel.mock.calls.length === 1)).toBe(true)
    expect(result.settled).toBe(false)
    a.release([{ address: '192.0.2.1', ttl: 60 }]); await flush(); expect(result.settled).toBe(false)
    aaaa.release([{ address: '2001:db8::1', ttl: 60 }]); await task
    expect(result.value?.dns.a).toEqual([]); expect(result.value?.dns.aaaa).toEqual([])
    expect(result.value?.dns.status).not.toBe('ok')
  })
  it('does not start any DNS request after cancellation, including reverse DNS', async () => {
    const controller = new AbortController(); controller.abort()
    await probeDns('probe.example', 'basic', controller.signal); await probeDns('192.0.2.1', 'basic', controller.signal)
    expect(state.resolvers).toHaveLength(0)
  })
})
describe('TCP physical close', () => {
  it.each(['cancel', 'timeout', 'error', 'connect', 'throw', 'close'])('holds a port probe after %s until close', async boundary => {
    if (boundary === 'throw') state.connect.mockImplementation(() => { throw new Error('sync connect') })
    const controller = new AbortController(), { result, task } = observe(probePorts('192.0.2.1', 443, 'basic', controller.signal))
    const socket = state.sockets[0]
    if (boundary === 'cancel') controller.abort()
    else if (boundary !== 'throw') socket.emit(boundary, boundary === 'error' ? new Error('refused') : undefined)
    await flush(); expect(result.settled).toBe(boundary === 'close')
    if (boundary !== 'close') { expect(socket.destroy).toHaveBeenCalledOnce(); socket.emit('close') }
    await task; expect(socket.eventNames()).toEqual([])
    expect(result.value?.[0].open).toBe(boundary === 'connect')
  })
  it('measures connect RTT without including delayed close', async () => {
    const { result, task } = observe(probeReachabilityAndLatency('192.0.2.1', 443))
    for (let i = 0; i < 5; i++) {
      await flush(); const socket = state.sockets[i]
      await vi.advanceTimersByTimeAsync(10); socket.emit('connect')
      await vi.advanceTimersByTimeAsync(250); expect(result.settled).toBe(false); socket.emit('close')
      await vi.advanceTimersByTimeAsync(60)
    }
    await task; expect(result.value?.latency?.samples).toEqual([10, 10, 10, 10, 10])
  })
})
describe('TLS physical close', () => {
  it.each(['cancel', 'timeout', 'error', 'ready', 'close'])('drains %s and ignores a later successful handshake', async boundary => {
    const controller = new AbortController(), { result, task } = observe(probeTls('192.0.2.1', 443, undefined, controller.signal))
    const socket = state.sockets[0]
    if (boundary === 'cancel') controller.abort()
    else if (boundary === 'ready') socket.ready()
    else socket.emit(boundary, boundary === 'error' ? new Error('TLS refused') : undefined)
    await flush(); expect(result.settled).toBe(boundary === 'close')
    socket.ready(); socket.emit('close'); await task
    expect(result.value?.status).toBe(boundary === 'ready' ? 'ok' : boundary === 'cancel' ? 'skipped' : 'error')
    expect(socket.eventNames()).toEqual([])
  })
  it('waits for close after the overall TLS deadline and keeps the original duration', async () => {
    const { result, task } = observe(probeTls('192.0.2.1', 443))
    await vi.advanceTimersByTimeAsync(3501); expect(result.settled).toBe(false)
    await vi.advanceTimersByTimeAsync(250); state.sockets[0].ready(); state.sockets[0].emit('close'); await task
    expect(result.value).toMatchObject({ status: 'error', durationMs: 3500, error: 'TLS handshake timeout' })
  })
  it('does not create a socket after cancellation and handles synchronous initialization failure', async () => {
    const controller = new AbortController(); controller.abort()
    expect((await probeTls('192.0.2.1', 443, undefined, controller.signal)).status).toBe('skipped')
    expect(state.sockets).toHaveLength(0)
    state.tlsFactory = () => { throw new Error('sync TLS init') }
    expect((await probeTls('192.0.2.1', 443)).error).toBe('sync TLS init')
  })
})
describe('traceroute physical close', () => {
  it.skipIf(process.platform !== 'win32').each(['cancel', 'timeout', 'error'])('retains child after %s and preserves partial hops', async boundary => {
    const controller = new AbortController(), { result, task } = observe(probeRoute('192.0.2.1', controller.signal))
    const child = state.children[0]; child.stdout.emit('data', Buffer.from('  1  1 ms  1 ms  1 ms  192.0.2.2\r\n'))
    if (boundary === 'cancel') controller.abort()
    if (boundary === 'timeout') await vi.advanceTimersByTimeAsync(3501)
    if (boundary === 'error') child.emit('error', new Error('spawn failed'))
    await flush(); expect(result.settled).toBe(false); expect(child.kill).toHaveBeenCalledOnce()
    child.emit('close', 0); await task
    expect(result.value?.status).not.toBe('ok'); expect(result.value?.commandFinished).toBe(false)
    expect(result.value?.hopDetails).toHaveLength(1); expect(child.eventNames()).toEqual([]); expect(child.stdout.eventNames()).toEqual([])
  })
  it.skipIf(process.platform !== 'win32')('preserves normal close parsing and handles synchronous spawn failure', async () => {
    const { result, task } = observe(probeRoute('192.0.2.1'))
    state.children[0].stdout.emit('data', Buffer.from('  1  1 ms  1 ms  1 ms  192.0.2.1\r\n'))
    state.children[0].emit('close', 0); await task
    expect(result.value).toMatchObject({ status: 'ok', commandFinished: true, reachedTarget: true, partial: false })
    expect(state.children[0].kill).not.toHaveBeenCalled()
    state.spawn.mockImplementation(() => { throw new Error('sync spawn') })
    expect((await probeRoute('192.0.2.1')).error).toBe('sync spawn')
  })
})

describe('native loopback resource boundaries', () => {
  it.each(['connect', 'cancel'])('TCP %s returns after the real socket closes', async boundary => {
    vi.useRealTimers()
    const actual = await vi.importActual<typeof import('net')>('net')
    const peers = new Set<import('net').Socket>(), server = actual.createServer(socket => { peers.add(socket); socket.once('close', () => peers.delete(socket)) })
    await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve))
    let native: import('net').Socket | undefined, closed = false
    state.socketFactory = () => { native = new actual.Socket(); native.once('close', () => { closed = true }); return native }
    try {
      const controller = new AbortController(), { task, result } = observe(probePorts('127.0.0.1', (server.address() as import('net').AddressInfo).port, 'basic', controller.signal))
      // Basic mode also probes 443 for a non-443 profile; cancel that second sample.
      if (boundary === 'cancel') controller.abort()
      else native!.once('connect', () => controller.abort())
      await task; expect(closed).toBe(true); expect(result.value?.[0]).toBeDefined()
    } finally { native?.destroy(); for (const peer of peers) peer.destroy(); await new Promise<void>(resolve => server.close(() => resolve())) }
  }, 15_000)
  it('TLS cancellation drains a real TLS socket without receiving a handshake', async () => {
    vi.useRealTimers()
    const actualNet = await vi.importActual<typeof import('net')>('net'), actualTls = await vi.importActual<typeof import('tls')>('tls')
    const peers = new Set<import('net').Socket>(), server = actualNet.createServer(socket => { peers.add(socket); socket.once('close', () => peers.delete(socket)) })
    await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve))
    let native: import('tls').TLSSocket | undefined, closed = false
    state.tlsFactory = options => { native = actualTls.connect(options); native.once('close', () => { closed = true }); return native }
    try {
      const controller = new AbortController(), { result, task } = observe(probeTls('127.0.0.1', (server.address() as import('net').AddressInfo).port, undefined, controller.signal))
      controller.abort(); await task
      expect(closed).toBe(true); expect(result.value?.status).toBe('skipped')
    } finally { native?.destroy(); for (const peer of peers) peer.destroy(); await new Promise<void>(resolve => server.close(() => resolve())) }
  }, 15_000)
  it('cancels real resolver queries against a local UDP fixture', async () => {
    vi.useRealTimers()
    const actual = await vi.importActual<typeof import('dns')>('dns'), dgram = await import('node:dgram')
    const server = dgram.createSocket('udp4')
    await new Promise<void>(resolve => server.bind(0, '127.0.0.1', resolve))
    const native: InstanceType<typeof actual.promises.Resolver>[] = []
    let received = 0, receive!: () => void
    const receiving = new Promise<void>(resolve => { receive = resolve })
    server.on('message', () => { if (++received === 2) receive() })
    state.resolverFactory = options => { const resolver = new actual.promises.Resolver(options); resolver.setServers([`127.0.0.1:${server.address().port}`]); native.push(resolver); return resolver }
    let timer: ReturnType<typeof setTimeout> | undefined
    const controller = new AbortController()
    const { result, task } = observe(probeDns('probe.example', 'basic', controller.signal))
    try {
      await Promise.race([receiving, new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('local DNS fixture did not receive both families')), 2000) })])
      controller.abort(); await task
      expect(received).toBe(2); expect(result.value?.dns.a).toEqual([]); expect(result.value?.dns.aaaa).toEqual([])
    } finally { clearTimeout(timer); controller.abort(); for (const resolver of native) resolver.cancel(); await task; await new Promise<void>(resolve => server.close(resolve)) }
  }, 15_000)
})
