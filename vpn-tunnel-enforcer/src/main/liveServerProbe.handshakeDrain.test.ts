// AT-00-003/007: retain late SOCKS, media/throughput sockets and isolated child cleanup.
import { EventEmitter } from 'node:events'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
const state = vi.hoisted(() => ({ dial: vi.fn(), verify: vi.fn(), persist: vi.fn(), ready: vi.fn(), tls: [] as any[], raw: [] as any[], children: [] as any[], rm: vi.fn(), tlsError: false,
  tlsFactory: undefined as undefined | (() => any), nativeChild: false, status: { running: false, mode: 'directVpn', vpnProfileName: 'other' } }))
vi.mock('electron', () => ({ app: { getPath: () => '/tmp/test-userdata' }, ipcMain: { handle: vi.fn() } }))
vi.mock('./appLogger', () => ({ logEvent: vi.fn() }))
vi.mock('./settings', () => ({ settingsStore: { get: () => ({ proxyEngine: 'sing-box' }) } }))
vi.mock('./serverPicker', () => ({ serverPicker: { getProfiles: () => [], getActiveProfile: () => ({ id: state.status.vpnProfileName, name: state.status.vpnProfileName }) } }))
vi.mock('./tunController', () => ({ tunController: { getStatus: () => state.status }, getBundledResource: () => '/tmp/sing-box.exe', getDirectProxyPort: () => 10808,
  getTunnelProbePort: () => 10809, pickFreeLocalPort: async () => 50123, isVpnOutboundUdpCapable: () => false, shouldBlockQuicUdp443: () => true }))
vi.mock('./physicalAdapterLockdown', () => ({ getPhysicalAdapterDnsSources: async () => [] }))
vi.mock('./managedChildProcess', () => ({ cleanupManagedChildPidDirs: async () => {}, writeManagedChildPidFile: state.persist, removeManagedChildPidFile: async () => {} }))
vi.mock('fs/promises', async original => ({ ...await original<typeof import('fs/promises')>(), mkdtemp: async () => '/tmp/live-drain-fixture', readFile: async () => '', writeFile: async () => {}, rm: state.rm }))
vi.mock('socks', () => ({ SocksClient: { createConnection: state.dial } }))
vi.mock('./keyHealthChecker', async original => ({ ...await original<typeof import('./keyHealthChecker')>(), buildKeyProbeConfig: () => ({}), waitForLocalSocks: state.ready, verifyHttpsThroughSocket: state.verify }))
vi.mock('tls', async original => ({ ...await original<typeof import('tls')>(), connect: (options: unknown) => {
  if (state.tlsError) throw new Error('fixture TLS initialization failed')
  if (state.tlsFactory) { const socket = state.tlsFactory(); state.tls.push(socket); return socket }
  const socket = Object.assign(new EventEmitter(), { options, destroy: vi.fn(), write: vi.fn() }); state.tls.push(socket); return socket
} }))
vi.mock('child_process', async original => { const actual = await original<typeof import('child_process')>(); return { ...actual, spawn: () => {
  if (state.nativeChild) { const child = actual.spawn(process.execPath, ['-e', 'setInterval(() => {}, 1000)'], { windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] }); state.children.push(child); return child }
  const child = Object.assign(new EventEmitter(), { pid: 12001, stdout: new EventEmitter(), stderr: new EventEmitter(), kill: vi.fn() }); state.children.push(child); return child
} } })
import { probeMediaStream, probeTunnelHandshakeAndEgress, withHandshakeWorkerLock } from './liveServerProbe'
import type { ServerProfile } from '../shared/ipc-types'
const profile = { id: 'target', name: 'target', protocol: 'vless', server: 'probe.example', port: 443, outbound: { type: 'vless', server: 'probe.example', server_port: 443 } } as unknown as ServerProfile
const flush = async () => { for (let i = 0; i < 80; i++) await Promise.resolve() }
const tasks = new Set<Promise<unknown>>(), controllers = new Set<AbortController>(), releases = new Set<() => void>()
function controller() { const value = new AbortController(); controllers.add(value); return value }
function raw() { const socket = Object.assign(new EventEmitter(), { destroy: vi.fn() }); state.raw.push(socket); return socket }
function observe<T>(promise: Promise<T>) { const result = { settled: false, value: undefined as T | undefined }; const task = promise.then(value => { result.settled = true; result.value = value }, () => { result.settled = true }); tasks.add(task); return { result, task } }
beforeEach(() => {
  vi.useFakeTimers(); state.tls = []; state.raw = []; state.children = []; state.status.running = false; state.tlsError = false
  state.tlsFactory = undefined; state.nativeChild = false; state.persist.mockReset().mockResolvedValue(undefined)
  state.ready.mockReset().mockResolvedValue(undefined)
  state.rm.mockReset().mockResolvedValue(undefined); state.dial.mockReset().mockImplementation(async () => ({ socket: raw() }))
  state.verify.mockReset().mockResolvedValue({ egressIp: '203.0.113.1', country: 'NL' })
})
afterEach(async () => {
  for (const value of controllers) value.abort(); controllers.clear()
  for (const release of releases) release(); releases.clear()
  for (let i = 0; i < 20; i++) {
    for (const socket of [...state.tls, ...state.raw]) { if (vi.isMockFunction(socket.destroy)) socket.emit('close'); else socket.destroy() }
    if (!state.nativeChild) for (const child of state.children) child.emit('close', 0)
    await flush(); if (vi.isFakeTimers()) await vi.runOnlyPendingTimersAsync()
  }
  await Promise.allSettled(tasks); tasks.clear(); vi.useRealTimers()
})
describe('media socket drain', () => {
  it.each([false, true])('cancels media promptly and holds TLS/raw socket until close (SOCKS=%s)', async socks => {
    const owner = controller(), { result, task } = observe(probeMediaStream(null, socks ? 10809 : undefined, owner.signal))
    await flush(); const tls = state.tls[0]; owner.abort(); await flush()
    expect(tls.destroy).toHaveBeenCalledOnce(); expect(result.settled).toBe(false)
    tls.emit('secureConnect'); expect(tls.write).not.toHaveBeenCalled()
    tls.emit('close'); await flush()
    if (socks) { expect(result.settled).toBe(false); state.raw[0].emit('close') }
    await task; expect(tls.eventNames()).toEqual([])
  })
  it('retains a cancelled SOCKS dial and the late socket without starting TLS', async () => {
    let release!: (value: { socket: ReturnType<typeof raw> }) => void
    state.dial.mockImplementationOnce(() => new Promise(resolve => { release = resolve })); releases.add(() => release({ socket: raw() }))
    const owner = controller(), { result, task } = observe(probeMediaStream(null, 10809, owner.signal))
    await flush(); owner.abort(); await flush(); expect(result.settled).toBe(false)
    const socket = raw(); release({ socket }); releases.clear(); await flush()
    expect(socket.destroy).toHaveBeenCalledOnce(); expect(state.tls).toHaveLength(0); expect(result.settled).toBe(false)
    socket.emit('close'); await task
  })
  it.each(['success', 'timeout', 'close', 'headers', 'end'])('drains media after %s and never writes late', async outcome => {
    const owner = controller(), { result, task } = observe(probeMediaStream(null, undefined, owner.signal))
    await flush(); const socket = state.tls[0]
    if (outcome === 'success') socket.emit('data', Buffer.from('HTTP/1.1 200 OK\r\n'))
    if (outcome === 'timeout') await vi.advanceTimersByTimeAsync(3500)
    if (outcome === 'headers') socket.emit('data', Buffer.alloc(65536, 120))
    if (outcome === 'end') socket.emit('end')
    if (outcome === 'close') socket.emit('close')
    else expect(result.settled).toBe(false)
    expect(socket.destroy).toHaveBeenCalledOnce()
    owner.abort(); socket.emit('secureConnect'); if (outcome !== 'close') socket.emit('error', new Error('late reset'))
    socket.emit('close'); await task
    expect(socket.write).not.toHaveBeenCalled()
    expect(socket.eventNames()).toEqual([])
  })
  it('drains the raw media socket after synchronous TLS initialization failure', async () => {
    state.tlsError = true
    const owner = controller(), { result, task } = observe(probeMediaStream(null, 10809, owner.signal))
    await flush(); expect(state.raw[0].destroy).toHaveBeenCalled(); expect(result.settled).toBe(false)
    owner.abort(); state.raw[0].emit('close'); await task
    expect(vi.getTimerCount()).toBe(0)
  })
})
describe('isolated handshake process drain', () => {
  it('keeps the queue and work directory until the child and reflector sockets close', async () => {
    state.dial.mockRejectedValue(new Error('fixture destination unavailable'))
    const owner = controller(), { result, task } = observe(probeTunnelHandshakeAndEgress(profile, undefined, owner.signal))
    await flush(); expect(state.children).toHaveLength(1)
    expect(state.children[0].kill).toHaveBeenCalled(); expect(state.rm).not.toHaveBeenCalled(); expect(result.settled).toBe(false)
    const next = vi.fn(), queued = withHandshakeWorkerLock(async () => next()); tasks.add(queued)
    await flush(); expect(next).not.toHaveBeenCalled()
    state.children[0].emit('close', 0); await task
    await queued; expect(next).toHaveBeenCalledOnce()
    expect(state.rm).toHaveBeenCalledOnce()
  })
  it('passes cancellation and retention to real SOCKS/HTTPS boundaries and drains the returned sockets', async () => {
    state.status.running = true; state.status.vpnProfileName = 'target'
    state.dial.mockImplementation(async options => {
      if (options.destination.host.includes('ttvnw') || options.destination.host.includes('twitch')) throw new Error('fixture media skipped')
      return { socket: raw() }
    })
    const owner = controller(), { result, task } = observe(probeTunnelHandshakeAndEgress(profile, undefined, owner.signal))
    await flush(); expect(state.verify).toHaveBeenCalled()
    expect(state.verify.mock.calls.every(call => call[3] === owner.signal && typeof call[4] === 'function')).toBe(true)
    expect(result.settled).toBe(false)
    for (const socket of state.raw) socket.emit('close')
    await task
  })
  it('handles a child error during PID persistence and still waits for physical close', async () => {
    let release!: () => void
    state.persist.mockImplementationOnce(() => new Promise<void>(resolve => { release = resolve })); releases.add(() => release())
    const { result, task } = observe(probeTunnelHandshakeAndEgress(profile))
    await flush(); state.children[0].emit('error', new Error('fixture spawn error')); await flush()
    expect(result.settled).toBe(false); release(); releases.clear(); await flush()
    expect(state.children[0].kill).toHaveBeenCalled(); expect(state.rm).not.toHaveBeenCalled()
    state.children[0].emit('close', -1); await task
    expect(result.value?.handshake.status).not.toBe('ok'); expect(state.rm).toHaveBeenCalledOnce()
  })
  it('cancels and drains the readiness poll when a child error wins the race', async () => {
    let release!: () => void
    state.ready.mockImplementationOnce(() => new Promise<void>(resolve => { release = resolve })); releases.add(() => release())
    const { result, task } = observe(probeTunnelHandshakeAndEgress(profile))
    await flush(); state.children[0].emit('error', new Error('fixture early child error')); await flush()
    expect(state.ready.mock.calls[0][2].aborted).toBe(true)
    expect(state.ready.mock.calls[0][3]).toBeTypeOf('function')
    state.children[0].emit('close', -1); await flush(); expect(result.settled).toBe(false)
    release(); releases.clear(); await task
    expect(result.value?.handshake.status).not.toBe('ok'); expect(state.dial).not.toHaveBeenCalled()
  })
})

async function startThroughput() {
  state.status.running = true; state.status.vpnProfileName = 'target'
  state.dial.mockImplementation(async options => {
    if (/ttvnw|twitch/.test(options.destination.host)) throw new Error('fixture media skipped')
    return { socket: raw() }
  })
  const owner = controller(), observed = observe(probeTunnelHandshakeAndEgress(profile, undefined, owner.signal, true))
  await flush()
  return { owner, ...observed }
}

describe('throughput resource drain through the production handshake', () => {
  it('retains a late cancelled SOCKS dial without starting TLS or another sample', async () => {
    const original = state.dial.getMockImplementation()!
    let release!: (value: { socket: ReturnType<typeof raw> }) => void
    state.status.running = true; state.status.vpnProfileName = 'target'
    state.dial.mockImplementation(options => {
      if (/ttvnw|twitch/.test(options.destination.host)) return Promise.reject(new Error('fixture media skipped'))
      if (options.destination.host === 'speed.cloudflare.com') return new Promise(resolve => { release = resolve })
      return original(options)
    })
    releases.add(() => release({ socket: raw() }))
    const owner = controller(), { result, task } = observe(probeTunnelHandshakeAndEgress(profile, undefined, owner.signal, true))
    await flush(); owner.abort(); await flush(); expect(result.settled).toBe(false)
    const late = raw(); release({ socket: late }); releases.clear(); await flush()
    expect(late.destroy).toHaveBeenCalledOnce(); expect(state.tls).toHaveLength(0)
    expect(result.settled).toBe(false); for (const raw of state.raw) raw.emit('close')
    await task; expect(state.dial.mock.calls.filter(([options]) => options.destination.host === 'speed.cloudflare.com')).toHaveLength(1)
  })
  it('aborts pending TLS immediately but retains both sockets until close', async () => {
    const { owner, result, task } = await startThroughput(), socket = state.tls[0]
    owner.abort(); await flush()
    expect(socket.destroy).toHaveBeenCalledOnce(); expect(result.settled).toBe(false)
    socket.emit('secureConnect'); socket.emit('error', new Error('late reset'))
    expect(socket.write).not.toHaveBeenCalled()
    socket.emit('close'); await flush(); expect(result.settled).toBe(false)
    for (const raw of state.raw) raw.emit('close')
    await task; expect(state.tls).toHaveLength(1); expect(vi.getTimerCount()).toBe(0)
  })
  it('holds each successful sample until raw and TLS close before starting the next', async () => {
    const { result, task } = await startThroughput()
    for (let index = 0; index < 3; index++) {
      const socket = state.tls[index], raw = state.raw[3 + index]
      socket.emit('secureConnect'); expect(socket.write).toHaveBeenCalledOnce()
      await vi.advanceTimersByTimeAsync(20)
      socket.emit('data', Buffer.from('HTTP/1.1 200 OK\r\nContent-Length: 4194304\r\n\r'))
      socket.emit('data', Buffer.concat([Buffer.from('\n'), Buffer.alloc(4194304)]))
      await flush(); expect(state.tls).toHaveLength(index + 1)
      await vi.advanceTimersByTimeAsync(500)
      socket.emit('close'); await flush(); expect(state.tls).toHaveLength(index + 1)
      raw.emit('close'); await flush()
    }
    expect(result.settled).toBe(false) // parent still owns the reflector sockets
    for (const raw of state.raw.slice(0, 3)) raw.emit('close')
    await task
    expect(result.value?.throughput?.samples).toHaveLength(3)
    expect(result.value?.throughput?.samples.map(sample => sample.durationMs)).toEqual([20, 20, 20])
    expect(result.value?.throughput?.samples.map(sample => sample.bytes)).toEqual([4194304, 4194304, 4194304])
  })
  it.each(['timeout', 'close', 'headers', 'end', 'http'])('drains failed sample after %s before accepting cancellation', async outcome => {
    const { owner, result, task } = await startThroughput(), socket = state.tls[0]
    if (outcome === 'timeout') await vi.advanceTimersByTimeAsync(12000)
    if (outcome === 'headers') socket.emit('data', Buffer.alloc(65536, 120))
    if (outcome === 'end') socket.emit('end')
    if (outcome === 'http') socket.emit('data', Buffer.from('HTTP/1.1 503 Unavailable\r\n\r\n'))
    if (outcome === 'close') socket.emit('close')
    await flush(); expect(state.tls).toHaveLength(1); expect(result.settled).toBe(false)
    expect(socket.destroy).toHaveBeenCalledOnce()
    owner.abort(); socket.emit('secureConnect'); expect(socket.write).not.toHaveBeenCalled()
    socket.emit('close'); for (const raw of state.raw) raw.emit('close')
    await task; expect(state.tls).toHaveLength(1); expect(vi.getTimerCount()).toBe(0)
  })
  it('drains the raw sample socket and clears timers on synchronous TLS init failure', async () => {
    state.tlsError = true
    const { owner, result, task } = await startThroughput()
    expect(state.raw[3].destroy).toHaveBeenCalled(); expect(result.settled).toBe(false)
    owner.abort(); for (const raw of state.raw) raw.emit('close')
    await task; expect(vi.getTimerCount()).toBe(0)
  })
})

describe('native handshake resource boundaries', () => {
  it('media cancellation returns only after the real loopback TLS socket closes', async () => {
    vi.useRealTimers()
    const net = await vi.importActual<typeof import('net')>('net'), tls = await vi.importActual<typeof import('tls')>('tls')
    const peers = new Set<import('net').Socket>(), server = net.createServer(socket => { peers.add(socket); socket.once('close', () => peers.delete(socket)) })
    await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve))
    let closed = false
    state.tlsFactory = () => { const socket = tls.connect({ host: '127.0.0.1', port: (server.address() as import('net').AddressInfo).port, rejectUnauthorized: false }); socket.once('close', () => { closed = true }); return socket }
    const owner = controller(), { result, task } = observe(probeMediaStream(null, undefined, owner.signal))
    try {
      await flush(); expect(state.tls).toHaveLength(1); owner.abort(); await task
      expect(closed).toBe(true); expect(result.value?.testedEndpoints).toHaveLength(1)
    } finally { owner.abort(); for (const socket of state.tls) socket.destroy(); for (const peer of peers) peer.destroy(); await task; await new Promise<void>(resolve => server.close(() => resolve())) }
  }, 15_000)
  it('isolated handshake removes the work directory after the real child closes', async () => {
    vi.useRealTimers(); state.nativeChild = true; state.dial.mockRejectedValue(new Error('fixture unavailable'))
    let closed = false
    state.persist.mockImplementation(async () => { state.children[0].once('close', () => { closed = true }) })
    state.rm.mockImplementation(async () => { expect(closed).toBe(true) })
    const { task, result } = observe(probeTunnelHandshakeAndEgress(profile))
    try { await task; expect(closed).toBe(true); expect(state.children[0].exitCode !== null || state.children[0].signalCode !== null).toBe(true); expect(result.value?.handshake.status).not.toBe('ok'); expect(state.rm).toHaveBeenCalledOnce() }
    finally { for (const child of state.children) child.kill('SIGKILL'); await task }
  }, 15_000)
})
