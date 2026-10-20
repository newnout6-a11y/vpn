// AT-00-003/007: retain late SOCKS, media/throughput sockets and isolated child cleanup.
import { EventEmitter } from 'node:events'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
const state = vi.hoisted(() => ({ dial: vi.fn(), verify: vi.fn(), persist: vi.fn(), ready: vi.fn(), tls: [] as any[], raw: [] as any[], children: [] as any[], rm: vi.fn(), tlsError: false,
  tlsFactory: undefined as undefined | (() => any), nativeChild: false, managed: false, status: { running: false, mode: 'directVpn', vpnProfileName: 'other' } }))
vi.mock('electron', () => ({ app: { getPath: () => '/tmp/test-userdata' }, ipcMain: { handle: vi.fn() } }))
vi.mock('./appLogger', () => ({ logEvent: vi.fn() }))
vi.mock('./operations', async original => {
  const actual = await original<typeof import('./operations')>()
  return { ...actual, operations: {
    run: (kind: any, effect: any, options: any) => state.managed ? actual.operations.run(kind, effect, options) : effect({ signal: options.signal, expire: () => false, retain: (task: Promise<unknown>) => task }),
    close: () => actual.operations.close(), resumeAdmission: () => actual.operations.resumeAdmission(),
    list: () => actual.operations.list()
  } }
})
vi.mock('./settings', () => ({ settingsStore: { get: () => ({ proxyEngine: 'sing-box' }) } }))
vi.mock('./serverPicker', () => ({ serverPicker: { getProfiles: () => [], getActiveProfile: () => ({ id: state.status.vpnProfileName, name: state.status.vpnProfileName }) } }))
vi.mock('./tunController', () => ({ tunController: { getStatus: () => state.status }, getBundledResource: () => '/tmp/sing-box.exe', getDirectProxyPort: () => 10808,
  getTunnelProbePort: () => 10809, pickFreeLocalPort: async () => 50123, isVpnOutboundUdpCapable: () => false, shouldBlockQuicUdp443: () => true }))
vi.mock('./physicalAdapterLockdown', () => ({ getPhysicalAdapterDnsSources: async () => [] }))
vi.mock('./managedChildProcess', () => ({ cleanupManagedChildPidDirs: async () => {}, writeManagedChildPidFile: state.persist, removeManagedChildPidFile: async () => {} }))
vi.mock('fs/promises', async original => ({ ...await original<typeof import('fs/promises')>(), mkdtemp: async () => '/tmp/live-drain-fixture', readFile: async () => '', writeFile: async () => {}, rm: state.rm }))
vi.mock('socks', () => ({ SocksClient: { createConnection: state.dial } }))
vi.mock('net', async original => ({ ...await original<typeof import('net')>(), Socket: class extends EventEmitter {
  connect() { queueMicrotask(() => this.emit('connect')); return this }
  destroy() { queueMicrotask(() => this.emit('close')); return this }
} }))
vi.mock('./keyHealthChecker', async original => ({ ...await original<typeof import('./keyHealthChecker')>(), buildKeyProbeConfig: () => ({}), waitForLocalSocks: state.ready, verifyHttpsThroughSocket: state.verify }))
vi.mock('tls', async original => ({ ...await original<typeof import('tls')>(), connect: (options: unknown) => {
  if (state.tlsError) throw new Error('fixture TLS initialization failed')
  if (state.tlsFactory) { const socket = state.tlsFactory(); state.tls.push(socket); return socket }
  const socket = Object.assign(new EventEmitter(), { options, destroy: vi.fn(), write: vi.fn() }); state.tls.push(socket); return socket
} }))
vi.mock('child_process', async original => { const actual = await original<typeof import('child_process')>(); return { ...actual, spawn: () => {
  if (state.nativeChild) { const child = actual.spawn(process.execPath, ['-e', 'setInterval(() => {}, 1000)'], { windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] }); state.children.push(child); return child }
  const child = Object.assign(new EventEmitter(), { pid: 12001, stdout: Object.assign(new EventEmitter(), { destroy: vi.fn() }), stderr: Object.assign(new EventEmitter(), { destroy: vi.fn() }), kill: vi.fn() }); state.children.push(child); return child
} } })
import { probeMediaStream, probeTunnelHandshakeAndEgress, withHandshakeWorkerLock } from './liveServerProbe'
import { operations } from './operations'
import { logEvent } from './appLogger'
import type { ServerProfile } from '../shared/ipc-types'
const profile = { id: 'target', name: 'target', protocol: 'vless', server: 'probe.example', port: 443, outbound: { type: 'vless', server: 'probe.example', server_port: 443 } } as unknown as ServerProfile
const flush = async () => { for (let i = 0; i < 80; i++) await Promise.resolve() }
const tasks = new Set<Promise<unknown>>(), controllers = new Set<AbortController>(), releases = new Set<() => void>()
function controller() { const value = new AbortController(); controllers.add(value); return value }
function raw() { const socket = Object.assign(new EventEmitter(), { destroy: vi.fn() }); state.raw.push(socket); return socket }
function observe<T>(promise: Promise<T>) { const result = { settled: false, value: undefined as T | undefined }; const task = promise.then(value => { result.settled = true; result.value = value }, () => { result.settled = true }); tasks.add(task); return { result, task } }
beforeEach(() => {
  vi.mocked(logEvent).mockClear()
  vi.useFakeTimers(); state.tls = []; state.raw = []; state.children = []; state.status.running = false; state.tlsError = false
  state.tlsFactory = undefined; state.nativeChild = false; state.persist.mockReset().mockResolvedValue(undefined)
  state.managed = false
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
  await Promise.allSettled(tasks); tasks.clear(); await operations.close(); operations.resumeAdmission(); vi.useRealTimers()
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
  it('escalates cancellation while readiness remains pending and retains both boundaries (AT-00-003/007)', async () => {
    let release!: () => void
    state.ready.mockImplementationOnce(() => new Promise<void>(resolve => { release = resolve })); releases.add(() => release())
    const owner = controller(), { result, task } = observe(probeTunnelHandshakeAndEgress(profile, undefined, owner.signal))
    await flush(); const child = state.children[0]
    const next = vi.fn(), queued = withHandshakeWorkerLock(async () => next()); tasks.add(queued)
    owner.abort(); await flush()
    expect(child.kill).toHaveBeenCalledWith('SIGTERM')
    await vi.advanceTimersByTimeAsync(1499); expect(child.kill).toHaveBeenCalledOnce()
    await vi.advanceTimersByTimeAsync(1); expect(child.kill).toHaveBeenLastCalledWith('SIGKILL')
    expect(result.settled).toBe(false); expect(next).not.toHaveBeenCalled(); expect(state.rm).not.toHaveBeenCalled()
    child.emit('close', 0); await flush()
    await vi.advanceTimersByTimeAsync(3500)
    expect(child.kill).toHaveBeenCalledTimes(2)
    expect(vi.mocked(logEvent).mock.calls.some(call => call[0] === 'warn')).toBe(false)
    expect(result.settled).toBe(false); expect(next).not.toHaveBeenCalled()
    release(); releases.clear(); await task; await queued
    expect(next).toHaveBeenCalledOnce(); expect(state.dial).not.toHaveBeenCalled(); expect(vi.getTimerCount()).toBe(0)
  })
  it('escalates a polite stop using the owned child and releases only after physical close', async () => {
    state.dial.mockRejectedValue(new Error('fixture unavailable'))
    const { result, task } = observe(probeTunnelHandshakeAndEgress(profile))
    await flush(); const child = state.children[0]
    expect(child.kill).toHaveBeenCalledWith('SIGTERM')
    await vi.advanceTimersByTimeAsync(1499); expect(child.kill).toHaveBeenCalledOnce()
    await vi.advanceTimersByTimeAsync(1); expect(child.kill).toHaveBeenLastCalledWith('SIGKILL')
    expect(result.settled).toBe(false); expect(state.rm).not.toHaveBeenCalled()
    child.emit('close', 0); await task; expect(vi.getTimerCount()).toBe(0)
  })
  it.each(['ready', 'persist'] as const)('allows trailing diagnostics after exit during %s before closing inherited pipes', async boundary => {
    let release!: () => void
    state[boundary].mockImplementationOnce(() => new Promise<void>(resolve => { release = resolve })); releases.add(() => release())
    state.dial.mockRejectedValue(new Error('fixture unavailable'))
    const { result, task } = observe(probeTunnelHandshakeAndEgress(profile))
    await flush(); const child = state.children[0]; child.emit('exit', 0)
    expect(child.stdout.destroy).not.toHaveBeenCalled(); expect(child.stderr.destroy).not.toHaveBeenCalled()
    child.stderr.emit('data', Buffer.from('authentication failed: final diagnostic'))
    release(); releases.clear(); await flush()
    await vi.advanceTimersByTimeAsync(1499); expect(child.stderr.destroy).not.toHaveBeenCalled()
    await vi.advanceTimersByTimeAsync(1)
    expect(child.stdout.destroy).toHaveBeenCalledOnce(); expect(child.stderr.destroy).toHaveBeenCalledOnce()
    await flush(); expect(result.settled).toBe(false); expect(state.rm).not.toHaveBeenCalled()
    child.emit('close', 0); await task; expect(state.rm).toHaveBeenCalledOnce()
    expect(result.value?.handshake.status).toBe('auth_failed')
  })
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

describe('managed caller cancellation and physical ownership', () => {
  it.each(['cancel', 'timeout'] as const)('records queued %s consistently with caller diagnostics (AT-00-003/005)', async boundary => {
    state.managed = true
    let release!: () => void
    const gate = new Promise<void>(resolve => { release = resolve }); releases.add(() => release())
    const worker = withHandshakeWorkerLock(() => gate); tasks.add(worker); await flush()
    const before = new Set(operations.list().map(operation => operation.operationId))
    const owner = controller(), { result, task } = observe(probeTunnelHandshakeAndEgress(profile, undefined, owner.signal))
    await flush()
    if (boundary === 'cancel') owner.abort(); else await vi.advanceTimersByTimeAsync(15000)
    await task; expect(result.value?.handshake.status).toBe(boundary === 'cancel' ? 'skipped' : 'timeout')
    expect(result.value?.mediaStream.status).toBe(boundary === 'cancel' ? 'skipped' : 'error')
    const records = operations.list().filter(operation => !before.has(operation.operationId))
    expect(records).toHaveLength(1)
    expect(records[0]).toMatchObject({ status: boundary === 'cancel' ? 'cancelled' : 'error', category: boundary === 'cancel' ? 'cancelled' : 'timeout' })
    expect(state.children).toHaveLength(0)
    release(); releases.clear(); await worker
  })
  it('rejects queued and new work explicitly when cleanup is blocked, then recovers after physical drain (AT-00-003/007)', async () => {
    state.managed = true; state.dial.mockRejectedValue(new Error('fixture unavailable'))
    const { result, task } = observe(probeTunnelHandshakeAndEgress(profile))
    await flush()
    const next = vi.fn(), queued = withHandshakeWorkerLock(async () => next()).catch(error => error); tasks.add(queued)
    let queueResult: any
    const queueTask = queued.then(value => { queueResult = value }); tasks.add(queueTask)
    await vi.advanceTimersByTimeAsync(5000); await task
    expect(result.value?.handshake.status).toBe('timeout')
    expect(queueResult).toMatchObject({ category: 'conflict' })
    await expect(withHandshakeWorkerLock(async () => next())).rejects.toMatchObject({ category: 'conflict' })
    expect(next).not.toHaveBeenCalled(); expect(state.rm).not.toHaveBeenCalled()
    const drain = observe(operations.close()); await flush(); expect(drain.result.settled).toBe(false)
    state.children[0].emit('close', 0); await drain.task; await queueTask
    await withHandshakeWorkerLock(async () => next()); expect(next).toHaveBeenCalledOnce()
    expect(state.rm).toHaveBeenCalledOnce()
  })
  it.each(['cancel', 'deadline'])('returns promptly on %s while a stuck child still owns its worker', async boundary => {
    state.managed = true; state.dial.mockRejectedValue(new Error('fixture unavailable'))
    const owner = controller(), { result, task } = observe(probeTunnelHandshakeAndEgress(profile, undefined, owner.signal))
    await flush(); expect(state.children[0].kill).toHaveBeenCalled(); expect(result.settled).toBe(false)
    if (boundary === 'cancel') owner.abort(); else await vi.advanceTimersByTimeAsync(5_000)
    await task; expect(result.value?.handshake.status).toBe(boundary === 'cancel' ? 'skipped' : 'timeout')
    expect(state.rm).not.toHaveBeenCalled()
    const next = vi.fn(), queued = withHandshakeWorkerLock(async () => next()).catch(error => error); tasks.add(queued)
    const drain = observe(operations.close()); await flush()
    expect(next).not.toHaveBeenCalled(); expect(drain.result.settled).toBe(false)
    if (boundary === 'deadline') expect(await queued).toMatchObject({ category: 'conflict' })
    state.children[0].emit('close', 0); await queued; await drain.task
    if (boundary === 'deadline') await withHandshakeWorkerLock(async () => next())
    expect(next).toHaveBeenCalledOnce(); expect(state.rm).toHaveBeenCalledOnce()
  })
  it('returns media cancellation promptly and keeps shutdown waiting for late SOCKS settlement and close', async () => {
    state.managed = true
    let release!: (value: { socket: ReturnType<typeof raw> }) => void
    state.dial.mockImplementationOnce(() => new Promise(resolve => { release = resolve })); releases.add(() => release({ socket: raw() }))
    const owner = controller(), observed = observe(probeMediaStream(null, 10809, owner.signal))
    await flush(); owner.abort(); await observed.task; expect(observed.result.value?.status).toBe('skipped')
    const drain = observe(operations.close()); await flush(); expect(drain.result.settled).toBe(false)
    const late = raw(); release({ socket: late }); releases.clear(); await flush()
    expect(late.destroy).toHaveBeenCalledOnce(); expect(state.tls).toHaveLength(0); expect(drain.result.settled).toBe(false)
    late.emit('close'); await drain.task
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
    let closedAtRemoval = false
    state.rm.mockImplementation(async () => { closedAtRemoval = closed })
    const { task, result } = observe(probeTunnelHandshakeAndEgress(profile))
    try { await task; expect(closed).toBe(true); expect(closedAtRemoval).toBe(true); expect(state.children[0].exitCode !== null || state.children[0].signalCode !== null).toBe(true); expect(result.value?.handshake.status).not.toBe('ok'); expect(state.rm).toHaveBeenCalledOnce() }
    finally { for (const child of state.children) child.kill('SIGKILL'); await task }
  }, 15_000)
})
