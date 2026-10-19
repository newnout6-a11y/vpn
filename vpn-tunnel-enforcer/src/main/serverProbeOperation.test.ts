// AT-00-001/003/004/005: production probe and IPC, controlled DNS/HTTP/socket boundaries.
import { EventEmitter } from 'node:events'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { ipcMain } from 'electron'
import { probeServer, registerServerProbeIpcHandlers } from './serverProbe'
import { operations } from './operations'
import { cancelRequesterOperation } from './requesterOperation'
import { withCorrelation } from './actionCorrelation'

const state = vi.hoisted(() => ({ boundary: vi.fn(async (_stage: string) => {}), sockets: [] as any[],
  resolvers: [] as any[], v4: ['8.8.8.8'], v6: [] as string[], geoFail: false, tunnel: false,
  privateGeo: false, connectThrows: false }))
vi.mock('electron', () => ({ ipcMain: { handle: vi.fn() } }))
vi.mock('./appLogger', () => ({ logEvent: vi.fn() }))
vi.mock('./settings', () => ({ settingsStore: { get: () => ({ disableGeoLookup: state.privateGeo }) } }))
vi.mock('./tunController', () => ({ tunController: { getStatus: () => ({ running: state.tunnel }) } }))
vi.mock('dns', () => {
  const resolve4 = async (_host: string) => { await state.boundary('dns'); return state.v4 }
  const resolve6 = async (_host: string) => { await state.boundary('dns'); return state.v6 }
  const reverse = async (_ip: string) => { await state.boundary('reverse'); return ['edge.example.test'] }
  return { promises: { resolve4, resolve6, reverse, Resolver: class {
    cancel = vi.fn()
    resolve4 = resolve4; resolve6 = resolve6; reverse = reverse
    constructor(_options: unknown) { state.resolvers.push(this) }
  } } }
})
vi.mock('net', async original => {
  const actual = await original<typeof import('net')>()
  const { EventEmitter } = await import('node:events')
  return { ...actual, Socket: class extends EventEmitter {
    destroyed = false; closed = false; host = ''; port = 0
    constructor() { super(); state.sockets.push(this) }
    setTimeout = vi.fn()
    connect(port: number, host: string) {
      this.host = host; this.port = port
      if (state.connectThrows) throw new Error('private native connect detail')
      void state.boundary('tcp').then(() => { if (!this.destroyed) this.emit('connect') })
      return this
    }
    destroy() {
      if (!this.destroyed) { this.destroyed = true; void state.boundary('close').then(() => { this.closed = true; this.emit('close') }) }
      return this
    }
  } }
})
vi.mock('axios', () => ({ default: { get: async (url: string, _options: unknown) => {
  await state.boundary(url.includes('ipwho') ? 'asn-fallback' : 'asn')
  if (state.geoFail && !url.includes('ipwho')) throw new Error('private HTTP detail')
  return { data: { asn: 'AS1', org: 'fixture', country: 'fixture' } }
} } }))
const flush = async () => { for (let i = 0; i < 100; i++) await Promise.resolve() }
const releases = new Set<() => void>(), tasks = new Set<Promise<unknown>>()
function hold(stage: string) {
  let release!: () => void
  const gate = new Promise<void>(resolve => { release = resolve }); releases.add(release)
  state.boundary.mockImplementation(async current => { if (current === stage) await gate })
  return release
}
function start(options: Record<string, unknown> = {}) {
  let result: any
  const task = probeServer('vpn.example.test', 8443, options).then(value => { result = value }, error => { result = error })
  tasks.add(task)
  return { task, result: () => result }
}
beforeEach(() => {
  vi.useFakeTimers(); vi.mocked(ipcMain.handle).mockClear()
  state.boundary.mockReset().mockResolvedValue(undefined)
  state.sockets = []; state.resolvers = []; state.v4 = ['8.8.8.8']; state.v6 = []
  state.geoFail = false; state.tunnel = false; state.privateGeo = false; state.connectThrows = false
})
afterEach(async () => {
  for (const release of releases) release()
  releases.clear(); await vi.runAllTimersAsync(); await Promise.allSettled(tasks); tasks.clear()
  await operations.close(); operations.resumeAdmission(); vi.useRealTimers()
})

describe('server probe lifetime', () => {
  it.each(['dns', 'reverse', 'asn', 'asn-fallback', 'tcp'])('cancels at %s without late stages or results', async stage => {
    state.geoFail = stage === 'asn-fallback'
    const release = hold(stage), controller = new AbortController(), run = start({ signal: controller.signal })
    await flush(); expect(state.boundary).toHaveBeenCalledWith(stage)
    controller.abort(); await flush()
    expect(run.result()).toMatchObject({ category: 'cancelled' })
    const after = state.boundary.mock.calls.length
    release(); await run.task; await operations.close()
    expect(state.boundary.mock.calls.slice(after).every(([item]) => item === 'close')).toBe(true)
    expect(state.sockets.every(socket => socket.closed)).toBe(true)
    expect(state.resolvers.some(resolver => resolver.cancel.mock.calls.length > 0)).toBe(stage === 'dns' || stage === 'reverse')
  })
  it.each(['dns', 'reverse', 'asn', 'close'])('retains physical %s work until settlement', async stage => {
    const release = hold(stage), controller = new AbortController(), run = start({ signal: controller.signal })
    await flush(); controller.abort(); await flush()
    expect(run.result()).toMatchObject({ category: 'cancelled' })
    let drained = false
    const closing = operations.close().then(() => { drained = true }); await flush()
    expect(drained).toBe(false)
    release(); await closing; expect(state.sockets.every(socket => socket.closed)).toBe(true)
  })
  it('uses a typed deadline while retaining an unresponsive HTTP boundary', async () => {
    const release = hold('asn'), run = start()
    await flush(); await vi.advanceTimersByTimeAsync(9001)
    expect(run.result()).toMatchObject({ category: 'timeout' })
    release(); await run.task
  })
  it('retains the other DNS family after one cancelled query settles', async () => {
    const gates: Array<() => void> = []
    state.boundary.mockImplementation(stage => stage === 'dns' ? new Promise<void>(resolve => {
      gates.push(resolve); releases.add(resolve)
    }) : Promise.resolve())
    const controller = new AbortController(), run = start({ signal: controller.signal })
    await flush(); expect(gates).toHaveLength(2)
    controller.abort(); await flush()
    let drained = false
    const closing = operations.close().then(() => { drained = true })
    gates[0](); await flush()
    expect(drained).toBe(false)
    gates[1](); await closing
    expect(run.result()).toMatchObject({ category: 'cancelled' })
  })
  it('cancels private DNS resolvers at their stage limit and rejects late addresses', async () => {
    const release = hold('dns'), run = start()
    await flush(); await vi.advanceTimersByTimeAsync(2501)
    expect(state.resolvers).toHaveLength(2)
    expect(state.resolvers.every(resolver => resolver.cancel.mock.calls.length === 1)).toBe(true)
    expect(run.result()).toBeUndefined()
    release(); await run.task
    expect(run.result()).toMatchObject({ category: 'network' })
    expect(state.sockets).toHaveLength(0)
  })
  it('does not publish success before actual socket close', async () => {
    state.tunnel = true
    const release = hold('close'), run = start()
    await flush(); expect(run.result()).toBeUndefined()
    release(); await run.task
    expect(run.result()).toMatchObject({ host: 'vpn.example.test', resolvedIps: ['8.8.8.8'], latency: null })
    expect(state.sockets[0]).toMatchObject({ closed: true, host: '8.8.8.8', port: 8443 })
  })
  it('measures connect RTT without adding physical close drain time', async () => {
    const release = hold('close'), run = start()
    await flush(); expect(run.result()).toBeUndefined()
    await vi.advanceTimersByTimeAsync(250)
    release(); await vi.runAllTimersAsync(); await run.task
    expect(run.result().latency.samples).toEqual([0, 0, 0, 0, 0])
    expect(state.sockets.every(socket => socket.closed)).toBe(true)
  })
  it('does not resolve the hostname a second time for TCP and refuses missing/private answers', async () => {
    state.tunnel = true
    const run = start(); await vi.runAllTimersAsync(); await run.task
    expect(state.sockets.every(socket => socket.host === '8.8.8.8')).toBe(true)
    for (const ips of [[], ['127.0.0.1'], ['8.8.8.8', '10.1.2.3'], ['::ffff:127.0.0.1'], ['::ffff:7f00:1'], ['fe90::1'], ['0:0:0:0:0:0:0:1']]) {
      state.v4 = ips; state.sockets = []; state.boundary.mockClear()
      const failed = start(); await vi.runAllTimersAsync(); await failed.task
      expect(failed.result()).toMatchObject({ category: ips.length ? 'permission' : 'network' })
      expect(state.sockets).toHaveLength(0)
      expect(state.boundary.mock.calls.every(([stage]) => stage === 'dns')).toBe(true)
    }
  })
  it('closes sockets when native connect throws synchronously', async () => {
    state.connectThrows = true
    const run = start(); await vi.runAllTimersAsync(); await run.task
    expect(run.result()).toMatchObject({ openPorts: [], latency: null })
    expect(state.sockets.every(socket => socket.closed)).toBe(true)
  })
  it('preserves action correlation and allows independent probes', async () => {
    state.tunnel = true
    const release = hold('asn')
    const first = withCorrelation('ipc_11111111111141118111111111111111', () => start())
    const second = withCorrelation('ipc_22222222222242228222222222222222', () => start())
    await flush()
    expect(operations.list().slice(-2).map(row => row.correlationId)).toEqual([
      'ipc_11111111111141118111111111111111', 'ipc_22222222222242228222222222222222'])
    release(); await Promise.all([first.task, second.task])
    expect(first.result().resolvedIps).toEqual(['8.8.8.8']); expect(second.result().resolvedIps).toEqual(['8.8.8.8'])
  })
})

describe('server probe requester', () => {
  const token = '11111111-1111-4111-8111-111111111111'
  const sender = () => Object.assign(new EventEmitter(), { isDestroyed: () => false })
  function invoke(owner: ReturnType<typeof sender>, id?: string) {
    registerServerProbeIpcHandlers()
    const handler = vi.mocked(ipcMain.handle).mock.calls.find(([channel]) => channel === 'server:probe')![1]
    const task = Promise.resolve(handler({ sender: owner } as never, 'vpn.example.test', 8443, id))
    tasks.add(task); return task
  }
  it.each(['destroyed', 'did-navigate', 'render-process-gone'])('cancels requester document on %s', async event => {
    const release = hold('dns'), owner = sender()
    const task = invoke(owner).catch(error => error); await flush(); owner.emit(event); await flush()
    let result: unknown; void task.then(value => { result = value }); await flush()
    expect(result).toMatchObject({ category: 'cancelled' })
    release(); await operations.close(); expect(owner.eventNames()).toEqual([])
  })
  it('rejects duplicate/malformed tokens and isolates sender cancellation', async () => {
    const release = hold('dns'), owner = sender(), foreign = sender()
    const task = invoke(owner, token).catch(error => error); await flush()
    await expect(invoke(owner, token)).rejects.toMatchObject({ category: 'conflict' })
    await expect(invoke(owner, 'bad')).rejects.toMatchObject({ category: 'validation' })
    expect(cancelRequesterOperation(foreign as never, token)).toBe(false)
    expect(cancelRequesterOperation(owner as never, token)).toBe(true)
    expect(await task).toMatchObject({ category: 'cancelled' })
    release(); await operations.close(); expect(cancelRequesterOperation(owner as never, token)).toBe(false)
  })
  it('preserves legacy success and geo privacy without document listeners', async () => {
    state.tunnel = true; state.privateGeo = true
    const owner = sender(), task = invoke(owner)
    await vi.runAllTimersAsync(); expect(await task).toMatchObject({ asn: null, latency: null, tlsCert: null, httpBanner: null })
    expect(state.boundary).not.toHaveBeenCalledWith('asn'); expect(owner.eventNames()).toEqual([])
  })
})
