// AT-00-003/005/007: production speed runner + registry + guard + real Conf.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { Readable } from 'node:stream'
import { mkdir, mkdtemp, rm } from 'node:fs/promises'
import { join } from 'node:path'
import { performance } from 'node:perf_hooks'
import { createServer } from 'node:http'

const state = vi.hoisted(() => ({ dir: '', send: vi.fn(), get: vi.fn(), post: vi.fn(), log: vi.fn(), handle: vi.fn(),
  currentIp: vi.fn(), handlers: new Map<string, (...args: any[]) => any>(), running: true }))
vi.mock('electron', () => ({
  ipcMain: { handle: state.handle }, app: { isPackaged: false },
  BrowserWindow: { getAllWindows: () => [{ isDestroyed: () => false, webContents: { send: state.send } }] }
}))
vi.mock('axios', () => ({ default: { get: state.get, post: state.post } }))
vi.mock('./appLogger', () => ({ logEvent: state.log }))
vi.mock('./tunController', () => ({ tunController: { getStatus: () => ({ running: state.running, vpnProfileName: 'fixture' }) } }))
vi.mock('./ipMonitor', () => ({ ipMonitor: { getCurrentIp: state.currentIp } }))
vi.mock('electron-store', async () => {
  const { default: Conf } = await vi.importActual<typeof import('conf')>('conf')
  return { default: class extends Conf {
    constructor(options: Record<string, unknown>) { super({ ...options, cwd: state.dir, configName: String(options.name), projectVersion: '1.1.24' }) }
  } }
})

const pendingGates = new Set<() => void>()
function held<T>() {
  let resolve!: (value: T) => void
  let settled = false
  const fallback = () => resolve({ data: {} } as T)
  const promise = new Promise<T>(done => { resolve = value => {
    settled = true
    pendingGates.delete(fallback)
    done(value)
  } })
  pendingGates.add(fallback)
  return { promise, resolve, get settled() { return settled } }
}
const response = () => ({ data: Readable.from([{ length: 3 * 1024 * 1024 }]) })
let speed: typeof import('./speedTest').speedTest, registry: typeof import('./operations').operations

beforeEach(async () => {
  vi.resetModules()
  vi.clearAllMocks()
  state.running = true
  state.currentIp.mockResolvedValue({ ip: null })
  state.handlers.clear()
  await mkdir('.tmp', { recursive: true })
  state.dir = await mkdtemp(join(process.cwd(), '.tmp', 'speed-operations-'))
  state.handle.mockImplementation((channel, handler) => state.handlers.set(channel, handler))
  const { ipcMain } = await import('electron')
  ipcMain.handle = state.handle
  delete (ipcMain as any)[Symbol.for('vpnte.ipc.trusted-boundary.installed')]
  ;(await import('./ipcSecurity')).installTrustedIpcBoundary()
  const service = await import('./operations')
  registry = service.operations
  service.registerOperationHandlers()
  speed = (await import('./speedTest')).speedTest
  speed.registerHandlers()
  state.get.mockImplementation(async (_url: string, options) => options?.responseType === 'stream' ? response() : { data: {} })
  state.post.mockImplementation(async (_url, stream) => { for await (const _chunk of stream) { /* drain fake transport */ }; return { status: 200 } })
})
afterEach(async () => {
  const closing = registry?.close()
  for (const release of pendingGates) release()
  await closing
  vi.restoreAllMocks()
  if (state.dir) await rm(state.dir, { recursive: true, force: true })
})
async function persistedHistory() {
  const { default: Conf } = await vi.importActual<typeof import('conf')>('conf')
  return new Conf({ cwd: state.dir, configName: 'speed-test', projectVersion: '1.1.24' }).get('history')
}
const operationEvents = () => state.log.mock.calls.filter(call => call[2] === 'feature operation').map(call => call[3])

describe('owned speed test effects', () => {
  it('does not persist a result if cancelled while publishing the final completion frame', async () => {
    const controller = new AbortController()
    state.send.mockImplementation((_channel, progress) => {
      if (progress.phase === 'complete') controller.abort()
    })
    await expect(speed.run({ signal: controller.signal })).rejects.toMatchObject({ category: 'cancelled' })
    await vi.waitFor(() => expect(speed.isRunning()).toBe(false))
    expect(await persistedHistory()).toEqual([])
    expect(operationEvents().map(operation => operation.status)).toEqual(['running', 'cancelled'])
  })
  it.each([10, 50, 90, 100])('cancels at %i percent, suppressing subsequent progress and persisted history', async target => {
    const controller = new AbortController(), streams: Readable[] = []
    state.get.mockImplementation(async (_url: string, options) => {
      if (options.responseType !== 'stream') return { data: {} }
      const stream = response(); streams.push(stream.data); return stream
    })
    let cancelledAt = 0, eventCount = 0
    state.send.mockImplementation((_channel, data) => {
      if (!cancelledAt && data.percent >= target) {
        cancelledAt = performance.now()
        eventCount = state.send.mock.calls.length
        controller.abort()
      }
    })
    await expect(speed.run({ signal: controller.signal })).rejects.toMatchObject({ category: 'cancelled' })
    expect(cancelledAt).toBeGreaterThan(0)
    expect(performance.now() - cancelledAt).toBeLessThan(900)
    await vi.waitFor(() => expect(speed.isRunning()).toBe(false))
    for (const stream of streams) stream.push({ length: 1000 }) // deliberately late transport callback
    expect(state.send).toHaveBeenCalledTimes(eventCount)
    expect(await persistedHistory()).toEqual([])
    expect(operationEvents().map(operation => operation.status)).toEqual(['running', 'cancelled'])
    for (const [, options] of state.get.mock.calls) {
      expect(options.signal).toBeInstanceOf(AbortSignal)
      expect(options.signal.aborted).toBe(true)
    }
  })

  it.each(['latency', 'download', 'upload'] as const)('retains admission while a cancelled %s request ignores abort and returns late', async phase => {
    const gate = held<any>(), entered = held<void>(), controller = new AbortController()
    let blocked = false
    if (phase === 'upload') {
      state.post.mockImplementationOnce(() => { blocked = true; entered.resolve(); return gate.promise })
    } else {
      const normal = state.get.getMockImplementation()!
      state.get.mockImplementation((url, options) => {
        if (!blocked && (phase === 'latency' || options.responseType === 'stream')) {
          blocked = true; entered.resolve(); return gate.promise
        }
        return normal(url, options)
      })
    }
    const task = speed.run({ signal: controller.signal }).catch(error => error)
    await vi.waitFor(() => expect(entered.settled).toBe(true))
    controller.abort()
    expect(await task).toMatchObject({ category: 'cancelled' })
    const eventCount = state.send.mock.calls.length
    expect(speed.isRunning()).toBe(true)
    await expect(speed.run()).rejects.toMatchObject({ category: 'conflict' })
    const late = response()
    gate.resolve(phase === 'download' ? late : { data: {} })
    await vi.waitFor(() => expect(speed.isRunning()).toBe(false))
    if (phase === 'download') expect(late.data.destroyed).toBe(true)
    expect(state.send).toHaveBeenCalledTimes(eventCount)
    expect(await persistedHistory()).toEqual([])
  })

  it('destroys response streams when cancellation lands between headers and stream consumption', async () => {
    const gate = held<any>(), controller = new AbortController(), late = response()
    const normal = state.get.getMockImplementation()!
    state.get.mockImplementation((url, options) => options.responseType === 'stream' ? gate.promise : normal(url, options))
    const task = speed.run({ signal: controller.signal }).catch(error => error)
    await vi.waitFor(() => expect(state.get.mock.calls.some(([, options]) => options.responseType === 'stream')).toBe(true))
    gate.resolve(late)
    queueMicrotask(() => controller.abort())
    expect(await task).toMatchObject({ category: 'cancelled' })
    await vi.waitFor(() => expect(speed.isRunning()).toBe(false))
    expect(late.data.destroyed).toBe(true)
    expect(await persistedHistory()).toEqual([])
  })

  it('returns deadline promptly, suppresses late network fallback, and drains before shutdown completes', async () => {
    const gate = held<any>(), entered = held<void>()
    state.get.mockImplementationOnce(() => { entered.resolve(); return gate.promise })
    const task = speed.run({ timeoutMs: 25 }).catch(error => error)
    await vi.waitFor(() => expect(entered.settled).toBe(true))
    const started = performance.now()
    expect(await task).toMatchObject({ category: 'timeout' })
    expect(performance.now() - started).toBeLessThan(900)
    const closed = vi.fn(), closing = registry.close().then(closed)
    await Promise.resolve()
    expect(closed).not.toHaveBeenCalled()
    gate.resolve({ data: {} })
    await closing
    expect(state.get).toHaveBeenCalledOnce()
    expect(await persistedHistory()).toEqual([])
    expect(operationEvents().map(operation => operation.status)).toEqual(['running', 'error'])
  })

  it('revokes IP monitor publication while a cancelled verification still drains', async () => {
    const gate = held<any>(), controller = new AbortController()
    state.get.mockImplementation(async (url: string, options) => options.responseType === 'stream' ? response()
      : { data: url.includes('ipify') ? { ip: '203.0.113.1' } : {} })
    state.currentIp.mockImplementationOnce(() => gate.promise)
    const task = speed.run({ signal: controller.signal }).catch(error => error)
    await vi.waitFor(() => expect(state.currentIp).toHaveBeenCalledOnce())
    const canPublish = state.currentIp.mock.calls[0][0]
    try {
      expect(canPublish).toBeTypeOf('function')
      expect(canPublish()).toBe(true)
      controller.abort()
      expect(await task).toMatchObject({ category: 'cancelled' })
      expect(canPublish()).toBe(false)
      expect(state.currentIp.mock.calls[0][1]).toBeInstanceOf(AbortSignal)
      expect(state.currentIp.mock.calls[0][1].aborted).toBe(true)
      expect(speed.isRunning()).toBe(true)
    } finally { controller.abort(); gate.resolve({ ip: '198.51.100.1' }) }
    await vi.waitFor(() => expect(speed.isRunning()).toBe(false))
    expect(await persistedHistory()).toEqual([])
  })

  it('aborts and drains a failed download round before retry, without stale progress', async () => {
    const slow = held<any>(), failed = held<any>(), oldStream = new Readable({ read() {} })
    let downloadCalls = 0, firstSignal!: AbortSignal
    const normal = state.get.getMockImplementation()!
    state.get.mockImplementation((url, options) => {
      if (options.responseType !== 'stream') return normal(url, options)
      if (++downloadCalls === 1) { firstSignal = options.signal; return slow.promise }
      if (downloadCalls === 2) return failed.promise.then(() => { throw new Error('failed first target') })
      return Promise.resolve(response())
    })
    const task = speed.run().catch(error => error)
    await vi.waitFor(() => expect(downloadCalls).toBe(2))
    failed.resolve({})
    try {
      await vi.waitFor(() => expect(firstSignal.aborted).toBe(true))
      expect(downloadCalls).toBe(2)
    } finally { slow.resolve({ data: oldStream }) }
    const result = await task
    expect(result.serverName).toBe('OVH')
    expect(oldStream.destroyed).toBe(true)
    expect(operationEvents().map(operation => operation.status)).toEqual(['running', 'success'])
    const before = state.send.mock.calls.length
    oldStream.push(Buffer.alloc(64))
    expect(state.send).toHaveBeenCalledTimes(before)
    expect(await persistedHistory()).toMatchObject([result])
  })

  it('exposes cancellation by UUID through the real guarded handlers, without allowing a stale ID to cancel replacement work', async () => {
    const firstGate = held<any>(), secondGate = held<any>()
    state.get.mockImplementationOnce(() => firstGate.promise)
    const running = state.handlers.get('speed-test:run')!({})
    const listing = await state.handlers.get('operations:list')!({})
    const first = listing.result[0]
    expect(first).toMatchObject({ kind: 'speed-test', source: 'ipc', owner: 'manual', status: 'running' })
    const invalid = await state.handlers.get('operations:cancel')!({}, 'not-a-uuid')
    expect(invalid).toMatchObject({ ok: false, error: { category: 'validation' } })
    expect(registry.list()[0].status).toBe('running')
    expect(await state.handlers.get('operations:cancel')!({}, first.operationId)).toMatchObject({ ok: true, result: true })
    expect(await running).toMatchObject({ ok: false, correlationId: first.correlationId, error: { category: 'cancelled' } })
    firstGate.resolve({ data: {} })
    await vi.waitFor(() => expect(speed.isRunning()).toBe(false))
    state.get.mockImplementationOnce(() => secondGate.promise)
    const replacement = speed.run().catch(error => error)
    const second = registry.list().at(-1)!
    expect(speed.cancel(first.operationId)).toBe(false)
    expect(second.status).toBe('running')
    expect(speed.cancel(second.operationId)).toBe(true)
    expect(await replacement).toMatchObject({ category: 'cancelled' })
    secondGate.resolve({ data: {} })
    await vi.waitFor(() => expect(speed.isRunning()).toBe(false))
    expect(await persistedHistory()).toEqual([])
  })

  it('persists one successful result, with one terminal operation sharing the actual IPC correlation', async () => {
    const result = await state.handlers.get('speed-test:run')!({})
    expect(result.ok).toBe(true)
    expect(await persistedHistory()).toMatchObject([result.result])
    const events = operationEvents()
    expect(events.map(operation => operation.status)).toEqual(['running', 'success'])
    expect(events.every(operation => operation.correlationId === result.correlationId)).toBe(true)
    const operation = registry.list().at(-1)!
    const progressIds = new Set(state.send.mock.calls.map(call => call[1].operationId))
    expect([...progressIds]).toEqual([operation.operationId])
    const diagnosticId = 'op_' + operation.operationId.replaceAll('-', '')
    expect(events.every(event => event.operationId === diagnosticId && event.operationKey === diagnosticId)).toBe(true)
  })

  it('rejects VPN-off as a typed conflict without issuing network requests', async () => {
    state.running = false
    expect(await state.handlers.get('speed-test:run')!({})).toMatchObject({ ok: false, error: { category: 'conflict' } })
    expect(state.get).not.toHaveBeenCalled()
    expect(state.post).not.toHaveBeenCalled()
    expect(await persistedHistory()).toEqual([])
  })

  it('aborts an actual loopback HTTP request and releases its socket instead of only ignoring its result', async () => {
    const axios = (await vi.importActual<typeof import('axios')>('axios')).default
    const entered = held<void>(), closed = held<void>(), controller = new AbortController()
    const server = createServer((request, response) => { entered.resolve(); request.on('close', () => closed.resolve()); response.on('error', () => {}) })
    await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve))
    const address = server.address() as import('node:net').AddressInfo
    state.get.mockImplementation((_url, options) => axios.get(`http://127.0.0.1:${address.port}`, { ...options, proxy: false }))
    const task = speed.run({ signal: controller.signal }).catch(error => error)
    try {
      await vi.waitFor(() => expect(entered.settled).toBe(true))
      controller.abort()
      expect(await task).toMatchObject({ category: 'cancelled' })
      await vi.waitFor(() => expect(closed.settled).toBe(true))
      await vi.waitFor(() => expect(speed.isRunning()).toBe(false))
      expect(await persistedHistory()).toEqual([])
    } finally { controller.abort(); server.closeAllConnections(); await new Promise<void>(resolve => server.close(() => resolve())) }
  })
})
