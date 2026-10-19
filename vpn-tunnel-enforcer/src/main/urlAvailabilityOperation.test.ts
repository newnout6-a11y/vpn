// AT-00-003/004/005/008: production URL probes with controlled OS boundaries.
import { EventEmitter } from 'node:events'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { ipcMain } from 'electron'
import { checkUrl, probePageSignal, registerUrlAvailabilityHandlers } from './urlAvailability'
import { operations } from './operations'
import { cancelRequesterOperation } from './requesterOperation'
import { withCorrelation } from './actionCorrelation'
import { logEvent } from './appLogger'

const state = vi.hoisted(() => ({
  boundary: vi.fn(async (_stage: string) => {}), history: [] as any[], writes: vi.fn(),
  windows: [] as any[], sockets: [] as any[], tunnel: false, headStatus: 200, windowSetupThrows: false,
  resolverCancel: vi.fn(), resolverOptions: [] as unknown[], clashReply: null as null | { status: number; data: unknown }
}))
vi.mock('./versionedStore', () => ({ default: class {
  get() { return state.history }
  set(_key: string, value: any[]) { state.writes(value); state.history = value }
} }))
vi.mock('./appLogger', () => ({ logEvent: vi.fn() }))
vi.mock('./settings', () => ({ settingsStore: { get: () => ({}) } }))
vi.mock('./tunController', () => ({ tunController: { getStatus: () => ({ running: state.tunnel }) },
  getDirectProxyPort: () => 19001, getClashApiInfo: () => ({ port: 19002, secret: 'FAKE-private' }) }))
vi.mock('dns', () => ({ promises: {
  Resolver: class {
    private rejectCancel!: (error: Error) => void
    private cancelled = new Promise<never>((_resolve, reject) => { this.rejectCancel = reject })
    constructor(options: unknown) { state.resolverOptions.push(options); void this.cancelled.catch(() => {}) }
    resolve4() { return Promise.race([state.boundary('dns4').then(() => ['8.8.8.8']), this.cancelled]) }
    resolve6() { return Promise.race([state.boundary('dns6').then(() => []), this.cancelled]) }
    cancel() { state.resolverCancel(); this.rejectCancel(Object.assign(new Error('query cancelled'), { code: 'ECANCELLED' })) }
  },
  resolve4: async () => { await state.boundary('dns4'); return ['8.8.8.8'] },
  resolve6: async () => { await state.boundary('dns6'); return [] }
} }))
vi.mock('axios', () => ({ default: {
  head: async () => { await state.boundary('http-head'); return { status: state.headStatus, headers: {} } },
  get: async (url: string) => {
    if (url.includes('/delay')) { await state.boundary('clash'); return state.clashReply ?? { status: 200, data: { delay: 10 } } }
    if (url.includes('ipapi.co')) { await state.boundary('asn'); return { data: { org: 'test', country: 'test' } } }
    await state.boundary('http-get'); return { status: 200, headers: {} }
  }
} }))
vi.mock('net', async importOriginal => {
  const original = await importOriginal<typeof import('net')>()
  const { EventEmitter } = await import('node:events')
  return { ...original, Socket: class extends EventEmitter {
    closed = false
    constructor() { super(); state.sockets.push(this) }
    setTimeout() { return this }
    connect() { void state.boundary('tcp').then(() => this.emit('connect')); return this }
    destroy() { void state.boundary('tcp-close').then(() => { this.closed = true; this.emit('close') }); return this }
  } }
})
vi.mock('tls', async () => {
  const { EventEmitter } = await import('node:events')
  return { connect: () => {
    const socket = Object.assign(new EventEmitter(), { closed: false, getCipher: () => ({ name: 'TLS' }), getProtocol: () => 'TLSv1.3',
      destroy() { void state.boundary('tls-close').then(() => { socket.closed = true; socket.emit('close') }); return socket } })
    state.sockets.push(socket)
    void state.boundary('tls').then(() => socket.emit('secureConnect'))
    return socket
  } }
})
vi.mock('electron', async () => {
  const { EventEmitter } = await import('node:events')
  return { ipcMain: { handle: vi.fn() }, BrowserWindow: class extends EventEmitter {
    destroyed = false
    webContents = Object.assign(new EventEmitter(), {
      setWindowOpenHandler: () => { if (state.windowSetupThrows) throw new Error('FAKE-private browser setup') },
      session: { setProxy: async () => { await state.boundary('proxy') } },
      executeJavaScript: async () => { await state.boundary('script'); return { title: 'test', textSample: 'ordinary page', textLength: 100 } }
    })
    constructor() { super(); state.windows.push(this) }
    async loadURL() { await state.boundary('page-load'); this.webContents.emit('did-finish-load') }
    isDestroyed() { return this.destroyed }
    destroy() { this.destroyed = true; void state.boundary('window-close').then(() => this.emit('closed')) }
  } }
})

const tasks = new Set<Promise<unknown>>(), releases = new Set<() => void>()
const track = <T>(task: Promise<T>) => { tasks.add(task); return task }
const flush = async () => { for (let i = 0; i < 70; i++) await Promise.resolve() }
function hold(stage: string) {
  let release!: () => void
  const gate = new Promise<void>(done => { release = done }); releases.add(release)
  state.boundary.mockImplementation(async current => { if (current === stage) await gate })
  return release
}
const options = (signal: AbortSignal) => ({ signal }) as Parameters<typeof checkUrl>[1]
const sender = () => Object.assign(new EventEmitter(), { isDestroyed: () => false })
beforeEach(() => {
  vi.useFakeTimers()
  state.history = []; state.windows = []; state.sockets = []; state.tunnel = false; state.headStatus = 200
  state.windowSetupThrows = false
  state.resolverCancel.mockClear(); state.resolverOptions = []
  state.clashReply = null
  state.boundary.mockReset().mockResolvedValue(undefined); state.writes.mockReset(); vi.mocked(logEvent).mockClear()
})
afterEach(async () => {
  for (const release of releases) release()
  releases.clear()
  await vi.runAllTimersAsync(); await Promise.allSettled(tasks); tasks.clear()
  await operations.close(); operations.resumeAdmission(); vi.useRealTimers()
})

describe('URL check ownership', () => {
  it('destroys and drains an offscreen window when synchronous setup throws', async () => {
    state.windowSetupThrows = true
    await expect(probePageSignal('https://example.test/')).rejects.toThrow('FAKE-private browser setup')
    expect(state.windows).toHaveLength(1)
    expect(state.windows[0].isDestroyed()).toBe(true)
    expect(vi.getTimerCount()).toBe(0)
  })
  it.each(['dns4', 'dns6', 'asn', 'tcp', 'tls', 'http-head', 'http-get', 'clash', 'proxy', 'page-load', 'script'])
  ('cancels at %s promptly and fences late probes/history', async stage => {
    const release = hold(stage), controller = new AbortController()
    state.headStatus = stage === 'http-get' ? 405 : 200
    state.tunnel = stage === 'clash'
    let result: unknown
    const task = track(checkUrl('https://example.test/', options(controller.signal)).then(value => { result = value }, error => { result = error }))
    await flush(); await vi.advanceTimersByTimeAsync(1500); await flush()
    expect(state.boundary).toHaveBeenCalledWith(stage)
    controller.abort(); await flush()
    expect(result).toMatchObject({ category: 'cancelled' })
    expect(operations.list().at(-1)).toMatchObject({ status: 'cancelled' })
    release(); await vi.runAllTimersAsync(); await task; await operations.close()
    expect(state.history).toEqual([])
    expect(state.writes).not.toHaveBeenCalled()
    expect(vi.mocked(logEvent).mock.calls.some(call => call[2] === 'check finished')).toBe(false)
    expect(state.windows.every(win => win.isDestroyed())).toBe(true)
    expect(state.sockets.every(socket => socket.closed)).toBe(true)
  })

  it.each(['tcp-close', 'tls-close', 'window-close', 'asn', 'http-head'])
  ('retains physical %s work after prompt cancellation', async stage => {
    const release = hold(stage), controller = new AbortController()
    const task = track(checkUrl('https://example.test/', options(controller.signal)).catch(error => error))
    await flush(); await vi.advanceTimersByTimeAsync(1500); await flush()
    controller.abort(); await flush()
    expect(await task).toMatchObject({ category: 'cancelled' })
    let drained = false
    const closing = operations.close().then(() => { drained = true }); await flush()
    expect(drained).toBe(false)
    release(); await vi.runAllTimersAsync(); await closing
    expect(state.writes).not.toHaveBeenCalled()
  })

  it('commits one current result with the action correlation and preserves prior history', async () => {
    state.history = [{ id: 'earlier' }]
    const correlationId = 'ipc_d5abf17ebf694f239e3cb69ed0b32089'
    const task = track(withCorrelation(correlationId, () => checkUrl('https://example.test/')))
    await flush(); await vi.advanceTimersByTimeAsync(1500); await flush()
    expect(await task).toMatchObject({ verdict: 'works-both' })
    expect(state.writes).toHaveBeenCalledOnce()
    expect(state.history).toHaveLength(2)
    expect(state.history[1]).toEqual({ id: 'earlier' })
    expect(operations.list().at(-1)).toMatchObject({ kind: 'availability-check', status: 'success', correlationId, owner: 'manual' })
    expect(state.history[0]).toMatchObject({ correlationId, provenance: {
      source: 'ipc', owner: 'manual', route: 'unconfirmed', confidence: 'observed'
    } })
  })

  it('makes the synchronous history commit terminal against reentrant cancellation', async () => {
    const controller = new AbortController()
    state.writes.mockImplementationOnce(() => controller.abort())
    const task = track(checkUrl('https://example.test/', options(controller.signal)))
    await flush(); await vi.advanceTimersByTimeAsync(1500); await flush()
    expect(await task).toHaveProperty('verdict', 'works-both')
    expect(operations.list().at(-1)).toMatchObject({ status: 'success' })
    expect(state.writes).toHaveBeenCalledOnce()
  })

  it('cancels only the owned requester token and rejects duplicate/malformed tokens', async () => {
    registerUrlAvailabilityHandlers()
    const handler = vi.mocked(ipcMain.handle).mock.calls.find(call => call[0] === 'url-availability:check')![1]
    const owner = sender(), foreign = sender(), id = 'a5abf17e-bf69-4f23-9e3c-b69ed0b32089'
    await expect(handler({ sender: owner } as never, 'https://example.test/', 'forged')).rejects.toMatchObject({ category: 'validation' })
    const release = hold('dns4')
    const task = track(Promise.resolve(handler({ sender: owner } as never, 'https://example.test/', id)).catch(error => error))
    await flush()
    await expect(handler({ sender: owner } as never, 'https://example.test/', id)).rejects.toMatchObject({ category: 'conflict' })
    expect(cancelRequesterOperation(foreign as never, id)).toBe(false)
    expect(cancelRequesterOperation(owner as never, id)).toBe(true)
    expect(await task).toMatchObject({ category: 'cancelled' })
    expect(cancelRequesterOperation(owner as never, id)).toBe(false)
    release(); await operations.close()
    expect(state.writes).not.toHaveBeenCalled()
    expect(owner.eventNames()).toEqual([])
  })

  it('rejects an already cancelled call before DNS or window creation', async () => {
    const controller = new AbortController(); controller.abort()
    await expect(checkUrl('https://example.test/', options(controller.signal))).rejects.toMatchObject({ category: 'cancelled' })
    expect(state.boundary).not.toHaveBeenCalled()
    expect(state.windows).toEqual([])
  })

  it('uses typed validation and a common deadline while retaining late DNS', async () => {
    await expect(checkUrl('ftp://example.test')).rejects.toMatchObject({ category: 'validation' })
    const release = hold('dns4')
    const task = track(checkUrl('https://example.test/').catch(error => error))
    await flush()
    await vi.advanceTimersByTimeAsync(60_000)
    expect(await task).toMatchObject({ category: 'timeout' })
    expect(operations.list().at(-1)).toMatchObject({ status: 'error', category: 'timeout' })
    expect(state.resolverCancel).toHaveBeenCalledOnce()
    release(); await operations.close()
    expect(state.writes).not.toHaveBeenCalled()
  })

  it('physically cancels DNS with a bounded resolver and permits an independent fresh check', async () => {
    const release = hold('dns4'), controller = new AbortController()
    const first = track(checkUrl('https://example.test/', options(controller.signal)).catch(error => error))
    await flush(); controller.abort(); await flush()
    expect(state.resolverCancel).toHaveBeenCalledOnce()
    expect(state.resolverOptions[0]).toEqual({ timeout: 8000, tries: 1 })
    expect(await first).toMatchObject({ category: 'cancelled' })
    state.boundary.mockResolvedValue(undefined)
    const fresh = track(checkUrl('https://other.test/'))
    await flush(); await vi.advanceTimersByTimeAsync(1500); await flush()
    expect(await fresh).toHaveProperty('verdict', 'works-both')
    release()
    expect(state.writes).toHaveBeenCalledOnce()
  })

  it.each(['proxy', 'script'])('uses actual window close to revoke a stuck %s promise', async stage => {
    const release = hold(stage), controller = new AbortController()
    const task = track(checkUrl('https://example.test/', options(controller.signal)).catch(error => error))
    await flush(); await vi.advanceTimersByTimeAsync(1500); await flush()
    controller.abort(); await flush()
    expect(await task).toMatchObject({ category: 'cancelled' })
    let drained = false
    const closing = operations.close().then(() => { drained = true }); await flush()
    expect(drained).toBe(true)
    release(); await closing
    expect(state.writes).not.toHaveBeenCalled()
  })

  it('fails explicitly when page proxy setup fails instead of publishing an unscored positive verdict', async () => {
    state.boundary.mockImplementation(async stage => { if (stage === 'proxy') throw new Error('FAKE-private proxy config') })
    await expect(track(checkUrl('https://example.test/'))).rejects.toMatchObject({ category: 'network' })
    expect(state.writes).not.toHaveBeenCalled()
    expect(state.windows.every(win => win.isDestroyed())).toBe(true)
    expect(state.boundary).not.toHaveBeenCalledWith('page-load')
  })

  it('admits independent simultaneous checks without mixing their history commits', async () => {
    const release = hold('http-head')
    const first = track(checkUrl('https://first.test/')), second = track(checkUrl('https://second.test/'))
    await flush()
    expect(state.boundary.mock.calls.filter(([stage]) => stage === 'http-head')).toHaveLength(2)
    release(); await flush(); await vi.advanceTimersByTimeAsync(1500); await flush()
    expect((await first).url).toBe('https://first.test/')
    expect((await second).url).toBe('https://second.test/')
    expect(state.writes).toHaveBeenCalledTimes(2)
    expect(new Set(state.history.map(row => row.url))).toEqual(new Set(['https://first.test/', 'https://second.test/']))
  })

  it('extracts an allowlisted Clash cause without exposing the response message', async () => {
    state.tunnel = true
    state.clashReply = { status: 500, data: { message: 'dial FAKE-private C:\\secret connection reset by peer' } }
    const task = track(checkUrl('https://example.test/'))
    await flush(); await vi.advanceTimersByTimeAsync(1500); await flush()
    const result = await task
    expect(result.direct?.errorMessage).toContain('ECONNRESET')
    expect(JSON.stringify(result)).not.toContain('FAKE-private')
    expect(JSON.stringify(result)).not.toContain('secret')
  })

  it.each(['ECONNRESET', 'ECONNREFUSED', 'ECONNABORTED', 'EPROTO', 'CERT_HAS_EXPIRED'])
  ('preserves safe diagnostic cause %s without exception text', async code => {
    state.boundary.mockImplementation(async stage => { if (stage.startsWith('http-')) throw Object.assign(new Error('FAKE-private at C:\\secret\\path'), { code }) })
    const result = await track(checkUrl('https://example.test/'))
    expect(result.direct?.errorMessage).toContain(code)
    expect(JSON.stringify(result)).not.toContain('FAKE-private')
    expect(JSON.stringify(result)).not.toContain('secret')
  })

  it.each(['destroyed', 'did-navigate', 'render-process-gone'])('binds the IPC check to document %s', async eventName => {
    registerUrlAvailabilityHandlers()
    const handler = vi.mocked(ipcMain.handle).mock.calls.find(call => call[0] === 'url-availability:check')![1]
    const owner = sender(), foreign = sender(), id = 'a5abf17e-bf69-4f23-9e3c-b69ed0b32089'
    const release = hold('dns4')
    let result: unknown
    const task = track(Promise.resolve(handler({ sender: owner } as never, 'https://example.test/', id)).then(value => { result = value }, error => { result = error }))
    await flush()
    expect(cancelRequesterOperation(foreign as never, id)).toBe(false)
    owner.emit(eventName); await flush()
    expect(result).toMatchObject({ category: 'cancelled' })
    expect(owner.listenerCount(eventName)).toBe(0)
    release(); await task; await operations.close()
    expect(state.writes).not.toHaveBeenCalled()
  })
})
