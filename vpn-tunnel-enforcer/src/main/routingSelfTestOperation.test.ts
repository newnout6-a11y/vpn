// AT-00-003/004/005: production routing probe, controlled HTTP/SOCKS boundaries.
import { EventEmitter } from 'node:events'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { runRoutingSelfTest } from './routingSelfTest'
import { operations } from './operations'
import { logEvent } from './appLogger'
import { withCorrelation } from './actionCorrelation'
import { ipcMain } from 'electron'
import { registerRoutingSelfTestHandlers } from './routingSelfTest'
import { cancelRequesterOperation } from './requesterOperation'

const state = vi.hoisted(() => ({ boundary: vi.fn(async (_stage: string) => {}), sockets: [] as any[],
  smart: true, tunnel: true, vpnError: false }))
vi.mock('./appLogger', () => ({ logEvent: vi.fn() }))
vi.mock('./settings', () => ({ settingsStore: { get: () => ({ smartRuSplit: state.smart }) } }))
vi.mock('./tunController', () => ({ tunController: { getStatus: () => ({ running: state.tunnel }) }, getDirectProxyPort: () => 19001 }))
vi.mock('electron', () => ({ ipcMain: { handle: vi.fn() } }))
vi.mock('axios', () => ({ default: { get: async (url: string) => {
  const stage = url.includes('yandex') ? 'ru' : 'vpn'
  await state.boundary(stage)
  if (state.vpnError && stage === 'vpn') throw new Error('FAKE-private HTTP at C:\\secret')
  return { data: stage === 'vpn' ? '8.8.8.8' : '9.9.9.9' }
} } }))
vi.mock('socks', async () => {
  const { EventEmitter } = await import('node:events')
  return { SocksClient: { createConnection: async () => {
    await state.boundary('socks')
    const socket = Object.assign(new EventEmitter(), {
      closed: false, writes: 0, setTimeout: vi.fn(),
      write() { socket.writes++; void state.boundary('body').then(() => {
        if (!socket.closed) socket.emit('data', Buffer.from('HTTP/1.1 200 OK\r\n\r\n9.9.9.9'))
      }) },
      destroy() { void state.boundary('close').then(() => { socket.closed = true; socket.emit('close') }); return socket }
    })
    state.sockets.push(socket)
    return { socket }
  } } }
})

const releases = new Set<() => void>(), tasks = new Set<Promise<unknown>>()
const track = <T>(task: Promise<T>) => { tasks.add(task); return task }
const flush = async () => { for (let i = 0; i < 60; i++) await Promise.resolve() }
function hold(stage: string) {
  let release!: () => void
  const gate = new Promise<void>(done => { release = done }); releases.add(release)
  state.boundary.mockImplementation(async current => { if (current === stage) await gate })
  return release
}
const run = runRoutingSelfTest
beforeEach(() => {
  vi.useFakeTimers(); state.boundary.mockReset().mockResolvedValue(undefined)
  state.sockets = []; state.smart = true; state.tunnel = true; state.vpnError = false
  vi.mocked(logEvent).mockClear()
})
afterEach(async () => {
  for (const release of releases) release()
  releases.clear(); await vi.runAllTimersAsync(); await Promise.allSettled(tasks); tasks.clear()
  await operations.close(); operations.resumeAdmission(); vi.useRealTimers()
})

describe('routing probe ownership', () => {
  it.each(['vpn', 'socks', 'body', 'ru'])('cancels promptly at %s and suppresses late work/logs', async stage => {
    const release = hold(stage), controller = new AbortController()
    let result: unknown
    const task = track(run({ signal: controller.signal }).then(value => { result = value }, error => { result = error }))
    await flush(); expect(state.boundary).toHaveBeenCalledWith(stage)
    controller.abort(); await flush()
    expect(result).toMatchObject({ category: 'cancelled' })
    const calls = state.boundary.mock.calls.length
    release(); await task; await flush(); await operations.close()
    expect(state.boundary.mock.calls.slice(calls).every(([item]) => item === 'close')).toBe(true)
    expect(state.sockets.every(socket => socket.closed)).toBe(true)
    expect(vi.mocked(logEvent).mock.calls.some(call => call[2] === 'completed')).toBe(false)
  })

  it.each(['vpn', 'socks', 'close'])('retains physical %s work until it drains', async stage => {
    const release = hold(stage), controller = new AbortController()
    const task = track(run({ signal: controller.signal }).catch(error => error))
    await flush(); controller.abort(); await flush()
    expect(await task).toMatchObject({ category: 'cancelled' })
    let drained = false
    const closing = operations.close().then(() => { drained = true }); await flush()
    expect(drained).toBe(false)
    release(); await closing
    expect(state.sockets.every(socket => socket.closed)).toBe(true)
    if (stage === 'socks') expect(state.sockets[0].writes).toBe(0)
  })

  it('waits for actual SOCKS close before publishing success', async () => {
    const release = hold('close'); let done = false
    const task = track(run().then(value => { done = true; return value }))
    await flush(); expect(done).toBe(false)
    release(); const result = await task
    expect(result.verdict).toBe('ok')
    expect(state.sockets[0].closed).toBe(true)
    expect(operations.list().at(-1)).toMatchObject({ kind: 'routing-check', status: 'success', owner: 'manual' })
  })

  it('has a typed deadline and no late fallback requests', async () => {
    state.vpnError = true
    const release = hold('vpn'), task = track(run().catch(error => error))
    await flush(); await vi.advanceTimersByTimeAsync(60_000)
    expect(await task).toMatchObject({ category: 'timeout' })
    release(); await operations.close()
    expect(state.boundary.mock.calls.filter(([stage]) => stage === 'vpn')).toHaveLength(1)
    expect(state.boundary).not.toHaveBeenCalledWith('ru')
  })

  it('refuses an already aborted request without starting probes', async () => {
    const controller = new AbortController(); controller.abort()
    await expect(run({ signal: controller.signal })).rejects.toMatchObject({ category: 'cancelled' })
    expect(state.boundary).not.toHaveBeenCalled()
  })

  it('keeps independent operations/correlation identities and successful logs', async () => {
    const release = hold('vpn')
    const firstId = 'ipc_11111111111141118111111111111111', secondId = 'ipc_22222222222242228222222222222222'
    const first = track(withCorrelation(firstId, () => run()))
    const second = track(withCorrelation(secondId, () => run()))
    await flush(); const records = operations.list().slice(-2)
    expect(records.map(row => row.correlationId)).toEqual([firstId, secondId])
    expect(records[0].operationId).not.toBe(records[1].operationId)
    release(); expect((await first).verdict).toBe('ok'); expect((await second).verdict).toBe('ok')
    expect(vi.mocked(logEvent).mock.calls.filter(call => call[2] === 'completed')).toHaveLength(2)
  })
})

describe('routing requester handler', () => {
  const token = '11111111-1111-4111-8111-111111111111'
  const sender = () => Object.assign(new EventEmitter(), { isDestroyed: () => false })
  const invoke = (owner: ReturnType<typeof sender>, id?: string) => {
    registerRoutingSelfTestHandlers()
    const handler = vi.mocked(ipcMain.handle).mock.calls.find(([name]) => name === 'run-routing-self-test')![1]
    return track(Promise.resolve(handler({ sender: owner } as never, id)))
  }
  it.each(['destroyed', 'did-navigate', 'render-process-gone'])('cancels when requester document emits %s', async event => {
    const release = hold('vpn'), owner = sender()
    const task = invoke(owner).catch(error => error)
    await flush(); owner.emit(event); await flush()
    expect(await task).toMatchObject({ category: 'cancelled' })
    release(); await operations.close()
    expect(owner.listenerCount(event)).toBe(0)
    expect(vi.mocked(logEvent).mock.calls.some(call => call[2] === 'completed')).toBe(false)
  })
  it('rejects duplicate/malformed tokens and isolates cancellation by sender', async () => {
    const release = hold('vpn'), owner = sender(), foreign = sender()
    const task = invoke(owner, token).catch(error => error); await flush()
    await expect(invoke(owner, token)).rejects.toMatchObject({ category: 'conflict' })
    await expect(invoke(owner, 'bad')).rejects.toMatchObject({ category: 'validation' })
    expect(cancelRequesterOperation(foreign as never, token)).toBe(false)
    expect(cancelRequesterOperation(owner as never, token)).toBe(true)
    expect(await task).toMatchObject({ category: 'cancelled' })
    expect(cancelRequesterOperation(owner as never, token)).toBe(false)
    release(); await operations.close()
  })
  it('preserves legacy zero-token success and removes document listeners', async () => {
    state.tunnel = false
    const owner = sender()
    await expect(invoke(owner)).resolves.toMatchObject({ verdict: 'tunnel-off' })
    expect(owner.eventNames()).toEqual([])
    expect(state.boundary).not.toHaveBeenCalled()
  })
  it('allows the same token for different senders and cancels only its owner', async () => {
    const release = hold('vpn'), firstOwner = sender(), secondOwner = sender()
    const first = invoke(firstOwner, token).catch(error => error), second = invoke(secondOwner, token)
    await flush()
    expect(cancelRequesterOperation(firstOwner as never, token)).toBe(true)
    expect(await first).toMatchObject({ category: 'cancelled' })
    release(); expect((await second).verdict).toBe('ok')
    expect(secondOwner.eventNames()).toEqual([])
  })
})
