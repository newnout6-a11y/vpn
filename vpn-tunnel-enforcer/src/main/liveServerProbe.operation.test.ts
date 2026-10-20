// AT-00-003/005/007: root cancellation fences progress/history and retains physical work.
import { EventEmitter } from 'node:events'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
const state = vi.hoisted(() => ({
  a: vi.fn(), aaaa: vi.fn(), sockets: [] as any[], requests: [] as any[], children: [] as any[],
  profiles: [] as any[], ready: vi.fn(), rm: vi.fn(), geo: vi.fn(),
  save: vi.fn(), splitRead: vi.fn(() => ({ enabled: false })), splitLoads: 0,
  splitGate: undefined as Promise<void> | undefined,
  handlers: new Map<string, Function>()
}))
vi.mock('electron', () => ({ app: { getPath: () => '/tmp/test-userdata' }, ipcMain: { handle: (channel: string, effect: Function) => state.handlers.set(channel, effect) } }))
vi.mock('./appLogger', () => ({ logEvent: vi.fn() }))
vi.mock('axios', () => ({ default: { get: state.geo } }))
vi.mock('./settings', () => ({ settingsStore: { get: () => ({ disableGeoLookup: true, proxyEngine: 'sing-box' }) } }))
vi.mock('./serverPicker', () => ({ serverPicker: { getProfiles: () => state.profiles, getActiveProfile: () => null } }))
vi.mock('./tunController', () => ({ tunController: { getStatus: () => ({ running: false }) }, getBundledResource: () => '/tmp/sing-box.exe', pickFreeLocalPort: async () => 50123 }))
vi.mock('./physicalAdapterLockdown', () => ({ getPhysicalAdapterDnsSources: async () => [] }))
vi.mock('./managedChildProcess', () => ({ cleanupManagedChildPidDirs: async () => {}, writeManagedChildPidFile: async () => {}, removeManagedChildPidFile: async () => {} }))
vi.mock('fs/promises', async original => ({ ...await original<typeof import('fs/promises')>(), mkdtemp: async () => '/tmp/live-owner-fixture', readFile: async () => '', writeFile: async () => {}, rm: state.rm }))
vi.mock('./keyHealthChecker', async original => ({ ...await original<typeof import('./keyHealthChecker')>(), buildKeyProbeConfig: () => ({}), waitForLocalSocks: state.ready }))
vi.mock('./liveServerHistory', () => ({
  liveServerHistory: { addCheck: state.save, getPreviousSuccessfulCheck: () => null },
  computeHistoryDiff: vi.fn(), sanitizeLiveCheckForStorage: (value: unknown) => value
}))
vi.mock('./splitTunneling', async () => {
  state.splitLoads++; await state.splitGate
  return { splitTunneling: { getConfig: state.splitRead, getDirectProcessNames: () => [], getVpnProcessNames: () => [], getDirectProcessPaths: () => [] } }
})
vi.mock('dns', async original => ({ ...await original<typeof import('dns')>(), promises: { Resolver: class {
  cancel = vi.fn(); resolve4 = state.a; resolve6 = state.aaaa; resolveCname = async () => []; reverse = async () => []
} } }))
vi.mock('net', async original => ({ ...await original<typeof import('net')>(), Socket: class extends EventEmitter {
  destroy = vi.fn(() => this); setTimeout = vi.fn(() => this); connect = vi.fn(() => this)
  constructor() { super(); state.sockets.push(this) }
} }))
vi.mock('http', () => ({ request: () => {
  const request = Object.assign(new EventEmitter(), { end: vi.fn(), destroy: vi.fn() })
  state.requests.push(request); return request
} }))
vi.mock('child_process', async original => ({ ...await original<typeof import('child_process')>(), spawn: () => {
  const child = Object.assign(new EventEmitter(), { pid: 12001, stdout: Object.assign(new EventEmitter(), { destroy: vi.fn() }), stderr: Object.assign(new EventEmitter(), { destroy: vi.fn() }), kill: vi.fn() })
  state.children.push(child); return child
} }))
import { collectSplitTunnelDiagnostics, probeInfrastructure, registerLiveServerProbeIpcHandlers, runLiveServerBatchCheck, runLiveServerCheck } from './liveServerProbe'
import { operations } from './operations'
import { withCorrelation } from './actionCorrelation'
const flush = async () => { for (let i = 0; i < 60; i++) await Promise.resolve() }
const releases: Array<() => void> = []
function held<T>(fallback: T) { let release!: (value: T) => void; const promise = new Promise<T>(done => { release = done }); releases.push(() => release(fallback)); return { promise, release } }
function observe<T>(task: Promise<T>) {
  const result = { settled: false, value: undefined as T | undefined, error: undefined as any }
  void task.then(value => { result.settled = true; result.value = value }, error => { result.settled = true; result.error = error })
  return result
}
async function drainFixtures() {
  for (let i = 0; i < 20; i++) {
    for (const resource of [...state.sockets, ...state.requests]) resource.emit('close')
    for (const child of state.children) child.emit('close', 0)
    await flush()
    await vi.advanceTimersByTimeAsync(60)
  }
}
beforeEach(() => {
  vi.useFakeTimers(); operations.resumeAdmission(); state.sockets = []; state.requests = []; state.children = []
  state.save.mockReset(); state.a.mockReset().mockResolvedValue([]); state.aaaa.mockReset().mockResolvedValue([])
  state.profiles = []; state.ready.mockReset().mockResolvedValue(undefined); state.rm.mockReset().mockResolvedValue(undefined)
  state.geo.mockReset()
})
afterEach(async () => {
  const closing = operations.close(); for (const release of releases.splice(0)) release()
  await drainFixtures(); await closing; operations.resumeAdmission(); vi.useRealTimers()
})
describe('root live-check ownership', () => {
  it.each(['cancel', 'deadline', 'shutdown'])('returns promptly on %s while delayed DNS still drains', async boundary => {
    const a = held<Array<{ address: string; ttl: number }>>([]), aaaa = held<Array<{ address: string; ttl: number }>>([])
    state.a.mockReturnValueOnce(a.promise); state.aaaa.mockReturnValueOnce(aaaa.promise)
    const controller = new AbortController(), progress = vi.fn(), previous = operations.list().length
    const result = observe(withCorrelation('ipc_11111111111141118111111111111111', () => runLiveServerCheck({ host: 'probe.example', port: 80 }, controller.signal, progress)))
    await flush(); let closing: Promise<void> | undefined, closed = false
    if (boundary === 'cancel') controller.abort()
    else if (boundary === 'deadline') await vi.advanceTimersByTimeAsync(25_000)
    else { closing = operations.close().then(() => { closed = true }) }
    await flush()
    expect(result.settled).toBe(true)
    expect(result.error).toMatchObject({ category: boundary === 'deadline' ? 'timeout' : 'cancelled' })
    const record = operations.list().slice(previous).find(operation => operation.kind === 'server-probe')!
    expect(record).toMatchObject({ status: boundary === 'deadline' ? 'error' : 'cancelled', correlationId: 'ipc_11111111111141118111111111111111', owner: 'manual' })
    expect(record.operationId).toMatch(/^[0-9a-f-]{36}$/)
    const notifications = progress.mock.calls.length
    expect(closed).toBe(false)
    a.release([{ address: '192.0.2.1', ttl: 60 }]); await flush(); expect(closed).toBe(false)
    aaaa.release([]); await drainFixtures(); await closing
    expect(state.sockets).toHaveLength(0); expect(state.requests).toHaveLength(0); expect(state.children).toHaveLength(0)
    expect(progress).toHaveBeenCalledTimes(notifications); expect(state.save).not.toHaveBeenCalled()
    if (boundary === 'shutdown') expect(closed).toBe(true)
  })
  it('suppresses late parallel progress and does not start the next phase after cancel', async () => {
    const controller = new AbortController(), progress = vi.fn()
    const result = observe(runLiveServerCheck({ host: 'probe.example', port: 80 }, controller.signal, progress))
    await flush(); expect(state.sockets.length).toBeGreaterThan(0); expect(state.requests).toHaveLength(1)
    controller.abort(); await flush(); expect(result.error).toMatchObject({ category: 'cancelled' })
    const notifications = progress.mock.calls.length
    const closing = operations.close(), closed = observe(closing)
    await flush(); expect(closed.settled).toBe(false)
    await drainFixtures(); await closing
    expect(progress).toHaveBeenCalledTimes(notifications); expect(state.save).not.toHaveBeenCalled(); expect(state.children).toHaveLength(0)
    expect(progress.mock.calls.some(([event]) => event.stage === 'handshake')).toBe(false)
  })
  it('does not start DNS or publish progress for an already cancelled request', async () => {
    const controller = new AbortController(), progress = vi.fn(); controller.abort()
    const result = observe(runLiveServerCheck({ host: 'probe.example', port: 80 }, controller.signal, progress))
    await flush(); expect(result.error).toMatchObject({ category: 'cancelled' })
    expect(state.a).not.toHaveBeenCalled(); expect(progress).not.toHaveBeenCalled(); expect(state.save).not.toHaveBeenCalled()
  })
  it.skipIf(process.platform !== 'win32')('retains a cancelled Windows path query until child close without starting PMTU', async () => {
    const controller = new AbortController(), progress = vi.fn()
    const result = observe(runLiveServerCheck({ host: '192.0.2.1', port: 80 }, controller.signal, progress))
    // Let the parallel stage finish but keep the Windows query physically open.
    for (let i = 0; i < 20 && !state.children.length; i++) {
      for (const resource of [...state.sockets, ...state.requests]) resource.emit('close')
      await flush(); await vi.advanceTimersByTimeAsync(60)
    }
    expect(state.children).toHaveLength(1); const child = state.children[0]
    controller.abort(); await flush(); expect(result.error).toMatchObject({ category: 'cancelled' }); expect(child.kill).toHaveBeenCalledOnce()
    const closing = operations.close(), closed = observe(closing); await flush(); expect(closed.settled).toBe(false)
    child.stdout.emit('data', Buffer.from('{"InterfaceIndex":42}')); child.emit('close', 0); await closing
    expect(state.children).toHaveLength(1); expect(state.save).not.toHaveBeenCalled()
    expect(progress.mock.calls.some(([event]) => event.stage === 'pmtu')).toBe(false)
  })
  it('keeps the root owner through handshake cleanup and delayed readiness after the caller is cancelled', async () => {
    const gate = held<void>(undefined); state.ready.mockReturnValueOnce(gate.promise)
    state.profiles = [{ id: 'target', protocol: 'vless', server: 'probe.example', port: 80, outbound: { type: 'vless', server: 'probe.example', server_port: 80 } }]
    const controller = new AbortController(), progress = vi.fn()
    const result = observe(runLiveServerCheck({ profileId: 'target' }, controller.signal, progress))
    for (let i = 0; i < 20 && !state.children.length; i++) {
      for (const resource of [...state.sockets, ...state.requests]) resource.emit('close')
      await flush(); await vi.advanceTimersByTimeAsync(60)
    }
    await flush(); expect(state.ready).toHaveBeenCalledOnce(); const child = state.children[0]
    controller.abort(); await flush(); expect(result.error).toMatchObject({ category: 'cancelled' })
    const closing = operations.close(), closed = observe(closing)
    await vi.advanceTimersByTimeAsync(5_001); expect(closed.settled).toBe(false); expect(state.rm).not.toHaveBeenCalled()
    expect(child.kill.mock.calls).toEqual([['SIGTERM'], ['SIGKILL']])
    child.emit('close', 0); await flush(); expect(closed.settled).toBe(false)
    gate.release(); await closing
    expect(state.rm).toHaveBeenCalledOnce(); expect(state.save).not.toHaveBeenCalled()
    expect(progress.mock.calls.some(([event]) => event.stage === 'path')).toBe(false)
  })
  it('commits a completed diagnostic exactly once, then ignores a later cancellation', async () => {
    const controller = new AbortController(), progress = vi.fn()
    const result = observe(runLiveServerCheck({ host: 'probe.example', port: 80 }, controller.signal, progress))
    await drainFixtures(); expect(result.error).toBeUndefined(); expect(result.settled).toBe(true)
    expect(state.save).toHaveBeenCalledOnce(); expect(result.value?.cancelled).toBe(false)
    const record = operations.list().find(operation => operation.operationKey === result.value?.id)
    expect(record).toMatchObject({ status: 'success' })
    controller.abort(); await flush(); expect(record?.status).toBe('success'); expect(state.save).toHaveBeenCalledOnce()
  })
  it('keeps an already committed check in a cancelled batch receipt without late progress', async () => {
    const controller = new AbortController(), progress = vi.fn()
    state.profiles = [{ id: 'target', server: 'probe.example', port: 80 }]
    // Cancellation inside the synchronous commit loses to that completed commit.
    state.save.mockImplementationOnce(() => controller.abort())
    const result = observe(runLiveServerBatchCheck({ profileIds: ['target'], mode: 'basic' }, controller.signal, progress))
    await drainFixtures()
    expect(result.error).toBeUndefined(); expect(result.settled).toBe(true)
    expect(state.save).toHaveBeenCalledOnce()
    expect(result.value).toMatchObject({ cancelled: true, errors: [] })
    expect(result.value?.results).toEqual([state.save.mock.calls[0][0]])
    expect(progress.mock.calls.some(([event]) => event.status === 'completed')).toBe(false)
  })
})
it.each([
  { batch: false, boundary: 'cancel' }, { batch: false, boundary: 'deadline' },
  { batch: true, boundary: 'cancel' }, { batch: true, boundary: 'deadline' }
])('retains sender admission through physical drain (batch=$batch, $boundary)', async ({ batch, boundary }) => {
  registerLiveServerProbeIpcHandlers()
  const gate = held<Array<{ address: string; ttl: number }>>([]); state.a.mockReturnValue(gate.promise)
  state.profiles = [{ id: 'target', server: 'probe.example', port: 80 }]
  const owner = Object.assign(new EventEmitter(), { id: 501, isDestroyed: () => false, send: vi.fn() })
  const other = Object.assign(new EventEmitter(), { id: 502, isDestroyed: () => false, send: vi.fn() })
  const run = state.handlers.get(batch ? 'server:live-check-batch' : 'server:live-check')!
  const cancel = state.handlers.get('server:live-check-cancel')!, count = batch ? 2 : 4
  const options = (requestId: string) => ({ requestId, host: 'probe.example', port: 80, profileIds: ['target'], mode: 'basic' })
  const results = Array.from({ length: count }, (_, index) => observe(run({ sender: owner }, options(`legacy-${index}`))))
  await flush(); expect(state.a).toHaveBeenCalledTimes(count)
  if (boundary === 'cancel') for (let i = 0; i < count; i++) await cancel({ sender: owner }, `legacy-${i}`)
  else await vi.advanceTimersByTimeAsync(25_000)
  await flush(); expect(results.every(result => result.settled)).toBe(true)
  if (!batch) expect(results.every(result => result.error?.category === (boundary === 'cancel' ? 'cancelled' : 'timeout'))).toBe(true)
  const refused = observe(run({ sender: owner }, options('replacement')))
  const duplicate = observe(run({ sender: owner }, options('legacy-0')))
  await flush()
  expect(refused.error).toMatchObject({ category: 'conflict' }); expect(duplicate.error).toMatchObject({ category: 'conflict' })
  expect(state.a).toHaveBeenCalledTimes(count)
  const independent = observe(run({ sender: other }, options('legacy-0')))
  await flush(); expect(independent.settled).toBe(false); expect(state.a).toHaveBeenCalledTimes(count + 1)
  await cancel({ sender: other }, 'legacy-0'); await flush()
  expect(owner.listenerCount('destroyed')).toBe(count)
  gate.release([]); await drainFixtures()
  expect(owner.listenerCount('destroyed')).toBe(0); expect(other.listenerCount('destroyed')).toBe(0)
  const replacement = observe(run({ sender: owner }, options('legacy-0')))
  await flush(); expect(replacement.error).toBeUndefined(); expect(state.a).toHaveBeenCalledTimes(count + 2)
  await cancel({ sender: owner }, 'legacy-0'); await drainFixtures()
})
it.each([false, true].flatMap(batch => ['destroyed', 'did-navigate', 'render-process-gone'].map(event => ({ batch, event }))))(
  'cancels only the requesting document and fences late progress (batch=$batch, $event)', async ({ batch, event }) => {
    registerLiveServerProbeIpcHandlers()
    const gate = held<Array<{ address: string; ttl: number }>>([]); state.a.mockReturnValue(gate.promise)
    state.profiles = [{ id: 'target', server: 'probe.example', port: 80 }]
    const sender = Object.assign(new EventEmitter(), { id: 601, isDestroyed: () => false, send: vi.fn() })
    const run = state.handlers.get(batch ? 'server:live-check-batch' : 'server:live-check')!
    const result = observe(run({ sender }, { requestId: 'legacy-document', host: 'probe.example', port: 80, profileIds: ['target'], mode: 'basic' }))
    await flush(); sender.emit(event); await flush()
    expect(result.settled).toBe(true)
    if (batch) expect(result.value).toMatchObject({ cancelled: true, errors: [] })
    else expect(result.error).toMatchObject({ category: 'cancelled' })
    const notifications = sender.send.mock.calls.length
    gate.release([]); await drainFixtures()
    expect(sender.send).toHaveBeenCalledTimes(notifications)
    expect(state.sockets).toHaveLength(0); expect(state.save).not.toHaveBeenCalled()
    for (const name of ['destroyed', 'did-navigate', 'render-process-gone']) expect(sender.listenerCount(name)).toBe(0)
  }
)
it.each([false, true])('does not cache a late ASN response after cancellation (fallback=%s)', async fallback => {
  const gate = held({ data: { asn: 'AS123', country: 'late' } }), controller = new AbortController()
  if (fallback) state.geo.mockRejectedValueOnce(new Error('primary failed'))
  state.geo.mockReturnValueOnce(gate.promise)
  const ip = fallback ? '192.0.2.42' : '192.0.2.41'
  const checking = probeInfrastructure('probe.example', ip, undefined, undefined, false, controller.signal)
  await flush(); controller.abort(); gate.release({ data: { asn: 'AS123', country: 'late' } })
  expect(await checking).toMatchObject({ status: 'skipped', asn: undefined })
  const calls = state.geo.mock.calls.length
  state.geo.mockResolvedValueOnce({ data: { asn: 'AS456', country: 'fresh' } })
  expect((await probeInfrastructure('probe.example', ip, undefined, undefined, false)).asn?.country).toBe('fresh')
  expect(state.geo).toHaveBeenCalledTimes(calls + 1)
})
it('fences a delayed split-routing import and avoids reading configuration after cancel', async () => {
  const gate = held<void>(undefined); state.splitGate = gate.promise
  const before = new AbortController(); before.abort()
  const preCancelled = observe(collectSplitTunnelDiagnostics(before.signal)); await flush()
  expect(state.splitLoads).toBe(0); expect(preCancelled.error).toMatchObject({ category: 'cancelled' })
  const controller = new AbortController(), result = observe(collectSplitTunnelDiagnostics(controller.signal))
  // Dynamic imports cross the module loader, so allow an event-loop turn too.
  await vi.waitFor(() => expect(state.splitLoads).toBe(1))
  controller.abort(); gate.release(); await vi.waitFor(() => expect(result.settled).toBe(true))
  expect(result.error).toMatchObject({ category: 'cancelled' }); expect(state.splitRead).not.toHaveBeenCalled()
})
