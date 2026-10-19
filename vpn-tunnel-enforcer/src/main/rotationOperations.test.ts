// AT-00-002/003/005/007: production rotation/registry/lane/FSM/IPC, real Conf/JSONL.
// OS probes, native restart, notifications and Electron identity are controlled boundaries.
import { afterEach, beforeEach, describe, expect, it, vi, type Mock } from 'vitest'
import { EventEmitter } from 'node:events'
import { mkdir, mkdtemp, readFile, rm } from 'node:fs/promises'
import { join } from 'node:path'
import { ConnectionLifecycle } from './connectionLifecycle'
import { TunnelStateMachine } from './tunnelStateMachine'

const state = vi.hoisted(() => ({
  dir: '', handlers: new Map<string, (...args: any[]) => any>(), log: vi.fn(),
  profiles: ['a', 'b'].map(id => ({ id, name: `Profile ${id}`, server: `${id}.example.test`, port: 443,
    status: 'unknown', protocol: 'vless', outbound: { type: 'vless', server: `${id}.example.test`, server_port: 443 } })),
  evidence: { running: false, pid: null as number | null, softApplied: false },
  active: 'a', select: vi.fn(), ping: vi.fn(), fingerprint: vi.fn(), restart: vi.fn(), send: vi.fn(), notify: vi.fn()
}))
vi.mock('electron', () => ({
  app: { isPackaged: false, getPath: () => state.dir },
  ipcMain: { handle: vi.fn((channel: string, handler: (...args: any[]) => any) => { state.handlers.set(channel, handler) }) },
  BrowserWindow: { getAllWindows: () => [{ webContents: { send: state.send } }] }
}))
vi.mock('electron-store', async () => {
  const { default: Conf } = await vi.importActual<typeof import('conf')>('conf')
  return { default: class extends Conf {
    constructor(options: Record<string, unknown>) { super({ ...options, cwd: state.dir, configName: String(options.name), projectVersion: '1.1.24' }) }
  } }
})
vi.mock('./serverPicker', () => ({
  serverPicker: { getProfiles: () => state.profiles, selectProfile: (id: string) => { state.select(id); state.active = id } },
  smartOfflinePing: (...args: unknown[]) => state.ping(...args)
}))
vi.mock('./settings', () => ({ settingsStore: { get: () => ({ adaptiveBypassEnabled: true }) } }))
vi.mock('./adaptiveBypass', () => ({
  readAdaptiveNetworkFingerprint: () => state.fingerprint(), beginAdaptiveConnection: () => ({ mode: 'standard' })
}))
vi.mock('./notifications', () => ({ notify: (...args: unknown[]) => state.notify(...args) }))
vi.mock('./tunController', () => ({ tunController: {
  getStatus: () => state.evidence, restartProtected: (...args: unknown[]) => state.restart(...args)
} }))

class Sender extends EventEmitter {
  destroyed = false
  mainFrame = { url: 'file:///C:/vpnte-fixture/index.html' }
  isDestroyed() { return this.destroyed }
  destroy() { this.destroyed = true; this.emit('destroyed') }
}
let sender: Sender, lane: ConnectionLifecycle, fsm: TunnelStateMachine, cleanup: Mock<() => Promise<{ success: boolean }>>
let registry: typeof import('./operations').operations, rotation: typeof import('./profileRotation').profileRotation
const releases = new Set<() => void>()
function held<T>(value: T) {
  let release!: () => void
  const promise = new Promise<T>(done => { release = () => done(value) })
  releases.add(release)
  return { promise, release }
}
const invoke = (channel: string, ...args: unknown[]) => state.handlers.get(channel)!({ sender, senderFrame: sender.mainFrame }, ...args)
const running = () => registry.list().find(operation => operation.status === 'running')!
const rotationBytes = () => readFile(join(state.dir, 'profile-rotation.json'), 'utf8')

async function logRows() {
  const logger = await import('./appLogger')
  let raw = ''
  await expect.poll(async () => {
    try { raw = await readFile(logger.getAppLogPath(), 'utf8'); return raw.trim().split('\n').length }
    catch { return 0 }
  }).toBe(state.log.mock.calls.length)
  return { raw, rows: raw.trim().split('\n').map(row => JSON.parse(row)) }
}

beforeEach(async () => {
  vi.resetModules(); vi.clearAllMocks()
  await mkdir('.tmp', { recursive: true })
  state.dir = await mkdtemp(join(process.cwd(), '.tmp', 'rotation-operations-'))
  state.evidence = { running: false, pid: null, softApplied: false }; state.active = 'a'
  state.ping.mockReset().mockResolvedValue(10); state.fingerprint.mockReset().mockResolvedValue(null)
  state.restart.mockReset().mockResolvedValue({ success: true }); state.notify.mockReset().mockResolvedValue(undefined)
  state.log = vi.spyOn(await import('./appLogger'), 'logEvent')
  for (const method of ['log', 'warn', 'error'] as const) vi.spyOn(console, method).mockImplementation(() => {})
  state.handlers.clear()
  const { ipcMain } = await import('electron')
  ipcMain.handle = vi.fn((channel, handler) => { state.handlers.set(channel, handler) })
  delete (ipcMain as any)[Symbol.for('vpnte.ipc.trusted-boundary.installed')]
  const security = await import('./ipcSecurity')
  security.installTrustedIpcBoundary()
  sender = new Sender(); security.registerTrustedRenderer(sender as any, sender.mainFrame.url)
  const module = await import('./operations'); registry = module.operations; module.registerOperationHandlers()
  rotation = (await import('./profileRotation')).profileRotation
  fsm = new TunnelStateMachine(() => state.evidence)
  cleanup = vi.fn(async () => { state.evidence.running = false; state.evidence.pid = null; return { success: true } })
  lane = new ConnectionLifecycle(vi.fn(), cleanup, undefined, fsm)
  rotation.setLifecycle(lane); rotation.registerHandlers()
  await invoke('rotation:set-config', { enabled: true, profileIds: ['a', 'b'], intervalMinutes: 5 })
})
afterEach(async () => {
  for (const release of releases) release()
  releases.clear()
  rotation?.stopTimer(); await registry?.close()
  vi.useRealTimers()
  if (state.log.mock.calls.length) await logRows()
  vi.restoreAllMocks()
  await rm(state.dir, { recursive: true, force: true, maxRetries: 8, retryDelay: 25 })
})

async function live() {
  await lane.start(async () => { state.evidence.running = true; state.evidence.pid = 10; return { success: true } })
}
async function pauseAt(phase: 'probe' | 'fingerprint' | 'restart') {
  if (phase !== 'probe') await live()
  const gate = held(phase === 'restart' ? { success: true } : phase === 'probe' ? 10 : null)
  const boundary = phase === 'probe' ? state.ping : phase === 'fingerprint' ? state.fingerprint : state.restart
  boundary.mockReturnValueOnce(gate.promise)
  const result = invoke('rotation:rotate-now')
  await vi.waitFor(() => expect(boundary).toHaveBeenCalledOnce())
  return { gate, result }
}

describe('production rotation operation lifetime', () => {
  it.each(['probe', 'fingerprint', 'restart'] as const)('cancels at %s, retains physical ownership and suppresses late persistence/events', async phase => {
    const before = await rotationBytes(), { gate, result } = await pauseAt(phase), operation = running()
    expect(operation).toMatchObject({ kind: 'rotation', owner: 'rotation', deadline: expect.any(Number) })
    expect(lane.operation?.operationId).toBe(operation.operationId)
    const start = performance.now()
    expect(await invoke('operations:cancel', operation.operationId)).toMatchObject({ ok: true, result: true })
    expect(await result).toMatchObject({ ok: false, correlationId: operation.correlationId, error: { category: 'cancelled' } })
    expect(performance.now() - start).toBeLessThan(900)
    const selected = state.select.mock.calls.length, sent = state.send.mock.calls.length, notified = state.notify.mock.calls.length
    expect(await invoke('rotation:rotate-now')).toMatchObject({ ok: false, error: { category: 'conflict' } })
    expect(cleanup).not.toHaveBeenCalled()
    gate.release(); await registry.close()
    expect(cleanup).toHaveBeenCalledTimes(phase === 'restart' ? 1 : 0)
    expect(await rotationBytes()).toBe(before)
    expect(state.select).toHaveBeenCalledTimes(selected); expect(state.send).toHaveBeenCalledTimes(sent); expect(state.notify).toHaveBeenCalledTimes(notified)
    expect(state.evidence.running).toBe(phase === 'fingerprint')
    expect(fsm.snapshot).toMatchObject({ state: phase === 'fingerprint' ? 'connected' : 'disconnected', transition: null })
    const { raw, rows } = await logRows()
    const records = rows.filter(row => row.message === 'feature operation' && row.details?.operationKey === 'op_' + operation.operationId.replaceAll('-', ''))
    expect(records).toHaveLength(2)
    expect(records.map(row => row.details.status)).toEqual(['running', 'cancelled'])
    expect(records.every(row => row.correlationId === operation.correlationId)).toBe(true)
    expect(raw).not.toContain(operation.operationId)
  })

  it.each(['destroy', 'config', 'reload', 'shutdown'] as const)('cancels the active preflight on %s and keeps later configuration', async reason => {
    const { gate, result } = await pauseAt('probe')
    let closing: Promise<void> | undefined
    if (reason === 'destroy') sender.destroy()
    if (reason === 'config') await invoke('rotation:set-config', { enabled: false, profileIds: ['a'] })
    if (reason === 'reload') rotation.initProfileRotation()
    if (reason === 'shutdown') { rotation.stopTimer(); closing = Promise.all([registry.close(), lane.close()]).then(() => undefined) }
    expect(await result).toMatchObject({ ok: false, error: { category: 'cancelled' } })
    const current = await rotationBytes()
    gate.release(); await closing; await registry.close()
    expect(await rotationBytes()).toBe(current)
    expect(state.select).not.toHaveBeenCalled(); expect(state.restart).not.toHaveBeenCalled()
    expect(sender.listenerCount('destroyed')).toBe(reason === 'destroy' ? 0 : 1) // only trusted-renderer registration remains
  })

  it.each(['manual', 'schedule'] as const)('%s startup preempts rotation and waits for the original native effect', async owner => {
    const { gate, result } = await pauseAt('restart')
    const start = vi.fn(async () => { state.evidence.running = true; state.evidence.pid = 20; return { success: true } })
    const replacement = lane.start(start, { owner })
    expect(await result).toMatchObject({ ok: false, error: { category: 'cancelled' } })
    expect(start).not.toHaveBeenCalled(); expect(cleanup).not.toHaveBeenCalled()
    gate.release()
    expect(await replacement).toEqual({ success: true })
    expect(cleanup).toHaveBeenCalledOnce()
    expect(fsm.snapshot).toMatchObject({ state: 'connected', pid: 20, transition: null })
  })

  it('commits a successful live rotation once and persists the next tick in real Conf', async () => {
    await live()
    const result = await invoke('rotation:rotate-now')
    expect(result).toMatchObject({ ok: true, result: { success: true, newProfile: 'b' } })
    expect(JSON.parse(await rotationBytes()).rotation).toMatchObject({ currentIndex: 1, nextRotationAt: expect.any(Number) })
    expect(registry.list()).toHaveLength(1)
    expect(fsm.snapshot).toMatchObject({ state: 'connected', transition: null, operation: { operationId: registry.list()[0].operationId, status: 'success' } })
    expect(state.restart).toHaveBeenCalledWith(expect.any(String), expect.any(Object), { signal: expect.any(AbortSignal) })
  })

  it('does not persist or announce the candidate before cancellable fingerprint preparation', async () => {
    const { gate, result } = await pauseAt('fingerprint')
    expect(state.active).toBe('a')
    expect(state.select).not.toHaveBeenCalled(); expect(state.send).not.toHaveBeenCalled(); expect(state.notify).not.toHaveBeenCalled()
    registry.cancel(running().operationId)
    expect(await result).toMatchObject({ ok: false, error: { category: 'cancelled' } })
    gate.release(); await registry.close()
    expect(state.active).toBe('a'); expect(state.restart).not.toHaveBeenCalled()
  })

  it('keeps the confirmed old tunnel after selection persistence throws before native restart', async () => {
    await live()
    state.select.mockImplementationOnce(() => { throw new Error('private write failure C:\\secret\\profile.json') })
    expect(await invoke('rotation:rotate-now')).toMatchObject({ ok: true, result: { success: false } })
    expect(fsm.snapshot).toMatchObject({ state: 'connected', transition: null, pid: 10, operation: { status: 'error' } })
    expect(state.active).toBe('a'); expect(state.restart).not.toHaveBeenCalled(); expect(state.send).not.toHaveBeenCalled()
    expect(JSON.stringify(state.notify.mock.calls)).not.toContain('private write failure')
    expect(JSON.stringify(state.notify.mock.calls)).not.toContain('Защита выключена')
  })

  it('serializes a reversible operationId in actual event rows instead of a masked UUID', async () => {
    await invoke('rotation:rotate-now')
    const operation = registry.list()[0], key = 'op_' + operation.operationId.replaceAll('-', '')
    const { rows } = await logRows()
    const events = rows.filter(row => row.message === 'feature operation')
    expect(events).toHaveLength(2)
    expect(events.every(row => row.details.operationId === key && row.details.operationKey === key)).toBe(true)
    const logger = await import('./appLogger')
    const readBack = (await logger.getFullLogs()).find(file => file.path === logger.getAppLogPath())!
    expect(readBack.content.trim().split('\n').map(row => JSON.parse(row)).filter(row => row.message === 'feature operation')).toEqual(events)
  })

  it.each(['cancel', 'timeout', 'conflict'] as const)('re-arms the enabled timer after a rotation %s with fresh current configuration', async outcome => {
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout', 'Date'] })
    rotation.initProfileRotation()
    const gate = held(10)
    if (outcome === 'conflict') void lane.start(async owner => { await owner.wait(gate.promise); return { success: false } }, { timeoutMs: 600_000 })
    else state.ping.mockReturnValueOnce(gate.promise)
    await vi.advanceTimersByTimeAsync(300_001)
    if (outcome === 'cancel') { registry.cancel(running().operationId); await vi.advanceTimersByTimeAsync(0) }
    if (outcome === 'timeout') await vi.advanceTimersByTimeAsync(120_001)
    expect(rotation.getConfig().nextRotationAt).toBeGreaterThan(Date.now())
    gate.release()
    if (outcome !== 'conflict') await vi.waitFor(() => expect(registry.isBusy('rotation')).toBe(false))
    rotation.stopTimer()
  })

  it('an unavailable offline rotation keeps the confirmed idle state and permits the next attempt', async () => {
    state.ping.mockResolvedValue(null)
    expect(await invoke('rotation:rotate-now')).toMatchObject({ ok: true, result: { success: false, newProfile: '' } })
    expect(fsm.snapshot).toMatchObject({ state: 'disconnected', transition: null, operation: { status: 'error' } })
    expect(state.select).not.toHaveBeenCalled()
    state.ping.mockResolvedValue(10)
    expect(await invoke('rotation:rotate-now')).toMatchObject({ ok: true, result: { success: true, newProfile: 'b' } })
  })

  it('a deadline during preflight returns promptly and prevents a delayed profile selection', async () => {
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout', 'Date'] })
    const gate = held(10); state.ping.mockReturnValueOnce(gate.promise)
    const result = invoke('rotation:rotate-now')
    await vi.advanceTimersByTimeAsync(0)
    expect(state.ping).toHaveBeenCalledOnce()
    await vi.advanceTimersByTimeAsync(120_001)
    expect(await result).toMatchObject({ ok: false, error: { category: 'timeout' } })
    expect(registry.list()[0]).toMatchObject({ status: 'error', category: 'timeout' })
    gate.release(); await registry.close()
    expect(state.select).not.toHaveBeenCalled(); expect(state.restart).not.toHaveBeenCalled()
  })

  it('owns timer rotations with a fresh correlation and stopTimer cancels their in-flight probe', async () => {
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout', 'Date'] })
    rotation.initProfileRotation()
    const gate = held(10); state.ping.mockReturnValueOnce(gate.promise)
    await vi.advanceTimersByTimeAsync(300_001)
    expect(state.ping).toHaveBeenCalledOnce()
    expect(running()).toMatchObject({ owner: 'rotation', source: 'lifecycle', correlationId: expect.stringMatching(/^op_/) })
    rotation.stopTimer(); gate.release(); await registry.close()
    expect(state.select).not.toHaveBeenCalled()
    expect(vi.getTimerCount()).toBe(0)
  })

  it('does not re-arm an expired timer after config disables rotation during its held probe', async () => {
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout', 'Date'] })
    rotation.initProfileRotation()
    const gate = held(10); state.ping.mockReturnValueOnce(gate.promise)
    await vi.advanceTimersByTimeAsync(300_001)
    await invoke('rotation:set-config', { enabled: false })
    const saved = await rotationBytes()
    gate.release(); await registry.close()
    expect(await rotationBytes()).toBe(saved)
    expect(rotation.getConfig()).toMatchObject({ enabled: false, nextRotationAt: null })
    expect(vi.getTimerCount()).toBe(0)
  })
})
